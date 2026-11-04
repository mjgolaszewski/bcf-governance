"""Real framing adversaries for the provider body deadline contract."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
import threading
import time
import ssl
import subprocess
from urllib.request import urlopen

import pytest

from bcf_governance.tooling import provider_read


def _deadline(response, timeout):
    owner = getattr(provider_read, "provider_response_deadline", None)
    assert callable(owner), "provider responses need an elapsed body deadline owner"
    return owner(response, timeout=timeout)


@contextmanager
def _server(mode, accepted=None, tls_context=None, response_codes=None):
    codes = iter(response_codes) if response_codes is not None else None
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            accepted.append("POST")
            self.do_GET()

        def do_GET(self):
            code = next(codes) if codes is not None else 200
            self.send_response(code)
            if code in {429, 503}:
                self.send_header("Retry-After", "0")
            if mode in {"chunk_header", "chunk_trailer"}:
                self.send_header("Transfer-Encoding", "chunked")
            else:
                self.send_header("Content-Length", "40")
            self.end_headers()
            try:
                if mode == "chunk_header":
                    data = b"000000000000000000000000000000000001\r\na\r\n0\r\n\r\n"
                elif mode == "chunk_trailer":
                    self.wfile.write(b"1\r\na\r\n0\r\n")
                    self.wfile.flush()
                    data = b"X-Trailer: " + b"a" * 40 + b"\r\n\r\n"
                else:
                    data = b"a" * 40
                for byte in data:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.01)
            except OSError:
                pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        scheme = 'https' if tls_context is not None else 'http'
        yield f"{scheme}://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()


@pytest.mark.parametrize("mode", ["body", "chunk_header", "chunk_trailer"])
@pytest.mark.parametrize("reader", ["read", "read1"])
def test_real_drip_and_internal_framing_share_one_elapsed_budget(mode, reader):
    with _server(mode) as url, urlopen(url, timeout=1) as response:
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            with _deadline(response, 0.08) as bounded:
                if reader == "read":
                    bounded.read()
                else:
                    while bounded.read1(1):
                        pass
        assert time.monotonic() - start < 0.30


@pytest.fixture(scope='module')
def verified_tls_contexts(tmp_path_factory):
    root = tmp_path_factory.mktemp('response-tls')
    certificate, key = root / 'cert.pem', root / 'key.pem'
    subprocess.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
         '-keyout', str(key), '-out', str(certificate)],
        check=True, capture_output=True,
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(certificate, key)
    client = ssl.create_default_context(cafile=str(certificate))
    yield server, client
    key.unlink()
    certificate.unlink()


@pytest.mark.parametrize('mode', ['body', 'chunk_header', 'chunk_trailer'])
@pytest.mark.parametrize('reader', ['read', 'read1'])
def test_verified_tls_framing_uses_the_same_absolute_body_budget(
    mode, reader, verified_tls_contexts,
):
    server, client = verified_tls_contexts
    with _server(mode, tls_context=server) as url, urlopen(url, context=client, timeout=1) as response:
        assert type(response.fp.raw._sock) is ssl.SSLSocket
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            with _deadline(response, 0.08) as bounded:
                if reader == 'read':
                    bounded.read()
                else:
                    while bounded.read1(1):
                        pass
        assert time.monotonic() - started < 0.30


@pytest.mark.parametrize("invalid", [True, False, 0, -1, float("nan"), float("inf"), "30", None])
def test_invalid_body_budget_is_rejected_without_consumption(invalid):
    response = BytesIO(b"exact")
    with pytest.raises(ValueError, match="deadline|timeout|budget"):
        with _deadline(response, invalid):
            pytest.fail("invalid deadline entered response consumption")
    assert response.tell() == 0


def test_finite_memory_response_preserves_bytes_and_does_not_close_caller_stream():
    response = BytesIO(b"exact")
    with _deadline(response, 1) as bounded:
        assert bounded.read(2) == b"ex"
        assert bounded.read() == b"act"
    assert not response.closed


def test_unknown_stream_cannot_claim_a_network_bound():
    class Unknown:
        def read(self, *_args):
            pytest.fail("unknown stream must not be read")

    with pytest.raises(OSError, match="response|transport|stream"):
        with _deadline(Unknown(), 1):
            pytest.fail("unqualified stream was admitted")


def test_memory_subclass_cannot_replace_the_qualified_read_primitive():
    class Replaced(BytesIO):
        def read(self, *_args):
            pytest.fail("unqualified replacement must not execute")

        read1 = read

    response = Replaced(b"exact")
    with _deadline(response, 1) as bounded:
        assert bounded.read() == b"exact"
    assert response.tell() == 5


def test_repeated_memory_reads_cannot_reset_the_body_budget():
    with _deadline(BytesIO(b"exact"), 0.01) as bounded:
        assert bounded.read(1) == b"e"
        time.sleep(0.02)
        with pytest.raises(TimeoutError):
            bounded.read(1)


def test_socket_inactivity_timeout_is_not_widened_and_is_restored():
    with _server("body") as url, urlopen(url, timeout=0.04) as response:
        transport = response.fp.raw._sock
        with _deadline(response, 1) as bounded:
            assert bounded.read(1) == b"a"
            assert transport.gettimeout() <= 0.04
        assert transport.gettimeout() == 0.04


def test_network_stream_without_qualified_socket_chain_is_rejected():
    from http.client import HTTPResponse
    from io import BufferedReader

    class SocketFixture:
        def makefile(self, *_args, **_kwargs):
            return BufferedReader(BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na"))

    response = HTTPResponse(SocketFixture())
    response.begin()
    try:
        with pytest.raises(OSError, match="stream.*not qualified"):
            with _deadline(response, 1):
                pytest.fail("unqualified HTTP framing stream admitted")
    finally:
        response.close()


def test_expired_mutation_response_never_retries_the_accepted_write(monkeypatch):
    from bcf_governance.tooling import ci_github_transport
    from bcf_governance.tooling.ci_github_response import provider_response_deadline

    accepted = []

    def body_budget(response, *, timeout):
        assert timeout == 30
        return provider_response_deadline(response, timeout=0.08)

    monkeypatch.setattr(ci_github_transport, "provider_response_deadline", body_budget)
    with _server("body", accepted) as url:
        with pytest.raises(ci_github_transport.GitHubTransportError, match="failed") as error:
            ci_github_transport.request_json(
                method="POST", api_url=url.rstrip("/"), path="/fixture", token="fixture-only",
                payload={"value": "exact"}, not_found_none=False, opener=urlopen, observations=[],
            )
    assert accepted == ["POST"]
    assert isinstance(error.value.__cause__, TimeoutError)


def test_all_original_response_consumers_have_deadline_scopes():
    import ast
    from collections import Counter
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    census = json.loads((root / "audits/issue-394/provider-response-read-census.json").read_text())
    expected = Counter(row["path"] for row in census["sites"])
    observed = Counter()
    for path in (root / "bcf_governance/tooling").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.With):
                continue
            for item in node.items:
                call = item.context_expr
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id == "provider_response_deadline"):
                    assert isinstance(item.optional_vars, ast.Name)
                    alias = item.optional_vars.id
                    reads = [child for child in ast.walk(node)
                             if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                             and isinstance(child.func.value, ast.Name)
                             and child.func.value.id == alias and child.func.attr == "read"]
                    observed[path.relative_to(root).as_posix()] += len(reads)
    assert observed == expected
    assert sum(observed.values()) == 7


@pytest.mark.parametrize("code", [429, 503])
@pytest.mark.parametrize("tls", [False, True])
def test_real_error_response_is_closed_before_retry_dispatch(code, tls, verified_tls_contexts):
    from urllib.error import HTTPError
    from urllib.request import Request

    server_context, client_context = verified_tls_contexts
    errors = []
    requests = []
    delays = []

    def opener(request, *, timeout):
        if errors:
            assert errors[-1].fp.closed
        requests.append(request)
        try:
            return urlopen(request, timeout=timeout,
                           context=client_context if tls else None)
        except HTTPError as failure:
            errors.append(failure)
            raise

    def sleeper(delay):
        assert errors[-1].fp.closed
        delays.append(delay)

    with _server("body", tls_context=server_context if tls else None,
                 response_codes=[code, 200]) as url:
        request = Request(url, method="GET")
        with provider_read.open_provider_get(request, timeout=1, opener=opener,
                                             sleeper=sleeper) as response:
            assert response.read() == b"a" * 40
    assert len(errors) == 1 and errors[0].fp.closed
    assert requests == [request, request] and requests[0] is requests[1]
    assert delays == [0.0]
