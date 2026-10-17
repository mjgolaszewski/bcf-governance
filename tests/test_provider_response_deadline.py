"""Real framing adversaries for the provider body deadline contract."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
import threading
import time
from urllib.request import urlopen

import pytest

from bcf_governance.tooling import provider_read


def _deadline(response, timeout):
    owner = getattr(provider_read, "provider_response_deadline", None)
    assert callable(owner), "provider responses need an elapsed body deadline owner"
    return owner(response, timeout=timeout)


@contextmanager
def _server(mode):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
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
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
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

    with pytest.raises(ValueError, match="response|transport|stream"):
        with _deadline(Unknown(), 1):
            pytest.fail("unqualified stream was admitted")
