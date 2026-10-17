"""Exercise the actual installed response owners without the source SDK."""
import json
import subprocess

from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)


PROBE = r'''import importlib.util, json, sys, threading, time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from urllib.request import Request, urlopen
assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0, str(Path('scripts').resolve()))
from _bcf_runtime import ci_github_response as owner
from _bcf_runtime.ci_github_transport import request_bytes, GitHubTransportError
from _bcf_runtime.ci_github_downloads import GitHubDownloadKind
from _bcf_runtime.provider_read import open_provider_get, ProviderReadError
assert Path(owner.__file__).resolve().is_relative_to(Path.cwd())
def forbidden(*args, **kwargs):
    raise AssertionError('invalid budget allocated provider work')
invalid = [True, False, 0, -1, float('nan'), float('inf'), '30', None]
for value in invalid:
    try:
        open_provider_get(Request('https://api.github.com/fixture'), timeout=value, opener=forbidden)
    except ProviderReadError as error:
        assert 'timeout' in str(error)
    else:
        raise AssertionError('invalid timeout admitted')
byte_limits = invalid + [1.5]
for value in byte_limits:
    try:
        request_bytes(api_url='https://api.github.com', path='/fixture', token='fixture-only',
                      kind=GitHubDownloadKind.RELEASE_ASSET, maximum_bytes=value,
                      opener=forbidden, observations=[])
    except GitHubTransportError as error:
        assert 'limit' in str(error)
    else:
        raise AssertionError('invalid byte limit admitted')
with owner.provider_response_deadline(BytesIO(b'exact'), timeout=1) as bounded:
    assert bounded.read() == b'exact'
expired = []
for mode in ('body', 'chunk_header', 'chunk_trailer'):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.send_response(200)
            if mode == 'body':
                self.send_header('Content-Length', '40')
            else:
                self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            try:
                if mode == 'body':
                    data = b'a' * 40
                elif mode == 'chunk_header':
                    data = b'000000000000000000000000000001\r\na\r\n0\r\n\r\n'
                else:
                    self.wfile.write(b'1\r\na\r\n0\r\n')
                    self.wfile.flush()
                    data = b'X-Trailer: ' + b'a' * 40 + b'\r\n\r\n'
                for byte in data:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(.01)
            except OSError:
                pass
    server = HTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with urlopen(f'http://127.0.0.1:{server.server_port}/', timeout=1) as response:
            started = time.monotonic()
            try:
                with owner.provider_response_deadline(response, timeout=.08) as bounded:
                    while bounded.read1(1):
                        pass
            except TimeoutError:
                expired.append(mode)
            else:
                raise AssertionError('installed reader accepted unbounded drip')
            assert time.monotonic() - started < .30
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()
print(json.dumps({'source_package_absent': True, 'invalid_timeouts_rejected': len(invalid),
                  'invalid_byte_limits_rejected': len(byte_limits), 'expired': expired}, sort_keys=True))
'''
# Collection-time syntax admission precedes wheel builds and installer fixtures.
compile(PROBE, 'installed-provider-response-probe', 'exec')


def test_installed_provider_budgets_precede_allocation_and_bound_framing(
    installed_consumer, isolated_python,
):
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', PROBE], cwd=installed_consumer,
        env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    assert json.loads(result.stdout) == {
        'source_package_absent': True, 'invalid_timeouts_rejected': 8,
        'invalid_byte_limits_rejected': 9,
        'expired': ['body', 'chunk_header', 'chunk_trailer'],
    }
