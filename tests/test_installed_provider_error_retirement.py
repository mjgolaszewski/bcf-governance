"""Fresh and upgraded private runtime must retire actual HTTP error bodies."""
import json
import subprocess

import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment, _record

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python


PROBE = r'''import importlib.util, json, sys, threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
assert importlib.util.find_spec('bcf_governance') is None
root = Path('scripts').resolve()
sys.path.insert(0, str(root))
from _bcf_runtime.provider_read import open_provider_get, ProviderReadError
class CleanupFault(RuntimeError):
    pass
class CleanupInterrupt(BaseException):
    pass
completed = []
for mode in ('retry429', 'retry503', 'terminal404', 'cleanup-fault', 'cleanup-interrupt'):
    requests, errors, dispatches = [], [], []
    signal = CleanupInterrupt('fixed installed cleanup control') if mode == 'cleanup-interrupt' else CleanupFault('fixed installed cleanup control')
    status = 429 if mode == 'retry429' else 404 if mode == 'terminal404' else 503
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            dispatches.append(self.path)
            code = status if len(dispatches) == 1 else 200
            body = b'bounded-error' if code != 200 else b'exact-success'
            self.send_response(code)
            self.send_header('Retry-After', '0')
            self.send_header('X-Control', mode)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except OSError:
                pass
    server = HTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    request = Request(f'http://127.0.0.1:{server.server_port}/retirement')
    def opener(subject, *, timeout):
        assert subject is request
        assert all(error.fp.closed for error in errors), 'previous error body still open before retry dispatch'
        requests.append(subject)
        try:
            return urlopen(subject, timeout=timeout)
        except HTTPError as error:
            errors.append(error)
            if mode in ('cleanup-fault', 'cleanup-interrupt'):
                native_close = error.close
                def failed_close():
                    native_close()
                    raise signal
                error.close = failed_close
            raise
    try:
        if mode.startswith('retry'):
            with open_provider_get(request, timeout=2, opener=opener, sleeper=lambda _: None) as response:
                assert response.read() == b'exact-success'
            assert len(requests) == len(dispatches) == 2 and len(errors) == 1
        else:
            caught = None
            try:
                open_provider_get(request, timeout=2, opener=opener, sleeper=lambda _: None)
            except BaseException as error:
                caught = error
            assert len(requests) == len(dispatches) == len(errors) == 1
            if mode == 'terminal404':
                assert caught is errors[0] and caught.code == 404 and caught.headers['X-Control'] == mode
            elif mode == 'cleanup-fault':
                assert isinstance(caught, ProviderReadError) and caught.__cause__ is errors[0]
                assert any('CleanupFault' in note for note in caught.__notes__)
            else:
                assert caught is signal
        assert all(error.fp.closed for error in errors)
        completed.append(mode)
    finally:
        for error in errors:
            error.fp.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()
origins = {name: str(Path(module.__file__).resolve()) for name, module in list(sys.modules.items())
           if name.startswith('_bcf_runtime.') and getattr(module, '__file__', None)}
assert origins and all(Path(value).is_relative_to(root) for value in origins.values())
print(json.dumps({'source_package_absent': True, 'cases': completed, 'private_origins': origins}, sort_keys=True))
'''
compile(PROBE, 'installed-provider-error-retirement', 'exec')


def test_installed_actual_error_response_retirement(installed_consumer, isolated_python):
    result = subprocess.run(
        [str(isolated_python), '-I', '-B', '-c', PROBE], cwd=installed_consumer,
        env=_environment(), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, _record(result)
    actual = json.loads(result.stdout)
    assert actual['source_package_absent'] is True and actual['private_origins']
    assert actual['cases'] == [
        'retry429', 'retry503', 'terminal404', 'cleanup-fault', 'cleanup-interrupt',
    ]
