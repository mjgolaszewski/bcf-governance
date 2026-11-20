"""Installed header and chunk numeric guards retain independent detectors."""
import inspect
import subprocess

import pytest

import test_installed_evidence_storage as fixtures
import test_provider_numeric_framing as cases

installed_consumer = fixtures.installed_consumer
isolated_python = fixtures.isolated_python
PROBE = '''from http.client import HTTPResponse
from pathlib import Path
import socket,sys
assert __import__("importlib.util").util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import ci_github_response as owner
''' + inspect.getsource(cases.Case) + '''
assert Case(b"HTTP/1.1 200 OK\\r\\nContent-Length: 5 \\t\\r\\n\\r\\nhello").consume(1)==b"hello"
for label,raw in [
 ("chunk",b"HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n+5\\r\\nhello\\r\\n0\\r\\n\\r\\n"),
 ("length",b"HTTP/1.1 200 OK\\r\\nContent-Length: +5\\r\\n\\r\\nhello")]:
 try:Case(raw).consume()
 except owner.ProviderResponseError:pass
 else:raise AssertionError("installed malformed numeric "+label+" accepted")
print("installed-provider-numeric-framing-qualified")
'''


def invoke(installed_consumer, isolated_python):
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=fixtures._environment(), capture_output=True, text=True)


def test_installed_valid_and_malformed_framing(installed_consumer, isolated_python):
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-provider-numeric-framing-qualified"


@pytest.mark.parametrize("cause", ["chunk", "length"])
def test_installed_detector_refuses_removed_guard(installed_consumer, isolated_python, cause):
    path = installed_consumer / "scripts/_bcf_runtime/ci_github_response.py"
    source = path.read_text()
    guard = ('re.fullmatch(rb"[0-9A-Fa-f]+", token) is None' if cause == "chunk"
             else "    _validate_provider_numeric_framing(response)\n")
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "False" if cause == "chunk" else ""))
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 1
    assert "installed malformed numeric " + cause + " accepted" in result.stderr
