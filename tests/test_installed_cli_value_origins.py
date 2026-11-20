"""Actual installed CLI/parser paths retain native and altered-origin witnesses."""
import hashlib
from pathlib import Path
import subprocess

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)

PROBE = '''import importlib.util,json,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import ci_commands
spec=importlib.util.spec_from_file_location("value_origin_fixture",sys.argv[1])
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
result=fixture.exercise(ci_commands,sys.argv[2])
print("installed-value-origin-result:"+json.dumps(result,sort_keys=True))
'''


@pytest.mark.parametrize('mode', ['ordinary', 'invalid', 'ownership', 'constructor', 'parser'])
def test_installed_actual_cli_value_origins(tmp_path, installed_consumer, isolated_python, mode):
    source = Path(__file__).with_name('cli_value_origins_support.py')
    fixture = tmp_path / 'value_origin_fixture.py'
    fixture.write_bytes(source.read_bytes())
    assert hashlib.sha256(fixture.read_bytes()).digest() == hashlib.sha256(source.read_bytes()).digest()
    result = subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE, str(fixture), mode],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'installed-value-origin-result:' in result.stdout
    assert '"runtime_context_qualified": false' in result.stdout
    print(next(line for line in result.stdout.splitlines() if line.startswith("installed-value-origin-result:")))
