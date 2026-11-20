"""Installed parsed-value admission rejects callbacks and stale mutable input."""
import json
from pathlib import Path
import subprocess

import pytest

from tests.test_postparsed_cli_guard import MODES
from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)

PROBE = '''import importlib.util,json,sys
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import ci_commands
spec=importlib.util.spec_from_file_location("postparse_fixture",sys.argv[1])
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
result=fixture.exercise(ci_commands,sys.argv[2])
print("installed-postparse-observation:"+json.dumps(result,sort_keys=True))
'''


def invoke(tmp_path, installed_consumer, isolated_python, mode):
    source = Path(__file__).with_name('postparsed_cli_guard_support.py')
    fixture = tmp_path / 'postparse_fixture.py'
    fixture.write_bytes(source.read_bytes())
    return subprocess.run([str(isolated_python), '-I', '-B', '-c', PROBE, str(fixture), mode],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)


@pytest.mark.parametrize('mode', MODES)
def test_installed_postparsed_cli_guard(tmp_path, installed_consumer, isolated_python, mode):
    result = invoke(tmp_path, installed_consumer, isolated_python, mode)
    assert result.returncode == 0, result.stdout + result.stderr
    line = next(line for line in result.stdout.splitlines() if line.startswith('installed-postparse-observation:'))
    row = json.loads(line.partition(':')[2])
    assert row['authority'] is row['runtime_context_qualified'] is False
    print(line)


def test_installed_control_detects_removed_postparse_guard(tmp_path, installed_consumer, isolated_python):
    path = installed_consumer / 'scripts/_bcf_runtime/ci_commands.py'
    source = path.read_text()
    guard = '''            try:
                adopter_python = cli_arguments(args.adopter_python)
            except TypeError as exc:
                raise ReleaseQualificationError(
                    "--adopter-python requires ordinary parsed strings"
                ) from exc
'''
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, '            adopter_python = args.adopter_python\n'))
    result = invoke(tmp_path, installed_consumer, isolated_python, 'converter_word')
    assert result.returncode == 1
    assert 'postparser value reached qualification' in result.stderr
