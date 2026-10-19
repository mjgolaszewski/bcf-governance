"""Real prospective consumer custody; original policy/evaluator semantics stay intact."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from bcf_governance.tooling import controller_custody_prospective, trusted_controller_compatibility
from bcf_governance.tooling import evidence_process_supervisor
from bcf_governance.tooling.local_execution_admission import local_gate_lease
from tests.test_native_lease_custody import lease_path  # noqa: F401


def _observation(identity, helper: Path) -> str:
    return f'''import json,os,sys
from pathlib import Path
parent=Path('/proc',str(os.getppid()))
expected={identity!r}
def holds(root):
    for entry in (root/'fd').iterdir():
        try: value=entry.stat()
        except FileNotFoundError: continue
        if (value.st_dev,value.st_ino)==expected:return True
    return False
observation=dict(guardian={str(helper)!r}.encode() in (parent/'cmdline').read_bytes().split(bytes([0])),parent_lease=holds(parent),command_lease=holds(Path('/proc/self')))
'''


def test_trusted_controller_git_has_actual_native_guardian(lease_path: Path, tmp_path: Path, monkeypatch) -> None:
    git = shutil.which('git')
    assert git is not None
    root = tmp_path / 'repo'
    subprocess.run([git, 'init', '-q', str(root)], check=True)
    binary = tmp_path / 'bin'
    binary.mkdir()
    observed = tmp_path / 'observation.json'
    with local_gate_lease('c' * 40):
        value = lease_path.stat()
        program = _observation((value.st_dev, value.st_ino), Path(evidence_process_supervisor.__file__).resolve())
        wrapper = binary / 'git'
        wrapper.write_text(f'#!{sys.executable}\n' + program + f"Path({str(observed)!r}).write_text(json.dumps(observation))\nos.execv({git!r},[{git!r},*sys.argv[1:]])\n")
        wrapper.chmod(0o700)
        monkeypatch.setenv('PATH', str(binary) + os.pathsep + os.environ['PATH'])
        assert trusted_controller_compatibility._git(root, 'rev-parse', '--show-toplevel') == str(root.resolve())
        assert json.loads(observed.read_text()) == dict(guardian=True, parent_lease=True, command_lease=False), 'trusted-controller-git-native-custody-bypassed'


def test_controller_route_has_actual_native_guardian(lease_path: Path) -> None:
    expected = 'e' * 40
    with local_gate_lease('d' * 40):
        value = lease_path.stat()
        program = _observation((value.st_dev, value.st_ino), Path(evidence_process_supervisor.__file__).resolve())
        program += f"Path(os.environ['GITHUB_OUTPUT']).write_text('controller_commit_sha={expected}\\n')\nprint(json.dumps(observation))\n"
        result = controller_custody_prospective._route(
            ['{python}', '-I', '-c', program], python_executable=Path(sys.executable),
            payload={'fixture': 'unchanged route transport'}, expected_commit=expected,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == dict(guardian=True, parent_lease=True, command_lease=False), 'controller-route-native-custody-bypassed'
