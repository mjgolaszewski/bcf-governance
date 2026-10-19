"""Real prospective consumer custody; original policy/evaluator semantics stay intact."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from bcf_governance.tooling import controller_custody_prospective, trusted_controller_compatibility
from bcf_governance.tooling import evidence_process_supervisor
from bcf_governance.tooling.local_execution_admission import local_gate_lease
from tests.test_native_lease_custody import lease_path, _busy  # noqa: F401


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


def test_delayed_actual_guardian_preserves_authenticated_precommand_timeout(lease_path: Path, tmp_path: Path, monkeypatch) -> None:
    marker = tmp_path / 'expired-command-must-not-run'
    children, frames = [], []
    original_popen = evidence_process_supervisor.subprocess.Popen
    original_terminal = evidence_process_supervisor._terminal_result
    def delayed(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        children.append(process)
        time.sleep(0.2)
        return process
    def terminal(value, pid):
        frame = original_terminal(value, pid)
        if frame not in frames:
            frames.append(frame)
        return frame
    monkeypatch.setattr(evidence_process_supervisor.subprocess, 'Popen', delayed)
    monkeypatch.setattr(evidence_process_supervisor, '_terminal_result', terminal)
    with local_gate_lease('7' * 40):
        try:
            with pytest.raises(subprocess.TimeoutExpired):
                evidence_process_supervisor.run_admitted_command(
                    [sys.executable, '-I', '-c', 'from pathlib import Path;import sys;Path(sys.argv[1]).touch()', str(marker)],
                    cwd=tmp_path, capture_output=True, text=True, timeout=0.05,
                )
        finally:
            for process in children:
                process.wait(timeout=2)
        assert len(children) == 1
        assert len(frames) == 1 and frames[0]['type'] == 'not-started'
        assert frames[0]['reason'] == 'timeout' and frames[0]['command_pid'] is None and frames[0]['quiescent'] is True
        assert not marker.exists(), 'expired-command-was-allocated'
        assert _busy(lease_path)
    assert not _busy(lease_path)


def test_expired_readiness_cleanup_does_not_extend_or_authorize_command(lease_path: Path, tmp_path: Path, monkeypatch) -> None:
    marker = tmp_path / 'cleanup-expired-command'
    children, parent_messages = [], []
    original_popen = evidence_process_supervisor.subprocess.Popen
    original_send = evidence_process_supervisor._send
    def delayed(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        children.append(process)
        time.sleep(1.2)
        return process
    def send(connection, value):
        parent_messages.append(value)
        return original_send(connection, value)
    monkeypatch.setattr(evidence_process_supervisor.subprocess, 'Popen', delayed)
    monkeypatch.setattr(evidence_process_supervisor, '_send', send)
    with local_gate_lease('9' * 40):
        try:
            with pytest.raises(evidence_process_supervisor.OwnedProcessError):
                evidence_process_supervisor.run_owned_command(
                    [sys.executable, '-I', '-c', 'from pathlib import Path;import sys;Path(sys.argv[1]).touch()', str(marker)],
                    cwd=tmp_path, env=dict(os.environ), timeout_seconds=0.05,
                    cleanup_seconds=1, timeout_raises=True,
                )
        finally:
            for process in children:
                process.wait(timeout=2)
        assert not parent_messages, 'expired-cleanup-sent-new-command-or-cancellation'
        assert not marker.exists()
