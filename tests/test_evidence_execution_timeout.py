"""Real-process containment controls for the evidence command timeout boundary."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from bcf_governance.tooling.evidence_execution import _run

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux process-group custody control')


def test_evidence_command_preserves_successful_output(tmp_path):
    result = _run([sys.executable, '-c', "print('governed')"], cwd=tmp_path,
                  timeout_seconds=1)
    assert (result.returncode, result.stdout, result.stderr) == (0, 'governed\n', '')



def test_evidence_command_preserves_nonzero_unicode_and_universal_newlines(tmp_path):
    code = "import sys;sys.stdout.buffer.write(('é'*70000+'\\r\\n').encode());sys.stderr.write('failure\\r\\n');sys.exit(7)"
    result = _run([sys.executable, '-c', code], cwd=tmp_path, timeout_seconds=2)
    assert result.returncode == 7
    assert result.stdout == 'é' * 70000 + '\n'
    assert result.stderr == 'failure\n'

def test_evidence_direct_child_timeout_keeps_typed_failure(tmp_path):
    result = _run([sys.executable, '-c', 'import time; time.sleep(20)'],
                  cwd=tmp_path, timeout_seconds=1)
    assert result.returncode == 126
    assert 'execution infrastructure failure' in result.stderr


def _live(pid):
    try:
        for path in Path(f'/proc/{pid}/task').glob('*/stat'):
            try:
                raw = path.read_text()
            except FileNotFoundError:
                continue
            if raw[raw.rfind(')') + 2:].split()[0] not in {'Z', 'X'}:
                return True
        return False
    except FileNotFoundError:
        return False


@pytest.mark.parametrize('mode', ['timeout', 'background-success', 'threaded-background-success'])
def test_evidence_timeout_retires_inherited_pipe_descendants_within_outer_watchdog(tmp_path, mode):
    marker = tmp_path / 'owned-worker.json'
    worker = """import json, os, subprocess, sys, time
from pathlib import Path
path=Path(sys.argv[1]); temporary=path.with_suffix('.tmp')
metadata={'pid':os.getpid(),'group':os.getpgrp()}
temporary.write_text(json.dumps(metadata));temporary.replace(path)
background=sys.argv[2]!='timeout'
threaded=sys.argv[2]=='threaded-background-success'
child_code="import threading,time,ctypes; threading.Thread(target=lambda:time.sleep(20)).start(); ctypes.CDLL(None).pthread_exit(None)" if threaded else 'import time; time.sleep(20)'
child=subprocess.Popen([sys.executable,'-c',child_code],
    stdout=subprocess.DEVNULL if background else None,
    stderr=subprocess.DEVNULL if background else None)
metadata['child_pid']=child.pid
temporary.write_text(json.dumps(metadata));temporary.replace(path)
if threaded:
    deadline=time.monotonic()+1
    while time.monotonic()<deadline:
        raw=Path('/proc/'+str(child.pid)+'/stat').read_text()
        if raw[raw.rfind(')')+2:].split()[0]=='Z' and len(list(Path('/proc/'+str(child.pid)+'/task').iterdir()))>1:break
        time.sleep(0.01)
    else:raise AssertionError('threaded fixture did not establish zombie leader')
print('ready',flush=True)
if background:sys.exit(0)
time.sleep(20)
"""
    probe_code = """import json, sys, time
from pathlib import Path
from bcf_governance.tooling import evidence_execution
root=Path(sys.argv[1]);marker=Path(sys.argv[2]);worker=sys.argv[3];mode=sys.argv[4]
assert Path(evidence_execution.__file__).resolve().is_relative_to(root)
import os
original_signal=evidence_execution.os.killpg
def owned_signal(group, sig):
    os.waitid(os.P_PID,group,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    return original_signal(group,sig)
evidence_execution.os.killpg=owned_signal
start=time.monotonic()
result=evidence_execution._run([sys.executable,'-c',worker,str(marker),mode],
    cwd=marker.parent,timeout_seconds=2 if mode.startswith('threaded') else 1)
print(json.dumps({'returncode':result.returncode,'stderr':result.stderr,
                  'elapsed':time.monotonic()-start}))
"""
    probe = subprocess.Popen(
        [sys.executable, '-c', probe_code, str(ROOT), str(marker), worker, mode],
        cwd=tmp_path, env={'PATH': os.defpath, 'PYTHONPATH': str(ROOT)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    expired = False
    output = error = ''
    metadata = {}
    try:
        try:
            output, error = probe.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            expired = True
        if marker.exists():
            metadata = json.loads(marker.read_text())
        assert not expired, (
            'evidence runner did not return within external watchdog; inherited output '
            'pipes outlived the command timeout'
        )
        assert probe.returncode == 0, error
        result = json.loads(output)
        assert result['returncode'] == 126
        assert 'execution infrastructure failure' in result['stderr']
        assert 'child_pid' in metadata, 'fixture did not establish the descendant path'
        deadline = time.monotonic() + 1
        while _live(metadata['child_pid']) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not _live(metadata['child_pid']), 'timed-out command left a live descendant'
    finally:
        # Only fixture-created sessions/groups are eligible. Never signal the
        # pytest parent, another test, a native transaction or an unknown group.
        if not metadata and marker.exists():
            metadata = json.loads(marker.read_text())
        groups = {probe.pid}
        if metadata:
            assert metadata['group'] in {probe.pid, metadata['pid']}
            groups.add(metadata['group'])
        for group in groups:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        probe.communicate(timeout=2)


@pytest.mark.parametrize('disposition', ['ignored', 'custom'])
def test_nonexclusive_child_wait_owner_blocks_before_command_effect(tmp_path, disposition):
    marker = tmp_path / 'unexpected-command-effect'
    code = """import signal,sys
from pathlib import Path
from bcf_governance.tooling.evidence_execution import _run,EvidenceError
signal.signal(signal.SIGCHLD,signal.SIG_IGN if sys.argv[1]=='ignored' else lambda *args:None)
marker=Path(sys.argv[2])
try:
    _run([sys.executable,'-c',"from pathlib import Path;Path(__import__('sys').argv[1]).write_text('effect')",str(marker)],cwd=marker.parent,timeout_seconds=1)
except EvidenceError as exc:
    assert 'SIGCHLD' in str(exc)
else:
    raise AssertionError('nonexclusive wait owner executed command')
assert not marker.exists()
"""
    result = subprocess.run([sys.executable, '-c', code, disposition, str(marker)],
        cwd=tmp_path, env={'PATH': os.defpath, 'PYTHONPATH': str(ROOT)},
        capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not marker.exists()


def test_owned_command_completion_is_independent_of_foreign_process_births(tmp_path, monkeypatch):
    """Introduce real unrelated children between unmodified inventory reads."""
    from bcf_governance.tooling import evidence_execution

    original = evidence_execution._process_group_snapshot
    foreign = []
    calls = 0

    def snapshot(group):
        nonlocal calls
        observed = original(group)
        calls += 1
        if calls % 2:
            foreign.append(subprocess.Popen(
                [sys.executable, '-c', 'import time;time.sleep(20)'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            ))
        else:
            child = foreign.pop()
            child.kill()
            child.wait(timeout=2)
        return observed

    monkeypatch.setattr(evidence_execution, '_process_group_snapshot', snapshot)
    try:
        result = evidence_execution._run(
            [sys.executable, '-c', "print('owned-command-completed')"],
            cwd=tmp_path, timeout_seconds=1, cleanup_timeout_seconds=1,
        )
        assert (result.returncode, result.stdout, result.stderr) == (
            0, 'owned-command-completed\n', '',
        )
    finally:
        for child in foreign:
            child.kill()
            child.wait(timeout=2)
