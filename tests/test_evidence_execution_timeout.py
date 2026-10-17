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


def test_evidence_direct_child_timeout_keeps_typed_failure(tmp_path):
    result = _run([sys.executable, '-c', 'import time; time.sleep(20)'],
                  cwd=tmp_path, timeout_seconds=1)
    assert result.returncode == 126
    assert 'execution infrastructure failure' in result.stderr


def _live(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        return raw[raw.rfind(')') + 2:].split()[0] not in {'Z', 'X'}
    except FileNotFoundError:
        return False


@pytest.mark.parametrize('mode', ['timeout', 'background-success'])
def test_evidence_timeout_retires_inherited_pipe_descendants_within_outer_watchdog(tmp_path, mode):
    marker = tmp_path / 'owned-worker.json'
    worker = """import json, os, subprocess, sys, time
from pathlib import Path
path=Path(sys.argv[1]); temporary=path.with_suffix('.tmp')
metadata={'pid':os.getpid(),'group':os.getpgrp()}
temporary.write_text(json.dumps(metadata));temporary.replace(path)
background=sys.argv[2]=='background-success'
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'],
    stdout=subprocess.DEVNULL if background else None,
    stderr=subprocess.DEVNULL if background else None)
metadata['child_pid']=child.pid
temporary.write_text(json.dumps(metadata));temporary.replace(path)
print('ready',flush=True)
if background:sys.exit(0)
time.sleep(20)
"""
    probe_code = """import json, sys, time
from pathlib import Path
from bcf_governance.tooling import evidence_execution
root=Path(sys.argv[1]);marker=Path(sys.argv[2]);worker=sys.argv[3];mode=sys.argv[4]
assert Path(evidence_execution.__file__).resolve().is_relative_to(root)
start=time.monotonic()
result=evidence_execution._run([sys.executable,'-c',worker,str(marker),mode],
    cwd=marker.parent,timeout_seconds=1)
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
