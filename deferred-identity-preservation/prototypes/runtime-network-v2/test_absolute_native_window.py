"""Actual guardian birth/timeout evidence for nonextending absolute windows."""
import importlib
from pathlib import Path
import sys
import time

import pytest

from test_owner_registration import registration as _registration

core = importlib.import_module('_bcf_owner_runtime.evidence_process_supervisor')


def test_setup_delay_consumes_original_window_and_actual_child_is_reaped(tmp_path):
    deadline = time.monotonic()+0.8
    cleanup = deadline+0.5
    time.sleep(0.2)
    marker = tmp_path/'child.pid'
    command = [sys.executable, '-I', '-S', '-B', '-c',
        'import os,time;from pathlib import Path;Path('+repr(str(marker))+').write_text(str(os.getpid()));time.sleep(30)']
    started = time.monotonic()
    result = core.run_owned_command(command, cwd=tmp_path, env={'PATH': '/usr/bin:/bin'},
        timeout_seconds=10, cleanup_seconds=10,
        absolute_body_deadline=deadline, absolute_cleanup_deadline=cleanup)
    assert result.returncode == 126 and 'timed out' in result.stderr
    assert time.monotonic()-started < 1.5
    assert marker.exists() and not Path('/proc', marker.read_text()).exists()


def test_actual_guardian_arguments_bind_both_original_deadlines(tmp_path):
    deadline = time.monotonic()+3
    cleanup = deadline+0.75
    observed = []

    def ready(pid):
        arguments = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
        observed.append((float(arguments[4]), float(arguments[5])))

    result = core.run_owned_command([sys.executable, '-I', '-S', '-B', '-c', 'print("done")'],
        cwd=tmp_path, env={'PATH': '/usr/bin:/bin'}, timeout_seconds=20, cleanup_seconds=20,
        absolute_body_deadline=deadline, absolute_cleanup_deadline=cleanup,
        on_supervisor_ready=ready)
    assert result.returncode == 0 and result.stdout == 'done\n'
    assert len(observed) == 1
    body, reserve = observed[0]
    assert body <= deadline and 0 < reserve <= 0.75
    assert body+reserve <= cleanup


@pytest.mark.parametrize('kind', ['body_only', 'cleanup_only', 'expired', 'nan', 'bool', 'reversed'])
def test_invalid_absolute_windows_execute_nothing(tmp_path, kind):
    now = time.monotonic()
    pairs = {'body_only': (now+5, None), 'cleanup_only': (None, now+6),
             'expired': (now-1, now+5), 'nan': (float('nan'), now+5),
             'bool': (True, now+5), 'reversed': (now+5, now+4)}
    body, cleanup = pairs[kind]
    marker = tmp_path/'must-not-run'
    with pytest.raises(core.OwnedProcessError):
        core.run_owned_command([sys.executable, '-c', 'open('+repr(str(marker))+',"w").write("ran")'],
            cwd=tmp_path, env={'PATH': '/usr/bin:/bin'}, timeout_seconds=10, cleanup_seconds=10,
            absolute_body_deadline=body, absolute_cleanup_deadline=cleanup)
    assert not marker.exists()
