"""Real kernel custody controls for the typed native core; no provider effects."""
from __future__ import annotations

import fcntl
import importlib
import os
from pathlib import Path
import subprocess
import sys
from threading import Event, Timer
import time
import types

import pytest

PACKAGE = "_bcf_owner_runtime"
if PACKAGE not in sys.modules:
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(Path(__file__).parent)]
    sys.modules[PACKAGE] = package
core = importlib.import_module(PACKAGE + ".evidence_process_supervisor")


def run(tmp_path, script, **kwargs):
    return core.run_owned_command([sys.executable, "-I", "-S", "-c", script],
        cwd=tmp_path, env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        timeout_seconds=kwargs.pop("timeout_seconds", 5),
        cleanup_seconds=kwargs.pop("cleanup_seconds", 2), **kwargs)


def test_normal_exit_retains_stdout_stderr_and_returncode(tmp_path):
    observed = run(tmp_path, "import sys;print('out');print('err',file=sys.stderr);sys.exit(7)")
    assert (observed.returncode, observed.stdout, observed.stderr) == (7, "out\n", "err\n")


def test_real_timeout_reaps_actual_child_before_return(tmp_path):
    marker = tmp_path / "child.pid"
    script = "import os,time;from pathlib import Path;Path(" + repr(str(marker)) + ").write_text(str(os.getpid()));time.sleep(30)"
    started = time.monotonic()
    observed = run(tmp_path, script, timeout_seconds=0.2)
    assert observed.returncode == 126 and "timed out" in observed.stderr
    assert time.monotonic() - started < 3
    assert not Path("/proc", marker.read_text()).exists()


def test_session_escaping_descendant_is_owned_and_reaped(tmp_path):
    marker = tmp_path / "grandchild.pid"
    script = """import os,time
from pathlib import Path
pid=os.fork()
if pid:
 time.sleep(0.05)
 os._exit(0)
os.setsid()
Path(MARKER).write_text(str(os.getpid()))
time.sleep(30)
""".replace("MARKER", repr(str(marker)))
    observed = run(tmp_path, script)
    assert observed.returncode == 126 and "live descendants" in observed.stderr
    assert not Path("/proc", marker.read_text()).exists()


def test_trusted_cancel_uses_finite_cleanup_and_returns_after_quiescence(tmp_path):
    marker = tmp_path / "cancelled.pid"
    script = "import os,time;from pathlib import Path;Path(" + repr(str(marker)) + ").write_text(str(os.getpid()));time.sleep(30)"
    cancel = Event()
    timer = Timer(0.2, cancel.set)
    timer.start()
    try:
        observed = run(tmp_path, script, cancel_event=cancel)
    finally:
        timer.cancel()
        timer.join()
    assert observed.returncode == 126 and "interrupted" in observed.stderr
    assert not Path("/proc", marker.read_text()).exists()


def test_original_locked_ofd_enters_guardian_but_not_workload(tmp_path, monkeypatch):
    path = tmp_path / "original.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    expected = os.fstat(descriptor)
    launches = []
    original = subprocess.Popen
    class ObservePopen(original):
        def __init__(self, command, **kwargs):
            super().__init__(command, **kwargs)
            actual = Path("/proc", str(self.pid), "fd", str(descriptor)).stat()
            assert (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
            assert "FLOCK" in Path("/proc", str(self.pid), "fdinfo", str(descriptor)).read_text()
            launches.append(self.pid)
    monkeypatch.setattr(core.subprocess, "Popen", ObservePopen)
    script = """import errno,os
try:os.fstat(FD)
except OSError as error:assert error.errno==errno.EBADF
else:raise AssertionError('native lease leaked into candidate')
print('closed')
""".replace("FD", str(descriptor))
    try:
        observed = run(tmp_path, script, lease_descriptors=(descriptor,))
        assert observed.returncode == 0 and observed.stdout == "closed\n"
        assert launches and all(not Path("/proc", str(pid)).exists() for pid in launches)
        independent = os.open(path, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(independent)
    finally:
        os.close(descriptor)
    independent = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(independent)


@pytest.mark.parametrize("value", [0, -1, True, float("inf"), float("nan")])
def test_invalid_deadlines_refuse_before_child_allocation(tmp_path, value):
    with pytest.raises(core.OwnedProcessError, match="finite positive"):
        run(tmp_path, "raise AssertionError('must not run')", timeout_seconds=value)
