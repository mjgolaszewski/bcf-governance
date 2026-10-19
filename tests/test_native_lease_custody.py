"""Real descriptor-lifetime controls for the existing native lease owner."""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import select
import subprocess
import sys

import pytest

from bcf_governance.tooling.local_execution_admission import local_gate_lease
from bcf_governance.tooling.runtime_capacity import (
    EXECUTION_STATE_ENVIRONMENT,
    allocate_execution_state,
    retire_execution_state,
)
from tests.test_local_execution_admission import _runtime_contract


@pytest.fixture
def lease_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in EXECUTION_STATE_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    state = allocate_execution_state(
        tmp_path, _runtime_contract(), session_id=tmp_path.name,
        workload_id="native-custody-control", execution_id="descriptor", invocation={},
    )
    for name, value in state.environment().items():
        monkeypatch.setenv(name, value)
    try:
        yield Path(f"/tmp/bcf-local-gate-{os.getuid()}-{state.namespace}.lock")
    finally:
        retire_execution_state(state)


def _busy(path: Path) -> bool:
    with path.open("r+") as probe:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(probe, fcntl.LOCK_UN)
        return False


def _descriptor(path: Path) -> int:
    expected = path.stat()
    found = []
    for entry in Path("/proc/self/fd").iterdir():
        try:
            value = os.fstat(int(entry.name))
        except OSError:
            continue
        if (value.st_dev, value.st_ino) == (expected.st_dev, expected.st_ino):
            found.append(int(entry.name))
    assert len(found) == 1, "fixture must identify the actual acquired descriptor"
    return found[0]


def test_native_lease_releases_after_ordinary_unbound_scope(lease_path: Path) -> None:
    with local_gate_lease("a" * 40):
        identity = lease_path.stat()
        assert _busy(lease_path)
    assert not _busy(lease_path)
    assert lease_path.stat().st_ino == identity.st_ino


def test_native_lease_remains_owned_by_inherited_descriptor(lease_path: Path) -> None:
    child = None
    try:
        with local_gate_lease("b" * 40):
            descriptor = _descriptor(lease_path)
            identity = lease_path.stat()
            program = (
                "import os,sys; fd=int(sys.argv[1]); s=os.fstat(fd); "
                "assert (s.st_dev,s.st_ino)==(int(sys.argv[2]),int(sys.argv[3])); "
                "print('ready',flush=True); sys.stdin.buffer.read()"
            )
            child = subprocess.Popen(
                [sys.executable, "-I", "-c", program, str(descriptor),
                 str(identity.st_dev), str(identity.st_ino)],
                pass_fds=(descriptor,), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            assert child.stdout is not None
            assert select.select([child.stdout], [], [], 5)[0], "holder startup failed"
            assert child.stdout.readline() == b"ready\n"
            assert child.poll() is None
        assert child.poll() is None, "real inherited holder must still be alive"
        assert _busy(lease_path), "lease became free while its inherited descriptor was live"
    finally:
        if child is not None:
            try:
                child.communicate(input=b"stop", timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
    assert child is not None and child.returncode == 0
    assert not _busy(lease_path)
