from __future__ import annotations

import fcntl
from pathlib import Path

import pytest

from bcf_governance.tooling import local_execution_admission as admission


@pytest.fixture
def gate(tmp_path: Path, monkeypatch):
    path = tmp_path / "fixture.lock"
    # Unit-only file redirection; no governed work or production gate uses it.
    expected = f"/tmp/bcf-local-gate-{admission.os.getuid()}.lock"
    constructor = Path
    monkeypatch.setattr(admission, "authenticated_execution_state_namespace", lambda _: None)
    monkeypatch.setattr(admission, "Path", lambda value: path if str(value) == expected else constructor(value))
    return path


@pytest.mark.parametrize("retained", [b"a" * 40 + b"\n", b"\xff\xfe\n", b"untrusted-retained-data\nnot-an-owner\n"])
def test_busy_gate_never_promotes_retained_text_to_owner(gate, retained):
    gate.write_bytes(retained)
    with gate.open("r+") as holder:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(admission.LocalExecutionAdmissionError) as caught:
            with admission.local_gate_lease("b" * 40):
                pytest.fail("busy gate entered work")
        message = str(caught.value)
        assert message == "local_execution_busy_deferred: shared local gate is locked; execution owner is unverified"
        assert gate.read_bytes() == retained
        with gate.open("r+") as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_unowned_gate_reuses_exact_file_and_records_execution(gate):
    gate.write_bytes(b"\xffstale")
    inode = gate.stat().st_ino
    with admission.local_gate_lease("b" * 40):
        assert gate.stat().st_ino == inode
        assert gate.read_text() == "b" * 40 + "\n"
        with gate.open("r+") as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    with gate.open("r+") as contender:
        fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
