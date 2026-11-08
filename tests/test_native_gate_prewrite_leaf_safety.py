"""Real leaf IO and flock controls stay inside owned temporary paths."""
from pathlib import Path
from types import SimpleNamespace
import os
import pytest
from bcf_governance.tooling import local_execution_admission as owner


def settings():
    return SimpleNamespace(execution_inputs=lambda: {})


def local_leaf(tmp_path, monkeypatch):
    leaf = tmp_path/"gate.lock"
    monkeypatch.setattr(owner, "Path", lambda value: leaf)
    return leaf


def test_new_safe_native_leaf_and_competing_owner(tmp_path, monkeypatch):
    leaf = local_leaf(tmp_path, monkeypatch)
    with owner.local_gate_lease("a"*40, custody_settings=settings()):
        assert leaf.read_bytes() == b"a"*40+b"\n"
        with pytest.raises(owner.LocalExecutionAdmissionError, match="busy_deferred"):
            with owner.local_gate_lease("b"*40, custody_settings=settings()):
                raise AssertionError("competing owner admitted")
    assert leaf.read_bytes() == b"a"*40+b"\n"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "oversize", "fifo"])
def test_unsafe_leaf_refused_before_read_or_write(tmp_path, monkeypatch, kind):
    leaf = local_leaf(tmp_path, monkeypatch)
    protected = tmp_path/"protected"; protected.write_bytes(b"protected")
    if kind == "symlink": leaf.symlink_to(protected)
    elif kind == "hardlink": os.link(protected, leaf)
    elif kind == "oversize": leaf.write_bytes(b"x"*4097)
    else: os.mkfifo(leaf, 0o600)
    def forbidden(*args, **kwargs):
        raise AssertionError("unsafe leaf admitted to text IO")
    monkeypatch.setattr(owner.os, "fdopen", forbidden)
    with pytest.raises(owner.LocalExecutionAdmissionError, match="unsafe"):
        with owner.local_gate_lease("a"*40, custody_settings=settings()): pass
    assert protected.read_bytes() == b"protected"


@pytest.mark.parametrize("point", ["open", "flock-swap", "flock-hardlink", "flock-remove"])
def test_inode_change_is_refused_before_truncate(tmp_path, monkeypatch, point):
    leaf = local_leaf(tmp_path, monkeypatch); leaf.write_bytes(b"original")
    replacement = tmp_path/"replacement"; replacement.write_bytes(b"protected")
    saved = tmp_path/"saved"; linked = tmp_path/"linked"
    real_open = owner.os.open; real_flock = owner.fcntl.flock
    def mutate():
        if point == "flock-hardlink": os.link(leaf, linked)
        elif point == "flock-remove": leaf.rename(saved)
        else: leaf.rename(saved); replacement.rename(leaf)
    def swapped_open(path, flags, mode=0o777):
        if path == leaf and point == "open": mutate()
        return real_open(path, flags, mode)
    def swapped_flock(fd, operation):
        if operation == (owner.fcntl.LOCK_EX | owner.fcntl.LOCK_NB) and point != "open": mutate()
        return real_flock(fd, operation)
    monkeypatch.setattr(owner.os, "open", swapped_open)
    monkeypatch.setattr(owner.fcntl, "flock", swapped_flock)
    with pytest.raises(owner.LocalExecutionAdmissionError, match="unsafe|inode changed"):
        with owner.local_gate_lease("a"*40, custody_settings=settings()): pass
    if point == "flock-hardlink":
        assert leaf.read_bytes() == linked.read_bytes() == b"original"
        assert replacement.read_bytes() == b"protected"
    elif point == "flock-remove":
        assert saved.read_bytes() == b"original"
        assert not leaf.exists()
        assert replacement.read_bytes() == b"protected"
    else:
        assert saved.read_bytes() == b"original"
        assert leaf.read_bytes() == b"protected"


def test_foreign_uid_leaf_refused_before_open(tmp_path, monkeypatch):
    leaf = local_leaf(tmp_path, monkeypatch); leaf.write_bytes(b"original")
    actual_uid = os.getuid()
    monkeypatch.setattr(owner.os, "getuid", lambda: actual_uid+1)
    with pytest.raises(owner.LocalExecutionAdmissionError, match="unsafe"):
        with owner.local_gate_lease("a"*40, custody_settings=settings()): pass
    assert leaf.read_bytes() == b"original"


def test_absent_to_existing_leaf_refuses_without_text_io(tmp_path, monkeypatch):
    leaf = local_leaf(tmp_path, monkeypatch)
    original_open = owner.os.open
    def appeared(path, flags, mode=0o777):
        assert flags & os.O_EXCL
        leaf.write_bytes(b"protected")
        return original_open(path, flags, mode)
    def forbidden(*args, **kwargs):
        raise AssertionError("raced unrelated inode admitted to text IO")
    monkeypatch.setattr(owner.os, "open", appeared)
    monkeypatch.setattr(owner.os, "fdopen", forbidden)
    with pytest.raises(owner.LocalExecutionAdmissionError, match="unsafe"):
        with owner.local_gate_lease("a"*40, custody_settings=settings()): pass
    assert leaf.read_bytes() == b"protected"


def test_existing_leaf_disappearance_never_creates_replacement(tmp_path, monkeypatch):
    leaf = local_leaf(tmp_path, monkeypatch); leaf.write_bytes(b"original")
    saved = tmp_path/"saved"
    original_open = owner.os.open
    def disappeared(path, flags, mode=0o777):
        assert not flags & os.O_CREAT
        leaf.rename(saved)
        return original_open(path, flags, mode)
    monkeypatch.setattr(owner.os, "open", disappeared)
    with pytest.raises(owner.LocalExecutionAdmissionError, match="unsafe"):
        with owner.local_gate_lease("a"*40, custody_settings=settings()): pass
    assert not leaf.exists()
    assert saved.read_bytes() == b"original"
