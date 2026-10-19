"""Kernel input sealing must not depend on optional CPython header exports."""
from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
import sys
import time

import pytest

from bcf_governance.tooling import evidence_process_supervisor as supervisor
from bcf_governance.tooling.local_execution_admission import local_gate_lease
from tests.test_native_lease_custody import lease_path  # noqa: F401


def test_real_input_seals_without_optional_python_constant_names(monkeypatch) -> None:
    for name in ('F_ADD_SEALS', 'F_GET_SEALS', 'F_SEAL_SEAL', 'F_SEAL_SHRINK', 'F_SEAL_GROW', 'F_SEAL_WRITE'):
        monkeypatch.delattr(fcntl, name, raising=False)
    fd, device, inode = supervisor._stage_command_input(b'kernel-owned\x00\xff', time.monotonic() + 5)
    try:
        value = os.fstat(fd)
        assert (value.st_dev, value.st_ino) == (device, inode)
        assert fcntl.fcntl(fd, 1034) & 0xF == 0xF, 'actual-kernel-input-seals-missing'
        assert os.read(fd, 100) == b'kernel-owned\x00\xff'
        with pytest.raises(OSError) as error:
            os.write(fd, b'forged')
        assert error.value.errno == errno.EPERM
    finally:
        os.close(fd)
    with pytest.raises(OSError) as error:
        os.fstat(fd)
    assert error.value.errno == errno.EBADF


def test_kernel_sealing_rejection_closes_input_before_command_allocation(monkeypatch) -> None:
    descriptor = []
    original_create = os.memfd_create
    def create(*args):
        fd = original_create(*args)
        descriptor.append(fd)
        return fd
    def deny(*args):
        raise OSError(errno.EOPNOTSUPP, 'kernel sealing unavailable')
    monkeypatch.setattr(os, 'memfd_create', create)
    monkeypatch.setattr(fcntl, 'fcntl', deny)
    with pytest.raises(OSError, match='kernel sealing unavailable'):
        supervisor._stage_command_input(b'never unsealed', time.monotonic() + 5)
    assert len(descriptor) == 1
    with pytest.raises(OSError) as error:
        os.fstat(descriptor[0])
    assert error.value.errno == errno.EBADF


def test_actual_guardian_rejects_unsealed_input_before_command(lease_path: Path, tmp_path: Path, monkeypatch) -> None:
    marker = tmp_path / 'must-not-run'
    children = []
    original_popen = supervisor.subprocess.Popen
    def unsealed(data, deadline):
        fd = os.memfd_create('deliberately-unsealed-control', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.write(fd, data)
        os.lseek(fd, 0, os.SEEK_SET)
        value = os.fstat(fd)
        return fd, value.st_dev, value.st_ino
    def observe(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(supervisor, '_stage_command_input', unsealed)
    monkeypatch.setattr(supervisor.subprocess, 'Popen', observe)
    with local_gate_lease('f' * 40):
        with pytest.raises(supervisor.OwnedProcessError):
            supervisor.run_owned_command(
                [sys.executable, '-I', '-c', 'from pathlib import Path;import sys;Path(sys.argv[1]).touch()', str(marker)],
                cwd=tmp_path, env=dict(os.environ), timeout_seconds=3, cleanup_seconds=1,
                input_bytes=b'not immutable',
            )
        assert len(children) == 1
        assert children[0].wait(timeout=2) == 126
        assert not marker.exists(), 'unsealed-input-command-was-allocated'
