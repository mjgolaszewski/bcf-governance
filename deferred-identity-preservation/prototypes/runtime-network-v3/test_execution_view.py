"""Real source/namespace controls, without issuer or release certification."""
from __future__ import annotations

import errno
import importlib
import types
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

import pytest

PACKAGE = "_bcf_owner_runtime"
if PACKAGE not in sys.modules:
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(Path(__file__).parent)]
    sys.modules[PACKAGE] = package
module = importlib.import_module(PACKAGE + ".evidence_execution_view")
owner_module = importlib.import_module(PACKAGE + ".evidence_execution_owner")
peer_module = importlib.import_module(PACKAGE + ".evidence_held_peer")


def test_baseline_and_actual_uncommitted_control_have_distinct_views(tmp_path: Path) -> None:
    source = tmp_path / "working"
    source.mkdir()
    (source / "application.py").write_text("VALUE = 'baseline'\n")
    baseline = module.materialize_view(source, tmp_path / "baseline", ("application.py",))
    (source / "application.py").write_text("VALUE = 'control'\n")
    control = module.materialize_view(source, tmp_path / "control", ("application.py",))
    assert baseline.digest != control.digest
    assert (baseline.root / "application.py").read_text() == "VALUE = 'baseline'\n"
    assert (control.root / "application.py").read_text() == "VALUE = 'control'\n"


def test_symlink_input_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "working"
    source.mkdir()
    (tmp_path / "private").write_text("must not copy")
    (source / "application.py").symlink_to(tmp_path / "private")
    with pytest.raises(module.ExecutionViewError, match="symlink"):
        module.materialize_view(source, tmp_path / "view", ("application.py",))
    assert not (tmp_path / "view").exists()


@pytest.mark.parametrize("name", ["../private", "/private", "application.py/../private"])
def test_escaping_input_path_is_refused(tmp_path: Path, name: str) -> None:
    with pytest.raises(module.ExecutionViewError, match="relative"):
        module.inspect_view(tmp_path, (name,))


@pytest.mark.parametrize("unsafe_mount", ["none", "source-alias", "writable-submount"])
def test_real_held_namespace_is_independently_observed_before_release(tmp_path: Path, unsafe_mount: str) -> None:
    source = tmp_path / "working"
    source.mkdir()
    (source / "application.py").write_text("VALUE = 'actual-control'\n")
    view = module.materialize_view(source, tmp_path / "snapshot", ("application.py",))
    address = "\0bcf-held-view-" + os.urandom(16).hex()
    # This is trusted test bootstrap code, not a candidate-supplied observer.
    candidate = """import errno,json,os
from pathlib import Path
raw=Path('/work/application.py').read_text()
try:Path('/work/application.py').write_text('forbidden')
except OSError as e: assert e.errno in (errno.EROFS,errno.EACCES)
else:raise AssertionError('source was writable')
assert not Path('/docker').exists() and not Path('/home').exists() and not Path('/proc').exists()
for fd in range(3,64):
 try:os.fstat(fd)
 except OSError as e:assert e.errno==errno.EBADF
 else:raise AssertionError('inherited control descriptor')
print(json.dumps({'actual_source':raw,'write_refused':True,'host_aliases_absent':True,'control_fds_absent':True}))
"""
    stub = """import os,socket,sys
with socket.socket(socket.AF_UNIX) as c:
 c.connect('\\0'+sys.argv[1]);c.sendall(b'held')
 assert c.recv(1)==b'R'
os.execv('/usr/local/bin/python3.12',['python3.12','-I','-S','-c',""" + repr(candidate) + "] )"
    command = ["/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc",
               "--unshare-uts", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
               "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
               "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache", "--symlink", "usr/bin", "/bin",
               "--ro-bind", str(view.root), "/work", "--dev", "/dev", "--tmpfs", "/tmp",
               "--clearenv", "--", "/usr/local/bin/python3.12", "-I", "-S", "-c", stub, address]
    if unsafe_mount == "source-alias":
        command[command.index("--clearenv"):command.index("--clearenv")] = ["--bind", str(view.root), "/writable-source"]
    elif unsafe_mount == "writable-submount":
        (view.root / "mutable").mkdir()
        command[command.index("--clearenv"):command.index("--clearenv")] = ["--tmpfs", "/work/mutable"]
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(address)
        listener.listen(1)
        listener.settimeout(5)
        # Abstract addresses cannot be argv strings because they contain NUL.
        # Send the printable suffix; the stub reconstructs the kernel address.
        command[-1] = address[1:]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            supervisor = owner_module.ProcessIdentity.observe(process.pid)
            if unsafe_mount != "none":
                with pytest.raises(owner_module.OwnerAdmissionError, match="writable source"):
                    peer_module.observe_held_namespace(listener, expected_view=view,
                        supervisor=supervisor, deadline=time.monotonic() + 5)
                return
            connection, observation = peer_module.observe_held_namespace(
                listener, expected_view=view, supervisor=supervisor,
                deadline=time.monotonic() + 5)
            with connection:
                pid = observation.identity.pid
                assert pid != process.pid and pid != os.getpid()
                assert observation.source_digest == view.digest
                assert connection.recv(4) == b"held"
                connection.sendall(b"R")
            stdout, stderr = process.communicate(timeout=5)
            assert process.returncode == 0, stderr
            assert json.loads(stdout) == {"actual_source": "VALUE = 'actual-control'\n",
                                         "write_refused": True, "host_aliases_absent": True, "control_fds_absent": True}
            assert not Path("/proc", str(pid)).exists()
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
    assert module.inspect_view(view.root, ("application.py",)).digest == view.digest


def test_socketpair_is_not_an_accepted_workload_peer(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "application.py").write_text("pass\n")
    view = module.materialize_view(source, tmp_path / "view", ("application.py",))
    left, right = socket.socketpair()
    try:
        with pytest.raises(owner_module.OwnerAdmissionError, match="listening"):
            peer_module.observe_held_namespace(
                left, expected_view=view,
                supervisor=owner_module.ProcessIdentity.observe(os.getpid()),
                deadline=time.monotonic() + 2)
    finally:
        left.close()
        right.close()


def test_independent_source_inspection_refuses_expired_budget_before_read(tmp_path: Path) -> None:
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(owner_module.OwnerAdmissionError, match="deadline"):
            peer_module._actual_files(descriptor, budget=peer_module._InspectionBudget(time.monotonic() - 1))
    finally:
        os.close(descriptor)


def test_independent_source_inspection_refuses_oversize_actual_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "large").write_bytes(b"123456789")
    monkeypatch.setattr(peer_module, "MAX_FILE_BYTES", 8)
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(owner_module.OwnerAdmissionError, match="regular input"):
            peer_module._actual_files(descriptor, budget=peer_module._InspectionBudget(time.monotonic() + 2))
    finally:
        os.close(descriptor)
