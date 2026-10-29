"""Actual Unix peer and protocol controls; no issuer or JIT conformance claim."""
from __future__ import annotations

import importlib.util
import multiprocessing
import os
from pathlib import Path
import socket
import struct
import sys
import time

import pytest

PATH = Path(__file__).with_name("evidence_execution_owner.py")
spec = importlib.util.spec_from_file_location("execution_owner", PATH)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def serve(path: str, ready: multiprocessing.connection.Connection, mode: str) -> None:
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        os.chmod(path, 0o600)
        listener.listen(1)
        ready.send(os.getpid())
        with listener.accept()[0] as connection:
            if mode == "stall":
                time.sleep(2)
                return
            raw = connection.recv(4096)
            if not raw:
                return
            if mode == "oversize":
                connection.sendall(struct.pack("!I", 65537))
            else:
                connection.sendall(struct.pack("!I", 2) + b"{}")
            connection.recv(1)


@pytest.fixture
def owner(socket_root: Path):
    tmp_path = socket_root
    children = []
    def start(mode="normal"):
        path = str(tmp_path / ("owner-" + str(len(children)) + ".sock"))
        parent, child = multiprocessing.Pipe(False)
        process = multiprocessing.Process(target=serve, args=(path, child, mode))
        process.start()
        assert parent.poll(5)
        pid = parent.recv()
        child.close()
        parent.close()
        children.append(process)
        return module.OwnerRegistration(Path(path), module.ProcessIdentity.observe(pid))
    yield start
    for process in children:
        if process.is_alive():
            process.terminate()
        process.join(5)
        assert not process.is_alive()


def test_actual_peer_connects_and_closes(owner):
    registration = owner()
    with registration.connect(deadline=time.monotonic() + 2) as session:
        assert session.request({"operation": "inspect"}) == {}


def test_wrong_real_process_is_refused_before_request(owner):
    registration = owner()
    wrong = module.OwnerRegistration(registration.endpoint, module.ProcessIdentity.observe(os.getpid()))
    with pytest.raises(module.OwnerAdmissionError, match="peer"):
        wrong.connect(deadline=time.monotonic() + 2)


def test_oversize_frame_is_refused_before_payload(owner):
    registration = owner("oversize")
    with registration.connect(deadline=time.monotonic() + 2) as session:
        with pytest.raises(module.OwnerAdmissionError, match="frame"):
            session.request({"operation": "inspect"})


def test_real_unresponsive_owner_has_finite_deadline(owner):
    registration = owner("stall")
    started = time.monotonic()
    with registration.connect(deadline=started + 0.1) as session:
        with pytest.raises(module.OwnerAdmissionError, match="deadline"):
            session.request({"operation": "inspect"})
    assert time.monotonic() - started < 1


def test_request_size_is_bounded_before_send(owner):
    registration = owner()
    with registration.connect(deadline=time.monotonic() + 2) as session:
        with pytest.raises(module.OwnerAdmissionError, match="request"):
            session.request({"payload": "x" * 1025})


def test_endpoint_permission_mismatch_is_refused(owner):
    registration = owner()
    os.chmod(registration.endpoint, 0o666)
    with pytest.raises(module.OwnerAdmissionError, match="permission"):
        registration.connect(deadline=time.monotonic() + 2)
