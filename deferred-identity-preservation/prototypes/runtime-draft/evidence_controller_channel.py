"""Kernel-authenticated private controller messages, not provider authority.

The outside launcher selects the actual controller lifetime and hands it a
private SOCK_SEQPACKET capability. SO_PASSCRED authenticates each sender, rather
than confusing a socketpair's creator with its later controller. Payload labels
are references into the coordinator's independent plan, never owner selection.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import socket
import time
from typing import Any

from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity
from .evidence_packet_channel import receive_authenticated_packet

API_VERSION = 1
MAX_PACKET = 8192
MAX_REQUESTS = 4096
OPERATIONS = frozenset({"run_actual", "status", "cancel", "reconcile"})


@dataclass(frozen=True)
class ControllerRequest:
    request_id: str
    sequence: int
    operation: str
    invocation_id: str
    producer: str | None
    profile: str | None
    control: str | None
    sender: ProcessIdentity
    packet_sha256: str
    replayed: bool


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OwnerAdmissionError("controller message has duplicate fields")
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise OwnerAdmissionError("controller message has a non-finite number")


def _identity(value: Any) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is None:
        raise OwnerAdmissionError("controller invocation reference is malformed")
    return value


class ControllerChannel:
    """Selected by trusted outside bootstrap; decoded messages grant no effects."""

    def __init__(self, connection: socket.socket, *, controller: ProcessIdentity,
                 epoch: str) -> None:
        if (connection.family != socket.AF_UNIX
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                or type(controller) is not ProcessIdentity
                or type(epoch) is not str or re.fullmatch("[0-9a-f]{32}", epoch) is None):
            raise OwnerAdmissionError("controller requires a registered private packet channel")
        if ProcessIdentity.observe(controller.pid) != controller:
            raise OwnerAdmissionError("controller registration lifetime is not current")
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self._connection = connection
        self._controller = controller
        self._epoch = epoch
        self._last_sequence = 0
        self._seen: dict[str, ControllerRequest] = {}

    def receive(self, *, deadline: float) -> ControllerRequest:
        data = receive_authenticated_packet(self._connection, sender=self._controller,
            deadline=deadline, peer_label="controller", maximum=MAX_PACKET)
        try:
            row = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise OwnerAdmissionError("controller packet is not closed JSON") from error
        if type(row) is not dict or set(row) != {"version", "epoch", "request_id", "sequence", "operation", "body"}:
            raise OwnerAdmissionError("controller packet is outside its closed schema")
        if (type(row["version"]) is not int or row["version"] != API_VERSION
                or row["epoch"] != self._epoch or type(row["request_id"]) is not str
                or re.fullmatch("[0-9a-f]{32}", row["request_id"]) is None
                or type(row["sequence"]) is not int or not 1 <= row["sequence"] <= 1_000_000
                or type(row["operation"]) is not str or row["operation"] not in OPERATIONS):
            raise OwnerAdmissionError("controller packet identity or operation is invalid")
        body = row["body"]
        expected = {"invocation_id", "producer", "profile", "control"} if row["operation"] == "run_actual" else {"invocation_id"}
        if type(body) is not dict or set(body) != expected:
            raise OwnerAdmissionError("controller operation cannot select an owner or host path")
        invocation_id = _identity(body["invocation_id"])
        producer: str | None = None
        profile: str | None = None
        control: str | None = None
        if row["operation"] == "run_actual":
            producer, profile, control = (_identity(body[key]) for key in ("producer", "profile", "control"))
        digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if time.monotonic() >= deadline:
            raise OwnerAdmissionError("controller observation deadline exhausted")
        previous = self._seen.get(row["request_id"])
        if previous is not None:
            if previous.packet_sha256 != digest:
                raise OwnerAdmissionError("controller request ID was reused with changed content")
            return ControllerRequest(previous.request_id, previous.sequence, previous.operation,
                previous.invocation_id, previous.producer, previous.profile, previous.control,
                previous.sender, previous.packet_sha256, True)
        if row["sequence"] <= self._last_sequence or len(self._seen) >= MAX_REQUESTS:
            raise OwnerAdmissionError("controller request is out of order or allocation is exhausted")
        request = ControllerRequest(row["request_id"], row["sequence"], row["operation"],
            invocation_id, producer, profile, control, self._controller, digest, False)
        # Reserve before dispatch. A replay returns an acceptance observation;
        # it is never permission to execute the backend/provider operation again.
        self._seen[request.request_id] = request
        self._last_sequence = request.sequence
        return request
