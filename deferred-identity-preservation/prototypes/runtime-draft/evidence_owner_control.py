"""Closed metadata-only lifecycle calls to independently registered owner peers.

Owners, not this client or a candidate artifact, verify context and actual kernel
peers, persist intents, grant provider operations, serve fresh workload sockets,
and authenticate their own cleanup. Unsupported owner protocol refuses by default.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Any

from .evidence_execution_owner import OwnerAdmissionError, OwnerRegistration, ProcessIdentity
from .evidence_owner_registration import ReservedOwnerInvocation

CONTRACT = "bcf.actual-invocation-owner.v1"


class OwnerOutcomeUncertain(OwnerAdmissionError):
    """A potentially accepted owner operation requires owned reconciliation."""


@dataclass(frozen=True)
class _RoleExecution:
    role: str
    registration: OwnerRegistration
    execution_id: str


class OwnerControlPair:
    """Installed controller only; no owner selection from candidate input."""

    def __init__(self, reserved: ReservedOwnerInvocation, *, context_digest: str) -> None:
        if type(reserved) is not ReservedOwnerInvocation or not re.fullmatch("[0-9a-f]{64}", context_digest):
            raise OwnerAdmissionError("registered actual invocation and context digest are required")
        reserved.binding.validate()
        reserved.validate_allocation()
        self._reserved = reserved
        self._context = context_digest
        self._roles: dict[str, _RoleExecution] = {}
        self._state = "new"
        self._cleanup: dict[str, dict[str, Any]] = {}
        self._uncertain = False
        self._cleanup_deadline: float | None = None
        self._cleanup_errors: dict[str, str] = {}

    def _call(self, role: str, operation: str, *, execution_id: str | None = None,
              fields: dict[str, Any] | None = None,
              cleanup_deadline: float | None = None) -> dict[str, Any]:
        self._reserved.validate_allocation()
        cleanup_only = operation in {"finish_execution", "reconcile_execution"}
        owner = self._reserved.binding.issuer if role == "issuer" else self._reserved.binding.custody
        if cleanup_only:
            self._reserved.binding.validate_cleanup_owner(owner)
        else:
            self._reserved.binding.validate()
        deadline = (self._reserved.binding.absolute_deadline if cleanup_only
                    else self._reserved.deadline)
        if cleanup_deadline is not None:
            if (not cleanup_only or type(cleanup_deadline) not in (int, float)
                    or not math.isfinite(cleanup_deadline)):
                raise OwnerAdmissionError("owner cleanup deadline is invalid")
            deadline = min(deadline, cleanup_deadline)
        if deadline <= time.monotonic():
            raise OwnerAdmissionError("owner cleanup deadline exhausted")
        request = {"contract": CONTRACT, "operation": operation, "role": role,
                   "context_digest": self._context, **(fields or {})}
        if execution_id is not None:
            request["execution_id"] = execution_id
        self._uncertain = True
        try:
            with owner.connect(deadline=deadline) as session:
                response = session.request(request, response_timeout_seconds=(
                    60 if operation in {"stage_fresh_workload", "arm_delivery_once", "finish_execution"} else 30))
            required = {"contract", "role", "context_digest", "status", "execution_id"}
            if set(response) != required:
                raise OwnerOutcomeUncertain("owner response is outside the closed metadata contract")
            if (response["contract"] != CONTRACT or response["role"] != role
                    or response["context_digest"] != self._context
                    or type(response["execution_id"]) is not str
                    or re.fullmatch("[A-Za-z0-9._:-]{1,128}", response["execution_id"]) is None
                    or (execution_id is not None and response["execution_id"] != execution_id)):
                raise OwnerOutcomeUncertain("owner response does not bind the actual execution")
            self._uncertain = False
            return response
        except BaseException:
            self._state = "uncertain"
            raise

    def prepare_actual(self, *, manifest_path: Path, held_peer_pid: int) -> None:
        if self._state != "new" or type(held_peer_pid) is not int or held_peer_pid <= 0:
            raise OwnerAdmissionError("owner preparation requires one actual held invocation")
        if not manifest_path.is_absolute() or manifest_path.is_symlink() or not manifest_path.is_file():
            raise OwnerAdmissionError("owner context manifest must be an owned regular file")
        raw = manifest_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != self._context:
            raise OwnerAdmissionError("owner context manifest does not match actual context")
        # The owner independently reads and checks this manifest and the actual
        # peer's mounted view. A caller-provided hash or PID is not admission.
        for role in ("issuer", "custody"):
            response = self._call(role, "prepare_actual_execution", fields={
                "manifest_path": str(manifest_path), "held_peer_pid": held_peer_pid})
            if response["status"] != "prepared":
                self._state = "uncertain"
                raise OwnerOutcomeUncertain("owner did not prepare the actual execution")
            owner = self._reserved.binding.issuer if role == "issuer" else self._reserved.binding.custody
            self._roles[role] = _RoleExecution(role, owner, response["execution_id"])
        self._state = "prepared"

    def stage_fresh(self) -> None:
        if self._state != "prepared":
            raise OwnerAdmissionError("fresh staging requires both authenticated preparations")
        self._advance("stage_fresh_workload", "staged")

    def arm_delivery_once(self) -> None:
        if self._state != "staged":
            raise OwnerAdmissionError("delivery arming requires fresh staged ownership")
        # This does not claim a secret has been written. Each owner serves the
        # unchanged workload ABI only to its independently rechecked real peer.
        self._advance("arm_delivery_once", "armed")

    def _advance(self, operation: str, expected_status: str) -> None:
        for role in ("issuer", "custody"):
            handle = self._roles[role]
            response = self._call(role, operation, execution_id=handle.execution_id)
            if response["status"] != expected_status:
                self._state = "uncertain"
                raise OwnerOutcomeUncertain("owner lifecycle transition is not authenticated")
        self._state = expected_status

    def finish_after_native(self, *, native_returncode: int) -> None:
        """Report observation; owners independently require registry-bound Q/EOF/reap."""
        if self._state != "armed" or type(native_returncode) is not int:
            raise OwnerAdmissionError("owner finish requires the actual native terminal result")
        self._close_owned("finish_execution", {"native_returncode": native_returncode})

    def reconcile_owned(self) -> bool:
        # Context reconciliation covers pre-ID and lost-prepare outcomes. Never
        # retry preparation, staging, secret delivery, or extend the allocation.
        try:
            self._close_owned("reconcile_execution", {})
        except BaseException:
            return False
        return True

    def _close_owned(self, operation: str, fields: dict[str, Any]) -> None:
        pending = [role for role in ("issuer", "custody") if role not in self._cleanup]
        if not pending:
            self._state = "closed"
            self._uncertain = False
            return
        if self._cleanup_deadline is None:
            self._cleanup_deadline = min(self._reserved.binding.absolute_deadline,
                time.monotonic() + self._reserved.binding.cleanup_seconds)
        deadline = self._cleanup_deadline
        if time.monotonic() >= deadline:
            self._state = "uncertain"
            self._uncertain = True
            self._cleanup_errors.update({role: "cleanup_deadline_exhausted" for role in pending})
            raise OwnerOutcomeUncertain("independent owner cleanup deadline is exhausted")
        self._state = "closing"
        # Each independent peer gets the same finite window. A stalled or dead
        # issuer cannot prevent attempting custody reconciliation, or vice versa.
        with ThreadPoolExecutor(max_workers=len(pending), thread_name_prefix="bcf-owner-cleanup") as pool:
            futures = {}
            for role in pending:
                handle = self._roles.get(role)
                futures[role] = pool.submit(self._call, role, operation,
                    execution_id=handle.execution_id if handle else None,
                    fields=fields, cleanup_deadline=deadline)
            for role in pending:
                try:
                    response = futures[role].result()
                    if response["status"] != "closed":
                        raise OwnerOutcomeUncertain("independent owner cleanup is not closed")
                    owner = self._reserved.binding.issuer if role == "issuer" else self._reserved.binding.custody
                    self._roles[role] = _RoleExecution(role, owner, response["execution_id"])
                    self._cleanup[role] = {
                        "role": role, "owner_pid": owner.owner.pid,
                        "execution_id": response["execution_id"], "context_digest": self._context,
                        "response_digest": hashlib.sha256(json.dumps(response, sort_keys=True,
                            separators=(",", ":")).encode()).hexdigest(),
                    }
                    self._cleanup_errors.pop(role, None)
                except BaseException as error:
                    # Preserve role outcomes without serializing provider error
                    # bodies. Authenticated successes are never discarded/replayed.
                    self._cleanup_errors[role] = type(error).__name__[:64]
        if set(self._cleanup) != {"issuer", "custody"}:
            self._state = "uncertain"
            self._uncertain = True
            raise OwnerOutcomeUncertain("separate authenticated owner cleanup remains uncertain")
        self._state = "closed"
        self._uncertain = False

    def verified_cleanup(self, context_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if (self._state != "closed" or self._uncertain or context_digest != self._context
                or set(self._cleanup) != {"issuer", "custody"}):
            raise OwnerAdmissionError("separate authenticated cleanup is unavailable")
        # Authenticated durable closure does not become unknown merely because
        # the owner exited or the access allocation expired after its receipt.
        # Releasing already closed custody grants no new provider operation.
        if ProcessIdentity.observe(os.getpid()) != self._reserved.binding.controller:
            raise OwnerAdmissionError("cleanup belongs to another controller lifetime")
        return dict(self._cleanup["issuer"]), dict(self._cleanup["custody"])
