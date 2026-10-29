"""Cocoon coordinator port backed by the original Root's authenticated channel.

Bootstrap metadata comes from the original launcher. It bounds requests but
never replaces the Root registry's kernel and native-closure observations.
"""
from __future__ import annotations

from dataclasses import asdict
import time

from .issuer.contracts import Admission, Refused
from .runtime.evidence_execution_owner import ProcessIdentity
from .runtime.evidence_invocation_registry import RegistryAdmission, lifetime
from .runtime.evidence_registry_channel import RegistryOwnerClient, admission_metadata


class OriginalCoordinator:
    def __init__(self, client: RegistryOwnerClient, *, root: ProcessIdentity,
                 original: RegistryAdmission) -> None:
        if (type(client) is not RegistryOwnerClient
                or type(root) is not ProcessIdentity
                or ProcessIdentity.observe(root.pid) != root
                or type(original) is not RegistryAdmission
                or lifetime(root) != original.coordinator_lifetime):
            raise Refused()
        self._original = admission_metadata(asdict(original))
        self._root = root
        self._client = client

    def _metadata(self, admission: Admission) -> RegistryAdmission:
        if type(admission) is not Admission:
            raise Refused()
        metadata = admission_metadata(asdict(admission))
        if metadata != self._original:
            raise Refused()
        return metadata

    def _admission(self, metadata: RegistryAdmission) -> Admission:
        if metadata != self._original:
            raise Refused()
        return Admission(**asdict(metadata))

    def admit(self, context: str, manifest_path: str, held_pid: int) -> Admission:
        if context != self._original.context:
            raise Refused()
        return self._admission(self._client.admit(manifest_path=manifest_path, held_pid=held_pid))

    def recheck(self, admission: Admission, *, cleanup: bool) -> None:
        if type(cleanup) is not bool:
            raise Refused()
        self._client.recheck(self._metadata(admission), cleanup=cleanup)

    def recover(self, context: str, coordinator_lifetime: str,
                execution_id: str) -> Admission:
        if context != self._original.context:
            raise Refused()
        return self._admission(self._client.recover(
            coordinator_lifetime=coordinator_lifetime, execution_id=execution_id))

    def native_closed(self, admission: Admission) -> None:
        self._client.native_closed(self._metadata(admission))

    def authenticate_control(self, identity: ProcessIdentity) -> str:
        if (type(identity) is not ProcessIdentity or identity != self._root
                or ProcessIdentity.observe(self._root.pid) != self._root):
            raise Refused()
        return self._original.coordinator_lifetime

    def control_deadline(self, identity: ProcessIdentity, context: str | None,
                         operation: str | None) -> float:
        self.authenticate_control(identity)
        if context is None and operation is None:
            deadline = self._original.cleanup_deadline
        else:
            if context != self._original.context:
                raise Refused()
            deadline = (self._original.cleanup_deadline
                        if operation in {'finish_execution', 'reconcile_execution'}
                        else self._original.access_deadline)
        if time.monotonic() >= deadline:
            raise Refused()
        return deadline
