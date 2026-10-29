"""Original Root lifecycle driver; installation and real provider ports are external.

Only the keeper releases its original leases, after actual native closure and
both authenticated owner cleanups. Unknown outcomes retain custody in HOLD.
"""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import json
import time
from typing import Any

from .evidence_execution_owner import OwnerAdmissionError
from .evidence_execution_view import WorkingView, inspect_view
from .evidence_invocation_registry import ActualInvocationRegistry
from .evidence_owner_control import OwnerControlPair, OwnerOutcomeUncertain
from .evidence_serial_dispatch import OriginalRootDispatcher


class OriginalInvocationDriver:
    def __init__(self, registry: ActualInvocationRegistry, *,
                 dispatcher: OriginalRootDispatcher, owners: OwnerControlPair,
                 original_source: WorkingView) -> None:
        if (type(registry) is not ActualInvocationRegistry
                or type(dispatcher) is not OriginalRootDispatcher or dispatcher._registry is not registry
                or type(owners) is not OwnerControlPair or owners._context != registry.admission.context
                or owners._state != 'new' or owners._roles
                or type(original_source) is not WorkingView):
            raise OwnerAdmissionError('original Root lifecycle composition is required')
        registry._root(cleanup=False)
        reservation = owners._reserved
        reservation.binding.validate()
        reservation.validate_allocation()
        for role in ('issuer', 'custody'):
            registration = getattr(reservation.binding, role)
            if registration.owner != registry._owners[role]:
                raise OwnerAdmissionError('lifecycle owner differs from original registry role')
        manifest = json.loads(registry.manifest_path.read_bytes())
        actual = reservation.actual
        if ((actual.producer, actual.profile, actual.control)
                != (manifest['producer'], manifest['profile'], manifest['control'])
                or original_source.root != actual.repository
                or original_source.digest != registry._plan.inventory.source_digest
                or inspect_view(original_source.root, tuple(row[0] for row in original_source.manifest)) != original_source
                or registry._plan.release_attempted or registry._keeper.released
                or registry.admission.access_deadline > reservation.deadline
                or registry.admission.cleanup_deadline > reservation.binding.absolute_deadline):
            raise OwnerAdmissionError('original source, exact route or finite allocation differs')
        self._registry = registry
        self._dispatcher = dispatcher
        self._owners = owners
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='bcf-original-owner-control')
        self._pending: Future[Any] | None = None
        self._started = False
        self._bound: set[str] = set()

    def _owner_operation(self, operation: str, *, returncode: int | None = None,
                         cleanup: bool = False) -> Any:
        if self._pending is not None and not self._pending.done():
            raise OwnerOutcomeUncertain('previous original owner operation is not terminal')
        owners = self._owners
        pending: Future[Any]
        if operation == 'prepare':
            pending = self._pool.submit(owners.prepare_actual, manifest_path=self._registry.manifest_path,
                held_peer_pid=self._registry._observation.identity.pid)
        elif operation == 'stage':
            pending = self._pool.submit(owners.stage_fresh)
        elif operation == 'arm':
            pending = self._pool.submit(owners.arm_delivery_once)
        elif operation == 'finish' and type(returncode) is int:
            pending = self._pool.submit(owners.finish_after_native, native_returncode=returncode)
        elif operation == 'reconcile':
            pending = self._pool.submit(owners.reconcile_owned)
        else:
            raise OwnerAdmissionError('unsupported original owner lifecycle operation')
        self._pending = pending
        deadline = (self._registry.admission.cleanup_deadline if cleanup
                    else self._registry.admission.access_deadline)
        first_error: BaseException | None = None
        while not pending.done():
            if time.monotonic() >= deadline:
                self._registry._hold = True
                raise OwnerOutcomeUncertain('original owner lifecycle deadline exhausted')
            try:
                self._dispatcher.poll()
            except Exception as error:
                self._registry._hold = True
                if first_error is None:
                    first_error = error
        result = pending.result()
        if first_error is not None and not cleanup:
            raise first_error
        return result

    def _bind_prepared(self) -> None:
        # Only authenticated prepare responses retained by the exact original
        # OwnerControlPair can enter this registry. No controller wire API binds IDs.
        for role, handle in self._owners._roles.items():
            if role not in self._bound:
                self._registry.bind_execution(role, handle.execution_id)
                self._bound.add(role)

    def _native_closed(self, *, cleanup: bool = False) -> dict[str, Any]:
        keeper = self._registry._keeper
        first_error: Exception | None = None
        while True:
            status = keeper.status()
            if status['state'] == 'native_closed':
                for role in self._registry._admitted:
                    self._registry.native_closed(role, self._registry.admission)
                if first_error is not None and not cleanup:
                    raise first_error
                return status
            if status['state'] != 'pending' or time.monotonic() >= self._registry.admission.cleanup_deadline:
                raise OwnerOutcomeUncertain('actual native closure remains unproven')
            try:
                self._dispatcher.poll()
            except Exception as error:
                self._registry._hold = True
                if first_error is None:
                    first_error = error
                keeper.cancel()
                # A failed channel is disabled by the dispatcher. Continue
                # observing actual Q and service surviving cleanup channels.
                time.sleep(0.02)

    def run(self) -> dict[str, Any]:
        if self._started:
            raise OwnerAdmissionError('original invocation driver cannot be replayed')
        self._started = True
        try:
            try:
                self._owner_operation('prepare')
                self._bind_prepared()
                self._owner_operation('stage')
                self._owner_operation('arm')
                self._registry._root(cleanup=False)
                self._registry._plan.release()
                terminal = self._native_closed()
                self._owner_operation('finish', returncode=terminal['returncode'], cleanup=True)
            except BaseException:
                # Record known prepare outcomes before access is irreversibly
                # held. Lost prepare IDs remain unknown; never invent a handle.
                if self._pending is None or self._pending.done():
                    try:
                        self._bind_prepared()
                    except Exception:
                        pass
                self._registry._hold = True
                self._registry._keeper.cancel()
                self._native_closed(cleanup=True)
                if self._owner_operation('reconcile', cleanup=True) is not True:
                    raise OwnerOutcomeUncertain('separate original owner cleanup remains uncertain')
                self._registry._keeper.release_after_owner_cleanup(self._owners)
                raise
            self._registry._keeper.release_after_owner_cleanup(self._owners)
            return terminal
        finally:
            # A running/uncertain operation is not cancelled into invented Q.
            # Its original transport deadlines still apply; keeper retains FD.
            self._pool.shutdown(wait=False, cancel_futures=True)
