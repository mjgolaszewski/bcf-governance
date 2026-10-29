"""UNRUN concrete issuer lifecycle; provider and attestor remain real required ports.

No candidate request creates those dependencies. Every uncertain mutation/partial
delivery is consumed and reconciled, never retried by this state machine.
"""
from __future__ import annotations

import asyncio
import re
import time

from .contracts import Admission, Coordinator, Refused, Uncertain, WorkloadProvider
from .journal import Journal

CONTRACT = 'bcf.actual-invocation-owner.v1'


class IssuerLifecycle:
    def __init__(self, *, coordinator: Coordinator, provider: WorkloadProvider,
                 journal: Journal) -> None:
        if coordinator is None or provider is None or journal is None:
            raise Refused()
        self._coordinator, self._provider, self._journal = coordinator, provider, journal
        self._admitted: dict[str, Admission] = {}
        self._lock = asyncio.Lock()

    async def dispatch(self, request: dict, *, coordinator_lifetime: str) -> dict:
        async with self._lock:
            return await self._dispatch(request, coordinator_lifetime)

    async def _dispatch(self, request: dict, coordinator: str) -> dict:
        operation = request.get('operation')
        common = {'contract', 'operation', 'role', 'context_digest'}
        fields = {
            'prepare_actual_execution': {'manifest_path', 'held_peer_pid'},
            'stage_fresh_workload': {'execution_id'},
            'arm_delivery_once': {'execution_id'},
            'finish_execution': {'execution_id', 'native_returncode'},
            'reconcile_execution': set(),
        }
        if (operation not in fields or request.get('contract') != CONTRACT
                or request.get('role') != 'issuer'):
            raise Refused()
        allowed = common | fields[operation]
        if operation == 'reconcile_execution' and 'execution_id' in request:
            allowed.add('execution_id')
        if set(request) != allowed:
            raise Refused()
        context = request['context_digest']
        if type(context) is not str or re.fullmatch('[0-9a-f]{64}', context) is None:
            raise Refused()
        if operation == 'prepare_actual_execution':
            if (type(request['held_peer_pid']) is not int or request['held_peer_pid'] <= 0
                    or type(request['manifest_path']) is not str
                    or not request['manifest_path'].startswith('/')):
                raise Refused()
            admission = self._coordinator.admit(context, request['manifest_path'],
                                                 request['held_peer_pid'])
            if (type(admission) is not Admission or admission.context != context
                    or admission.coordinator_lifetime != coordinator):
                raise Refused()
            admission.validate(cleanup=False)
            if self._coordinator.recheck(admission, cleanup=False) is not None:
                raise Refused()
            execution = self._journal.prepare(context, coordinator)
            previous = self._admitted.get(execution)
            if previous is not None and previous != admission:
                raise Refused()  # Exact metadata repeat cannot renew an allocation.
            self._admitted[execution] = admission
            return self._response(context, execution, 'prepared')
        prior = self._journal.find(context, coordinator)
        if prior is None:
            # No durable execution is not a fabricated closed receipt. Registry
            # reconciliation of pre-ID preparation must establish the record.
            raise Uncertain()
        execution, state = prior
        if request.get('execution_id', execution) != execution:
            raise Refused()
        cleanup = operation in {'finish_execution', 'reconcile_execution'}
        if cleanup and state == 'closed':
            # Durable authenticated metadata readback renews no mutation budget.
            return self._response(context, execution, 'closed')
        admission = self._admitted.get(execution)
        if admission is None:
            if not cleanup:
                raise Uncertain()
            admission = self._coordinator.recover(context, coordinator, execution)
            if (type(admission) is not Admission or admission.context != context
                    or admission.coordinator_lifetime != coordinator):
                raise Uncertain()
        admission.validate(cleanup=cleanup)
        if self._coordinator.recheck(admission, cleanup=cleanup) is not None:
            raise Refused()
        deadline = admission.cleanup_deadline if cleanup else admission.access_deadline
        if deadline <= time.monotonic():
            raise Uncertain()
        async with asyncio.timeout(deadline - time.monotonic()):
            if operation == 'stage_fresh_workload':
                self._journal.transition(execution, 'prepared', 'staging')
                try:
                    outcome = await self._provider.stage(admission, execution,
                        lambda step, row: self._journal.event(execution, 'intent', {'step': step, **row}),
                        lambda step, row: self._journal.event(execution, 'outcome', {'step': step, **row}))
                    if outcome is not None:
                        raise Uncertain()
                    self._journal.transition(execution, 'staging', 'staged')
                except BaseException:
                    # Persisted staging is already uncertain; never reset to prepared.
                    raise
                return self._response(context, execution, 'staged')
            if operation == 'arm_delivery_once':
                self._journal.transition(execution, 'staged', 'armed')
                outcome = await self._provider.arm(admission, execution,
                    lambda: self._journal.consume_delivery(execution))
                if outcome is not None:
                    raise Uncertain()
                return self._response(context, execution, 'armed')
            if operation == 'finish_execution':
                if state != 'armed' or type(request['native_returncode']) is not int:
                    raise Refused()
                if self._coordinator.native_closed(admission) is not None:
                    raise Uncertain()
            # Provider must use exact persisted owned-target journal; never trust
            # arbitrary IDs in a cleanup request or repeat prior uncertain create.
            outcome = await self._provider.revoke_and_cleanup(admission, execution,
                self._journal.events(execution), reconcile=operation == 'reconcile_execution')
            if outcome is not None:
                raise Uncertain()
            self._journal.transition(execution, state, 'closed')
            return self._response(context, execution, 'closed')

    @staticmethod
    def _response(context: str, execution: str, status: str) -> dict:
        return {'contract': CONTRACT, 'role': 'issuer', 'context_digest': context,
                'execution_id': execution, 'status': status}
