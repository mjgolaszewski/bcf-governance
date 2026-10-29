"""Narrow owned cleanup, including lost create response; no broad or direct DB fallback."""
from __future__ import annotations

from uuid import UUID

from .contracts import Refused, Uncertain
from .gateway import Gateway
from .workload import PrivateState


async def cleanup_owned(provider, admission, execution, journal, *, reconcile: bool) -> None:
    # Independently retire pending/armed workload delivery before target cleanup.
    # Must be idempotent for a never-armed context, without replaying delivery.
    if await provider.deps.delivery_registry.disarm(admission, execution) is not None:
        raise Uncertain()
    creates = [row for row in journal if row.get('kind') == 'intent' and row.get('step') == 'create']
    state = provider._states.get(execution)
    if not creates:
        # No durable creation intent means this implementation never sent a
        # create request. Failed read-only JWKS/client setup owns no account.
        client = provider._clients.pop(execution, None)
        if client is not None:
            await client.close()
        return
    if len(creates) != 1 or creates[0].get('role') != provider.config.role:
        raise Uncertain()
    email = creates[0]['email']
    if state is None:
        if not reconcile:
            raise Uncertain()
        user = provider._user_factory(provider.config.audience)
        provider._clients[execution] = user
        keys = await user.request('GET', '/api/v1/auth/.well-known/jwks.json',
                                  deadline=admission.cleanup_deadline)
        if type(keys.value) is not dict or type(keys.value.get('keys')) is not list:
            raise Uncertain()
        boundary = provider._boundary_factory(keys.value['keys'], provider.authority, user, admission)
        state = PrivateState(admission, Gateway(boundary, provider.authority, user), email, '',
            lambda step, row: provider._journal.event(execution, 'intent', {'step': step, **row}),
            lambda step, row: provider._journal.event(execution, 'outcome', {'step': step, **row}))
        provider._states[execution] = state
    if state.admission != admission or state.email != email:
        raise Uncertain()
    outcomes = [row for row in journal if row.get('kind') == 'outcome'
                and row.get('step') == 'create' and row.get('principal_id')]
    if len(outcomes) > 1:
        raise Uncertain()
    if outcomes:
        principal = outcomes[0]['principal_id']
        if state.principal_id not in (None, principal):
            raise Uncertain()
        state.principal_id = principal
    else:
        # Query exactly one unpredictable owner-generated email. The list route
        # is fuzzy: never treat a prefix/substring or a saturated list as proof.
        empty_before = any(row.get('kind') == 'outcome' and row.get('step') == 'lookup' and row.get('email') == email
                           and row.get('outcome') == 'absent_before_create' for row in journal)
        if not empty_before:
            raise Uncertain()
        path = provider.authority.register_email(email, attest_intent=lambda supplied:
            None if supplied == email else provider._reject())
        result = await provider.authority.read(admission, path, deadline=admission.cleanup_deadline)
        rows = result.value
        if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                or rows[0].get('email') != email):
            # Zero is still UNKNOWN after a lost write; it is not authority to
            # recreate, close custody, or assume no late transaction can commit.
            raise Uncertain()
        state.principal_id = rows[0].get('id')
        provider._attest_owned(state, execution, state.principal_id)
        state.outcome('create', {'principal_id': state.principal_id, 'email': email,
                                 'role': provider.config.role})
    principal = state.principal_id
    provider._attest_owned(state, execution, principal)
    provider.authority.register_principal(principal,
        attest_owned=lambda value: provider._attest_owned(state, execution, value))
    base = '/api/v1/admin/principals/' + principal
    workbench = await state.gateway.admin(admission, 'GET', base + '/workbench', None,
                                          deadline=admission.cleanup_deadline)
    actual = workbench['principal']
    if actual.get('email') != email or actual.get('status') not in {'active', 'disabled'}:
        raise Uncertain()
    if not reconcile and not state.revoked:
        # Normal successful finish must establish a real current-session oracle
        # while ACTIVE; disabling first cannot masquerade as revocation proof.
        await provider.revoke_sessions(admission, execution)
    elif reconcile:
        state.intent('cleanup_revoke', {'principal_id': principal})
        await state.gateway.admin(admission, 'POST', base + '/sessions/revoke',
            {'reason': 'Owned uncertain-execution cleanup'}, deadline=admission.cleanup_deadline)
        state.outcome('cleanup_revoke', {'principal_id': principal, 'outcome': 'accepted'})
    if actual['status'] == 'active':
        state.intent('disable', {'principal_id': principal})
        await state.gateway.admin(admission, 'PATCH', base + '/status',
            {'status': 'disabled', 'reason': 'Owned JIT qualification cleanup'},
            deadline=admission.cleanup_deadline)
        state.outcome('disable', {'principal_id': principal, 'outcome': 'accepted'})
    closed = await state.gateway.admin(admission, 'GET', base + '/workbench', None,
                                       deadline=admission.cleanup_deadline)
    if closed['principal'].get('status') != 'disabled' or closed['principal'].get('email') != email:
        raise Uncertain()
    await state.gateway.user.close()
    state.password, state.seed, state.token = '', None, None
    provider._states.pop(execution, None)
    provider._clients.pop(execution, None)
