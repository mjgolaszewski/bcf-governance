"""Actual async requests, canonical private Provider validation and JWT semantics."""
from __future__ import annotations

import json
import time

from .contracts import Admission, Mutation, Refused
from .issuer_provider_v4 import IssuerBoundary
from .account_evidence import active_profile

OPERATIONS = {'create': 'admin_create_principal', 'capabilities': 'admin_grant_capability',
              'status': 'admin_update_principal_status',
              'sessions/revoke': 'admin_revoke_principal_sessions'}


class Gateway:
    def __init__(self, boundary: IssuerBoundary, authority, user_http):
        if type(boundary) is not IssuerBoundary:
            raise Refused()
        self.boundary, self.authority, self.user = boundary, authority, user_http

    async def admin(self, admission: Admission, method: str, path: str, body,
                    *, deadline: float):
        self.boundary.check_runtime(self.boundary.pin)
        action, raw, target = self.boundary._admin_route(method, path, body)
        if method == 'GET':
            result = await self.authority.read(admission, path, deadline=deadline)
        else:
            result = await self.authority.mutate(admission,
                Mutation(method, path, raw, OPERATIONS[action]), deadline=deadline)
        if result.status != 200 or type(result.value) is not dict:
            raise Refused()
        return self.boundary._validate_admin_result(action, raw, target, result.value)

    async def user_request(self, admission: Admission, method: str, path: str, body,
                           *, token=None):
        self.boundary.check_runtime(self.boundary.pin)
        action, raw = self.boundary._user_route(method, path, body, token)
        result = await self.user.request(method, path, body=raw, token=token,
                                         deadline=admission.access_deadline)
        if result.status != 200 or type(result.value) is not dict:
            raise Refused()
        return self.boundary._validate_user_result(action, raw, result.value)

    async def account(self, admission: Admission, token: str, audience: str, *,
                      principal_id: str, session_id: str, cleanup: bool):
        admission.validate(cleanup=cleanup)
        self.boundary.check_runtime(self.boundary.pin)
        deadline = admission.cleanup_deadline if cleanup else admission.access_deadline
        if audience not in {'racecar', 'chrysalis-identity'}:
            raise Refused()
        result = await self.user.request('GET', '/api/v1/account/profile?audience=' + audience,
                                         token=token, deadline=deadline)
        if result.status == 200:
            active_profile(result.value, principal_id=principal_id, session_id=session_id,
                subject=self.boundary.subject(principal_id), audience=audience)
        return result
