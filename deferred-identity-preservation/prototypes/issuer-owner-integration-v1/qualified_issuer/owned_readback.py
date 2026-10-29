"""Exact journal-owned principal lookup through the real fixed-origin admin API.

Unqualified integration port until genuine staged-principal acceptance. There
is no write, replay, broad lookup, environment credential discovery or injected
transport. A lost create response still requires a unique exact email/UUID read.
"""
from __future__ import annotations

import json
import math
import re
import ssl
import time
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

import httpx

from .issuer.contracts import Admission, AdminSession, Refused
from .issuer.http_exchange import ORIGIN, constant, safe_header, unique
from .issuer.journal import Journal
from .sandbox_profile import OriginalSandboxProfile


class OriginalOwnedPrincipalReadback:
    def __init__(self, *, profile: OriginalSandboxProfile, session: AdminSession,
                 tls: ssl.SSLContext) -> None:
        if (type(profile) is not OriginalSandboxProfile or type(session) is not AdminSession
                or session.tenant != profile._admission.tenant
                or session.subject != 'principal:c5f54cc0-d300-4e84-95f8-91334c3f32b8'
                or not safe_header(session.token)
                or type(session.expires_at_monotonic) not in (int, float)
                or not math.isfinite(session.expires_at_monotonic)
                or session.expires_at_monotonic <= profile._admission.cleanup_deadline
                or tls.verify_mode != ssl.CERT_REQUIRED or not tls.check_hostname):
            raise Refused()
        self._profile = profile
        self._session = session
        self._journal: Journal | None = None
        self._client = httpx.Client(base_url=ORIGIN, verify=tls, trust_env=False,
            follow_redirects=False, http2=False,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
            headers={'accept': 'application/json', 'accept-encoding': 'identity'}, timeout=10)

    def bind_journal(self, journal: Journal) -> None:
        if self._journal is not None or type(journal) is not Journal:
            raise Refused()
        self._journal = journal

    def _get(self, admission: Admission, path: str) -> Any:
        self._profile._current(admission)
        cleanup = self._profile._runtime._delivery._retired
        deadline = admission.cleanup_deadline if cleanup else admission.access_deadline
        remaining = min(deadline, self._session.expires_at_monotonic) - time.monotonic()
        if remaining <= 0:
            raise Refused()
        headers = {'x-chrysalis-tenant': admission.tenant,
                   'authorization': 'Bearer ' + self._session.token}
        try:
            with self._client.stream('GET', path, headers=headers, timeout=min(10, remaining)) as response:
                if (response.status_code != 200
                        or response.headers.get('content-encoding', 'identity') != 'identity'):
                    raise Refused()
                body = bytearray()
                for chunk in response.iter_raw(chunk_size=4096):
                    if time.monotonic() >= deadline or len(body) + len(chunk) > 65536:
                        raise Refused()
                    body.extend(chunk)
                if time.monotonic() >= deadline:
                    raise Refused()
                value = json.loads(body, object_pairs_hook=unique, parse_constant=constant)
        except (httpx.HTTPError, ValueError):
            raise Refused() from None
        self._profile._current(admission)
        return value

    def __call__(self, admission: Admission, execution: str, email: str, principal: str) -> None:
        self._profile._current(admission)
        if (self._journal is None or type(execution) is not str
                or type(email) is not str or type(principal) is not str
                or re.fullmatch('jit-[0-9a-f]{32}@' + re.escape(self._profile._config.email_domain), email) is None):
            raise Refused()
        try:
            if str(UUID(principal)) != principal:
                raise Refused()
        except ValueError:
            raise Refused() from None
        found = self._journal.find(admission.context, admission.coordinator_lifetime)
        if found is None or found[0] != execution:
            raise Refused()
        self._profile._runtime._coordinator.recover(admission.context, admission.coordinator_lifetime, execution)
        records = self._journal.events(execution)
        creates = [row for row in records if row.get('kind') == 'intent' and row.get('step') == 'create']
        if (len(creates) != 1 or creates[0].get('email') != email
                or creates[0].get('role') != self._profile._config.role
                or not any(row.get('kind') == 'outcome' and row.get('step') == 'lookup'
                    and row.get('email') == email and row.get('outcome') == 'absent_before_create'
                    for row in records)):
            raise Refused()
        outcomes = [row for row in records if row.get('kind') == 'outcome' and row.get('step') == 'create']
        if (len(outcomes) > 1 or outcomes and (outcomes[0].get('principal_id') != principal
                or outcomes[0].get('email') != email or outcomes[0].get('role') != self._profile._config.role)):
            raise Refused()
        rows = self._get(admission, '/api/v1/admin/principals?' + urlencode({'query': email, 'limit': 2}))
        if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                or rows[0].get('id') != principal or rows[0].get('email') != email):
            raise Refused()
        workbench = self._get(admission, '/api/v1/admin/principals/' + principal + '/workbench')
        if (type(workbench) is not dict or type(workbench.get('principal')) is not dict
                or workbench['principal'].get('id') != principal
                or workbench['principal'].get('email') != email
                or workbench['principal'].get('status') not in {'active', 'disabled'}
                or workbench['principal'].get('is_deleted') is not False):
            raise Refused()

    def close(self) -> None:
        self._client.close()
