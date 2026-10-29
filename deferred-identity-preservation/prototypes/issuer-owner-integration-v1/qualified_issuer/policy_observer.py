"""Real canonical-policy observations; no approval bypass or secret-body probes.

Unqualified until finite live read-only probe acceptance. Each public marker is
journaled before dispatch, checked through the daemon, retired by exact bytes,
and independently observed absent before an observation can grant anything.
"""
from __future__ import annotations

import asyncio
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tarfile
import time
from threading import Lock
from typing import Any
from urllib.parse import quote

from .issuer.contracts import Admission, AdminSession, Mutation, Refused
from .issuer.normal_policy import PolicyObservation, PolicyPin
from .sandbox_profile import OriginalSandboxProfile

_SOURCE = '/app/src/chrysalis_identity/api/admin_context_policy.py'
_SOURCE_SHA = '7c929bb4cb02e314c9a2f4bfb0915772b15ac2dcc94280376abb7ec61e7fbb6f'
_PROBE = '''import sys,json,hashlib,os
sys.path.insert(0,'/app/src')
from chrysalis_identity.api import admin_context_policy as p
from chrysalis_identity.settings import get_settings
from chrysalis_identity import config_catalog as c
s=get_settings()
v={'operation':sys.argv[1],'approval':p._approval_required(s,operation_name=sys.argv[1]),'strong':s.admin_require_strong_auth_for_admin_access,'step_up':s.admin_require_step_up_for_dangerous_mutations,'source_origin':p.__file__,'source_sha256':hashlib.sha256(open(p.__file__,'rb').read()).hexdigest(),'config_sha256':c.catalog_file_fingerprint(c.configured_catalog_path()),'profile':c.configured_catalog_profile(),'marker':sys.argv[2]}
f=os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(f,'w') as out:json.dump(v,out,allow_nan=False);out.flush();os.fsync(out.fileno())
'''
_RETIRE = '''import sys,os,stat,hashlib
p=sys.argv[1];f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
s=os.fstat(f)
assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==os.getuid() and s.st_size<=4096
v=os.read(f,4097);assert hashlib.sha256(v).hexdigest()==sys.argv[2]
t=os.lstat(p);assert (s.st_dev,s.st_ino)==(t.st_dev,t.st_ino)
os.unlink(p);os.close(f)
'''


class OriginalPolicyObserver:
    def __init__(self, *, profile: OriginalSandboxProfile, root: Path, session: AdminSession | None = None) -> None:
        if (type(profile) is not OriginalSandboxProfile or session is not None and (type(session) is not AdminSession or session.tenant != profile._admission.tenant)
                 or root.resolve() != root
                or not root.is_absolute()):
            raise Refused()
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise Refused()
        self._profile, self._session = profile, session
        self._native = profile._runtime._native
        self._app = profile._runtime._handoff['services']['app']
        self.pin = PolicyPin(self._app['id'], self._app['started_at'],
            profile._runtime._handoff['configuration_sha256'], 'openbao-kms', _SOURCE, _SOURCE_SHA)
        self._journal = os.open(root / 'policy.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self._lock = Lock()
        self._counter = 0
        self._pending: set[str] = set()
        self._failed = False

    def _record(self, value: dict[str, Any]) -> None:
        raw = json.dumps(value, sort_keys=True, allow_nan=False).encode() + b'\n'
        if len(raw) > 8192 or os.write(self._journal, raw) != len(raw):
            raise Refused()
        os.fsync(self._journal)

    @staticmethod
    def _route(mutation: Mutation) -> None:
        if type(mutation) is not Mutation:
            raise Refused()
        if mutation.operation == 'admin_create_principal':
            if (mutation.method, mutation.path) == ('POST', '/api/v1/admin/principals'):
                return
        else:
            routes = {'admin_grant_capability': ('POST', 'capabilities'),
                'admin_update_principal_status': ('PATCH', 'status'),
                'admin_revoke_principal_sessions': ('POST', 'sessions/revoke')}
            expected = routes.get(mutation.operation)
            match = re.fullmatch('/api/v1/admin/principals/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/(capabilities|status|sessions/revoke)', mutation.path)
            if expected is not None and match is not None and (mutation.method, match[2]) == expected:
                return
        raise Refused()

    def _archive(self, marker: str, *, absent: bool = False) -> bytes:
        connection = http.client.HTTPConnection('localhost', timeout=min(10, self._native.remaining()))
        connection.sock = self._native.connect()
        try:
            connection.request('GET', '/v1.45/containers/' + self._app['id'] + '/archive?path=' + quote(marker, safe=''))
            response = connection.getresponse()
            raw = response.read(65537)
            if len(raw) > 65536 or response.status != (404 if absent else 200):
                raise Refused()
            return raw
        finally:
            connection.close()

    def _probe(self, mutation: Mutation, deadline: float) -> PolicyObservation:
        if not self._lock.acquire(blocking=False):
            raise Refused()
        try:
            return self._probe_locked(mutation, deadline)
        finally:
            self._lock.release()

    def _probe_locked(self, mutation: Mutation, deadline: float) -> PolicyObservation:
        if self._failed or self._pending or self._counter >= 64 or time.monotonic() >= deadline:
            raise Refused()
        self._counter += 1
        marker = '/tmp/bcf239-policy-' + secrets.token_hex(16) + '.json'
        self._pending.add(marker)
        self._record({'stage': 'policy_probe_intent', 'marker': marker, 'operation': mutation.operation,
            'context': self._profile._admission.context, 'original_deadline': deadline})
        try:
            result = self._native.run(self._app['id'],
                ('/usr/local/bin/python', '-I', '-B', '-c', _PROBE, mutation.operation, marker), observe=self._record)
            if result.returncode != 0 or result.stderr:
                raise Refused()
            with tarfile.open(fileobj=io.BytesIO(self._archive(marker)), mode='r:') as archive:
                members = archive.getmembers()
                if len(members) != 1:
                    raise Refused()
                item = members[0]
                if not item.isfile() or item.name != Path(marker).name or item.size > 4096 or item.mode != 0o600:
                    raise Refused()
                stream = archive.extractfile(item)
                if stream is None:
                    raise Refused()
                raw = stream.read(4097)
            value = json.loads(raw)
            if (type(value) is not dict or value.get('marker') != marker
                    or value.get('operation') != mutation.operation or value.get('source_origin') != _SOURCE
                    or value.get('source_sha256') != _SOURCE_SHA or value.get('config_sha256') != self.pin.configuration_sha256
                    or value.get('profile') != self.pin.profile
                    or any(type(value.get(name)) is not bool for name in ('approval', 'strong', 'step_up'))):
                raise Refused()
            retired = self._native.run(self._app['id'],
                ('/usr/local/bin/python', '-I', '-B', '-c', _RETIRE, marker, hashlib.sha256(raw).hexdigest()), observe=self._record)
            if retired.returncode != 0 or retired.stderr:
                raise Refused()
            self._archive(marker, absent=True)
            self._record({'stage': 'policy_probe_retired', 'marker': marker, 'actual_daemon_absence': True})
            self._pending.remove(marker)
            if time.monotonic() >= deadline:
                raise Refused()
            return PolicyObservation(self.pin, mutation.operation, mutation.method, mutation.path,
                value['approval'], value['strong'], value['step_up'], time.monotonic())
        except BaseException:
            self._failed = True
            raise

    async def observe(self, admission: Admission, mutation: Mutation, deadline: float) -> PolicyObservation:
        self._route(mutation)
        self._profile._current(admission)
        if self._profile._runtime._delivery._retired and mutation.operation not in {
                'admin_update_principal_status', 'admin_revoke_principal_sessions'}:
            raise Refused()
        result = await asyncio.to_thread(self._probe, mutation, deadline)
        self._profile._current(admission)
        return result

    def attest(self, admission: Admission, mutation: Mutation, session: AdminSession,
               observation: PolicyObservation, pin: PolicyPin) -> None:
        self._route(mutation)
        if (self._session is None or session is not self._session or type(observation) is not PolicyObservation
                or pin != self.pin or observation.pin != self.pin
                or (observation.operation, observation.method, observation.path)
                != (mutation.operation, mutation.method, mutation.path)
                or self._pending or self._failed):
            raise Refused()
        self._profile._current(admission)

    def close(self) -> None:
        if not self._lock.acquire(blocking=False):
            raise Refused()
        try:
            if self._pending:
                raise Refused()
            os.close(self._journal)
        finally:
            self._lock.release()
