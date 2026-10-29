"""Private durable non-secret owner ledger; construction writes only when invoked.

UNRUN. SQLite files and their parent require separately admitted owner custody.
The root is operator-created 0700; this module never creates a parent tree.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid
import hashlib
import secrets

from .contracts import Refused, Uncertain

FIELDS = frozenset({'step', 'principal_id', 'factor_id', 'email', 'audience',
                    'operation', 'payload_sha256', 'outcome', 'role', 'action_id'})


class Journal:
    def __init__(self, root: Path, *, cap: int) -> None:
        if (type(cap) is not int or cap < 1 or not root.is_absolute()
                or root.resolve() != root):
            raise Refused()
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.getuid()):
            raise Refused()
        path = root / 'owner.sqlite3'
        if not path.exists():
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid()):
            raise Refused()
        self._db = sqlite3.connect(str(path), isolation_level=None, timeout=1)
        self._db.execute('PRAGMA synchronous=FULL')
        self._db.execute('PRAGMA journal_mode=DELETE')
        self._db.execute('CREATE TABLE IF NOT EXISTS executions '
            '(id TEXT PRIMARY KEY, context TEXT NOT NULL, coordinator TEXT NOT NULL, '
            'state TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0, '
            'UNIQUE(context, coordinator))')
        self._db.execute('CREATE TABLE IF NOT EXISTS events '
            '(seq INTEGER PRIMARY KEY AUTOINCREMENT, execution TEXT NOT NULL, '
            'kind TEXT NOT NULL, metadata TEXT NOT NULL)')
        self._cap = cap

    def close(self) -> None:
        self._db.close()

    def find(self, context: str, coordinator: str) -> tuple[str, str] | None:
        return self._db.execute('SELECT id,state FROM executions WHERE context=? AND coordinator=?',
                                (context, coordinator)).fetchone()

    def prepare(self, context: str, coordinator: str) -> str:
        if (re.fullmatch('[0-9a-f]{64}', context) is None
                or type(coordinator) is not str or not 1 <= len(coordinator) <= 512):
            raise Refused()
        self._db.execute('BEGIN IMMEDIATE')
        try:
            prior = self.find(context, coordinator)
            if prior is not None:
                if prior[1] != 'prepared':
                    raise Refused()
                self._db.execute('COMMIT')
                return prior[0]  # Non-secret exact repeat, no provider replay.
            count = self._db.execute('SELECT count(*) FROM executions').fetchone()[0]
            if count >= self._cap:
                raise Refused()
            execution = str(uuid.uuid4())
            self._db.execute('INSERT INTO executions(id,context,coordinator,state) VALUES(?,?,?,?)',
                             (execution, context, coordinator, 'prepared'))
            self._db.execute('COMMIT')
            return execution
        except BaseException:
            if self._db.in_transaction:
                self._db.execute('ROLLBACK')
            raise

    def transition(self, execution: str, expected: str, target: str) -> None:
        cursor = self._db.execute('UPDATE executions SET state=? WHERE id=? AND state=?',
                                  (target, execution, expected))
        if cursor.rowcount != 1:
            raise Uncertain()

    def event(self, execution: str, kind: str, metadata: dict[str, str]) -> None:
        if (kind not in {'intent', 'outcome', 'cleanup'} or not set(metadata) <= FIELDS
                or not all(type(value) is str and 0 < len(value) <= 512
                           for value in metadata.values())):
            raise Refused()
        raw = json.dumps(metadata, sort_keys=True, separators=(',', ':'), allow_nan=False)
        self._db.execute('INSERT INTO events(execution,kind,metadata) VALUES(?,?,?)',
                         (execution, kind, raw))

    def events(self, execution: str) -> tuple[dict, ...]:
        rows = self._db.execute('SELECT kind,metadata FROM events WHERE execution=? ORDER BY seq',
                                (execution,)).fetchall()
        return tuple({'kind': kind, **json.loads(raw)} for kind, raw in rows)

    def consume_delivery(self, execution: str) -> None:
        row = self._db.execute('UPDATE executions SET delivered=1 '
                              'WHERE id=? AND state=? AND delivered=0', (execution, 'armed'))
        if row.rowcount != 1:
            raise Uncertain()

    def workload_outcome(self, execution: str, operation: str) -> dict[str, str]:
        action = secrets.token_hex(16)
        self.event(execution, 'outcome', {'step': operation, 'action_id': action,
                                         'outcome': 'confirmed'})
        snapshot = json.dumps({'execution_id': execution, 'events': self.events(execution)},
                              sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return {'execution_id': uuid.UUID(execution).hex, 'action_id': action,
                'journal_sha256': hashlib.sha256(snapshot).hexdigest(), 'outcome': 'confirmed'}
