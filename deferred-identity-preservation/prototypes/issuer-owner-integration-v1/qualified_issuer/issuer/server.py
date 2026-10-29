"""Concrete closed framed owner control server; start is a separate live effect.

Maintained BCF ProcessIdentity.observe is injected from the installed/pinned
runtime. Its return value is checked by the independent coordinator registry.
No PID or owner identity from request JSON is used for control authentication.
"""
from __future__ import annotations

import asyncio
import json
import math
import time
import os
import socket
import stat
import struct
from pathlib import Path

from .contracts import Refused
from .http_exchange import constant, unique
from .lifecycle import IssuerLifecycle


class ControlServer:
    def __init__(self, lifecycle: IssuerLifecycle, *, observe_identity,
                 authenticate_control, control_deadline) -> None:
        if not all(callable(value) for value in (observe_identity, authenticate_control, control_deadline)):
            raise Refused()
        self._lifecycle = lifecycle
        self._observe, self._authenticate = observe_identity, authenticate_control
        self._deadline = control_deadline

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        start = time.monotonic()
        try:
            async with asyncio.timeout(30) as window:
                connection = writer.get_extra_info('socket')
                if connection is None or connection.family != socket.AF_UNIX:
                    raise Refused()
                pid, uid, _gid = struct.unpack('3i', connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                identity = self._observe(pid)
                if identity.pid != pid or identity.uid != uid:
                    raise Refused()
                coordinator = self._authenticate(identity)
                if type(coordinator) is not str or not coordinator:
                    raise Refused()
                aggregate = self._deadline(identity, None, None)
                if (type(aggregate) not in (int, float) or not math.isfinite(aggregate)
                        or min(start + 30, aggregate) <= time.monotonic()):
                    raise Refused()
                window.reschedule(asyncio.get_running_loop().time()
                                  + min(start + 30, aggregate) - time.monotonic())
                size, = struct.unpack('!I', await reader.readexactly(4))
                if not 0 < size <= 1024:
                    raise Refused()
                request = json.loads(await reader.readexactly(size),
                                     object_pairs_hook=unique, parse_constant=constant)
                if type(request) is not dict or self._observe(pid) != identity:
                    raise Refused()
                operation = request.get('operation')
                cap = 60 if operation in {'stage_fresh_workload', 'arm_delivery_once', 'finish_execution'} else 30
                authoritative = self._deadline(identity, request.get('context_digest'), operation)
                if type(authoritative) not in (int, float) or not math.isfinite(authoritative):
                    raise Refused()
                final_deadline = min(start + cap, aggregate, authoritative)
                if final_deadline <= time.monotonic():
                    raise Refused()
                # Fixed from original request start across header/body/response;
                # readiness cannot renew the registered absolute allocation.
                window.reschedule(asyncio.get_running_loop().time()
                                  + final_deadline - time.monotonic())
                response = await self._lifecycle.dispatch(request, coordinator_lifetime=coordinator)
                if self._observe(pid) != identity or time.monotonic() >= final_deadline:
                    raise Refused()
                raw = json.dumps(response, separators=(',', ':'), allow_nan=False).encode()
                if not 0 < len(raw) <= 65536:
                    raise Refused()
                if time.monotonic() >= final_deadline:
                    raise Refused()
                writer.write(struct.pack('!I', len(raw)) + raw)
                await writer.drain()
        except asyncio.CancelledError:
            raise
        except Exception:
            # A dropped/partial response is uncertain for the caller. Never send
            # fabricated prepared/staged/closed, exception text or secret data.
            pass
        finally:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except Exception:
                pass

    async def start(self, listener: socket.socket, endpoint: Path) -> asyncio.AbstractServer:
        info = endpoint.lstat()
        if (not endpoint.is_absolute() or endpoint.resolve() != endpoint
                or not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or listener.family != socket.AF_UNIX
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or listener.getsockname() != str(endpoint)):
            raise Refused()
        return await asyncio.start_unix_server(self.handle, sock=listener, limit=1028)
