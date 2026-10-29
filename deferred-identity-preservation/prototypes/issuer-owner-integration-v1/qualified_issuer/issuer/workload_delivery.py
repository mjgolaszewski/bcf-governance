"""Actual persistent unchanged Racecar owner-v2 framed workload protocol, UNRUN.

Listener creation and actual workload admission belong to the independent
registry. A handler cannot grant itself a peer or select candidate targets.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import struct
import time

from .contracts import Refused, Uncertain
from .http_exchange import constant, unique

SCHEMA = 'racecar/native-owner-rpc/v2'
OPERATION_SECONDS = 30


class WorkloadSession:
    def __init__(self, provider, admission, execution: str, consume) -> None:
        self.provider, self.admission, self.execution = provider, admission, execution
        self.consume = consume
        self.accepted = False

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            remaining = self.admission.access_deadline - time.monotonic()
            if remaining <= 0 or self.accepted:
                raise Refused()
            self.accepted = True  # An uncertain first connection is not replaced.
            async with asyncio.timeout(remaining):
                connection = writer.get_extra_info('socket')
                if connection is None or connection.family != socket.AF_UNIX:
                    raise Refused()
                # Registry inspects the actual accepted socket's SO_PEERCRED and
                # registered full kernel lifetime/source context, not this JSON.
                registry = self.provider.deps.delivery_registry
                if registry.authenticate(connection, self.admission) is not None:
                    raise Refused()
                used: set[str] = set()
                nonces: set[str] = set()
                sequence = 0
                while True:
                    # Idle between requests is bounded by original connection
                    # access lifetime. FIRST byte starts one immutable30s window
                    # spanning rest of header/body/op/response/close EOF.
                    first = await reader.readexactly(1)
                    deadline = min(time.monotonic() + OPERATION_SECONDS,
                                   self.admission.access_deadline)
                    if deadline <= time.monotonic():
                        raise Refused()
                    async with asyncio.timeout(deadline - time.monotonic()):
                        size, = struct.unpack('!I', first + await reader.readexactly(3))
                        if not 0 < size <= 1024:
                            raise Refused()
                        request = json.loads(await reader.readexactly(size),
                                             object_pairs_hook=unique, parse_constant=constant)
                        if (type(request) is not dict or set(request) != {'schema', 'op', 'sequence', 'nonce'}
                                or request['schema'] != SCHEMA or type(request['sequence']) is not int
                                or request['sequence'] != sequence + 1 or type(request['nonce']) is not str
                                or re.fullmatch('[0-9a-f]{32}', request['nonce']) is None
                                or request['nonce'] in nonces or request['op'] in used
                                or request['op'] not in {'login_once', 'revoke_owned_sessions', 'close'}):
                            raise Refused()
                        operation = request['op']
                        if operation == 'revoke_owned_sessions' and 'login_once' not in used:
                            raise Refused()
                        if registry.authenticate(connection, self.admission) is not None:
                            raise Refused()
                        sequence += 1
                        used.add(operation)
                        nonces.add(request['nonce'])
                        if operation == 'login_once':
                            value = await self.provider.login_material(self.admission, self.execution, self.consume)
                        elif operation == 'revoke_owned_sessions':
                            await self.provider.revoke_sessions(self.admission, self.execution)
                            value = self.provider._journal.workload_outcome(self.execution, operation)
                        else:
                            # Confirms workload channel action only. Issuer cleanup
                            # remains separately authenticated by lifecycle finish.
                            value = self.provider._journal.workload_outcome(self.execution, operation)
                        raw = json.dumps({**request, 'status': 'ready', 'value': value},
                                         separators=(',', ':'), allow_nan=False).encode()
                        if not 0 < len(raw) <= 65536:
                            raise Uncertain()
                        if registry.authenticate(connection, self.admission) is not None:
                            raise Refused()
                        # Synchronous authentication/serialization cannot be
                        # interrupted by asyncio.timeout until its next await.
                        if time.monotonic() >= deadline:
                            raise Uncertain()
                        # login_material has already fsynced delivery consumption.
                        writer.write(struct.pack('!I', len(raw)) + raw)
                        await writer.drain()
                        if operation == 'close':
                            # Client checks for unexpected pending bytes OR EOF even
                            # after its close response. Hold socket until disconnect.
                            if await reader.read(1):
                                raise Refused()
                            break
        except asyncio.CancelledError:
            raise
        except Exception:
            pass  # No secret/body/exception output, retries or invented success.
        finally:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except Exception:
                pass
