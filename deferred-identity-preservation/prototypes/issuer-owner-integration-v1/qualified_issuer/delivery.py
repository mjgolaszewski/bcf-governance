"""One original pending listener, closed by the issuer's cleanup lifecycle."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import os
from pathlib import Path
import socket
import stat
import sys
import time
from typing import Any

from .coordinator import OriginalCoordinator
from .issuer.contracts import Admission, Refused, Uncertain
from .runtime.evidence_owner_peer_bridge import OwnerPeerClient

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class OriginalDeliveryRegistry:
    def __init__(self, *, listener: socket.socket, endpoint: Path,
                 pending_identity: tuple[int, int, int],
                 coordinator: OriginalCoordinator, peers: OwnerPeerClient) -> None:
        if (type(coordinator) is not OriginalCoordinator or type(peers) is not OwnerPeerClient
                or listener.family != socket.AF_UNIX
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or not endpoint.is_absolute() or endpoint.resolve() != endpoint
                or listener.getsockname() != str(endpoint)):
            raise Refused()
        info = endpoint.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino, info.st_uid) != pending_identity
                or info.st_uid != os.getuid()):
            raise Refused()
        self._listener = listener
        self._endpoint = endpoint
        self._pending = pending_identity
        self._coordinator = coordinator
        self._peers = peers
        self._admission: Admission | None = None
        self._execution: str | None = None
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._armed = False
        self._retired = False
        self._accepted = False
        self._connection: tuple[int, int] | None = None

    async def arm(self, admission: Admission, execution: str, handler: Handler) -> None:
        if self._armed or self._retired or type(execution) is not str or not execution or not callable(handler):
            raise Refused()
        if self._coordinator.recover(admission.context, admission.coordinator_lifetime, execution) != admission:
            raise Refused()
        self._coordinator.recheck(admission, cleanup=False)
        info = self._endpoint.lstat()
        if ((info.st_dev, info.st_ino, info.st_uid) != self._pending
                or not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600):
            raise Refused()
        self._armed = True  # An uncertain bind is never retried.
        self._admission, self._execution = admission, execution

        async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if task is None:
                writer.close()
                return
            self._tasks.add(task)
            self._writers.add(writer)
            try:
                if self._retired or self._accepted:
                    raise Refused()
                self._accepted = True
                self.authenticate(writer.get_extra_info('socket'), admission)
                async with asyncio.timeout_at(asyncio.get_running_loop().time()
                        + admission.access_deadline - time.monotonic()):
                    await handler(reader, writer)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # No provider material or exception text leaves this boundary.
            finally:
                writer.close()
                self._writers.discard(writer)
                self._tasks.discard(task)

        # Python 3.13+ otherwise unlinks even an externally supplied socket.
        # The original Root retains custody of this pending filesystem inode.
        options: dict[str, Any] = {}
        if sys.version_info >= (3, 13):
            options['cleanup_socket'] = False
        self._server = await asyncio.start_unix_server(serve, sock=self._listener, limit=1028, **options)
        self._coordinator.recheck(admission, cleanup=False)

    def authenticate(self, connection: Any, admission: Admission) -> None:
        if (not self._armed or self._retired or admission != self._admission
                or connection is None or connection.family != socket.AF_UNIX):
            raise Refused()
        self._coordinator.recheck(admission, cleanup=False)
        # asyncio TransportSocket exposes fileno but cannot itself send SCM_RIGHTS.
        # Own the duplicate only for the duration of actual Root peer inspection.
        with socket.socket(fileno=os.dup(connection.fileno())) as accepted:
            info = os.fstat(accepted.fileno())
            key = (info.st_dev, info.st_ino)
            if self._connection is not None and self._connection != key:
                raise Refused()
            self._peers.authenticate(accepted)
            self._connection = key
        self._coordinator.recheck(admission, cleanup=False)

    async def disarm(self, admission: Admission, execution: str) -> None:
        if type(admission) is not Admission or type(execution) is not str or not execution:
            raise Refused()
        if self._admission is not None and (admission != self._admission or execution != self._execution):
            raise Refused()
        self._retired = True  # No subsequent await can reopen secret delivery.
        if self._server is not None:
            self._server.close()
        else:
            self._listener.close()
        for writer in tuple(self._writers):
            writer.close()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        # Local delivery stops even if the cleanup registry lookup is uncertain.
        self._coordinator.recheck(admission, cleanup=True)
        self._coordinator.native_closed(admission)
        if self._coordinator.recover(admission.context, admission.coordinator_lifetime, execution) != admission:
            raise Refused()
        remaining = min(5.0, admission.cleanup_deadline - time.monotonic())
        if remaining <= 0:
            raise Uncertain()
        try:
            async with asyncio.timeout(remaining):
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                if self._server is not None:
                    await self._server.wait_closed()
        except TimeoutError:
            raise Uncertain() from None
        self._coordinator.recheck(admission, cleanup=True)
        # Root owns the pending path; no unlink or replacement is permitted here.
