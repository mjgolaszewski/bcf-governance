"""Serial original-Root dispatch for registry and actual accepted-peer channels.

Dispatch is not provider cleanup. A failed role stays disabled and the original
registry stays in HOLD; surviving cleanup channels can still be serviced.
"""
from __future__ import annotations

import math
import os
import select
import socket
import time

from .evidence_execution_owner import OwnerAdmissionError
from .evidence_invocation_registry import ActualInvocationRegistry
from .evidence_owner_peer_bridge import OwnerPeerBridge
from .evidence_registry_channel import RegistryOwnerChannel


class OriginalRootDispatcher:
    def __init__(self, registry: ActualInvocationRegistry, *,
                 servers: dict[str, RegistryOwnerChannel], peers: OwnerPeerBridge) -> None:
        if (type(registry) is not ActualInvocationRegistry or type(peers) is not OwnerPeerBridge
                or set(servers) != {'issuer', 'custody'}):
            raise OwnerAdmissionError('original registry and both original channel roles are required')
        registry._root(cleanup=True)
        if (peers._plan is not registry._plan or peers._context != registry.admission.context
                or peers._owners != registry._owners or peers._deadline != registry.admission.access_deadline):
            raise OwnerAdmissionError('peer bridge differs from the original registry allocation')
        self._registry = registry
        self._peers = peers
        self._servers = dict(servers)
        self._channels: dict[int, tuple[str, str, socket.socket, tuple[int, int]]] = {}
        for role, server in servers.items():
            if (type(server) is not RegistryOwnerChannel or server._registry is not registry
                    or server._role != role or server._failed):
                raise OwnerAdmissionError('registry channel is not its original installed role')
            self._add('registry', role, server._channel)
            self._add('peer', role, peers._channels[role])

    def _add(self, kind: str, role: str, channel: socket.socket) -> None:
        info = os.fstat(channel.fileno())
        key = (info.st_dev, info.st_ino)
        if channel.fileno() in self._channels or any(row[3] == key for row in self._channels.values()):
            raise OwnerAdmissionError('original dispatch channels are not distinct')
        self._channels[channel.fileno()] = (kind, role, channel, key)

    def poll(self, timeout: float = 0.02) -> None:
        self._registry._root(cleanup=True)  # Also enforces the original serial Root thread.
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= 1:
            raise OwnerAdmissionError('Root polling requires a finite bounded wait')
        remaining = self._registry.admission.cleanup_deadline - time.monotonic()
        if remaining <= 0:
            raise OwnerAdmissionError('original Root cleanup deadline exhausted')
        readable, _, _ = select.select(list(self._channels), [], [], min(timeout, remaining))
        for descriptor in readable:
            kind, role, channel, key = self._channels[descriptor]
            try:
                info = os.fstat(channel.fileno())
                if channel.fileno() != descriptor or (info.st_dev, info.st_ino) != key:
                    raise OwnerAdmissionError('original Root dispatch channel was replaced')
                if kind == 'registry':
                    self._servers[role].handle_once()
                else:
                    if (self._registry.held
                            or time.monotonic() >= self._registry.admission.access_deadline):
                        raise OwnerAdmissionError('workload peer access is held or expired')
                    self._peers.handle_once(role)
            except BaseException:
                self._registry._hold = True
                channel.close()
                del self._channels[descriptor]
                raise
