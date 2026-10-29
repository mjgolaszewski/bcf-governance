"""Bounded transparent byte relay to one originally selected TCP endpoint.

TLS stays end to end: this component neither decrypts traffic nor substitutes
certificates. Endpoint construction grants no owner or credential authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
import select
import socket
from threading import Event, Lock, Thread
import time

from .evidence_execution_owner import OwnerAdmissionError


@dataclass(frozen=True)
class FixedEndpoint:
    address: str
    port: int

    def validate(self) -> None:
        try:
            address = str(ipaddress.IPv4Address(self.address))
        except (ValueError, TypeError) as error:
            raise OwnerAdmissionError('fixed relay endpoint is invalid') from error
        if (type(self.address) is not str
                or address != self.address
                or type(self.port) is not int or not 1 <= self.port <= 65535):
            raise OwnerAdmissionError('fixed relay endpoint is invalid')


class FixedServiceRelay:
    """Own the original listener and all connections until actual closure."""

    def __init__(self, listener: socket.socket, endpoint: FixedEndpoint, *,
                 access_deadline: float, cleanup_deadline: float,
                 maximum_connections: int = 32, maximum_bytes: int = 16*1024*1024) -> None:
        if type(endpoint) is not FixedEndpoint:
            raise OwnerAdmissionError('original fixed endpoint is required')
        endpoint.validate()
        now = time.monotonic()
        if (any(type(v) not in {int, float} or not math.isfinite(v)
                for v in (access_deadline, cleanup_deadline))
                or not now < access_deadline < cleanup_deadline
                or cleanup_deadline-now > 21600+300
                or type(maximum_connections) is not int or not 1 <= maximum_connections <= 64
                or type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 64*1024*1024
                or type(listener) is not socket.socket
                or listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or listener.getsockname() not in {(a,443) for a in ('127.0.0.2','127.0.0.3','127.0.0.4')}):
            raise OwnerAdmissionError('fixed relay original bounds or listener are invalid')
        self._listener = listener
        self._endpoint = endpoint
        self._access_deadline = access_deadline
        self._cleanup_deadline = cleanup_deadline
        self._maximum_connections = maximum_connections
        self._maximum_bytes = maximum_bytes
        self._stop = Event()
        self._lock = Lock()
        self._connections: set[socket.socket] = set()
        self._workers: list[Thread] = []
        self._accepted = 0
        self._bytes = 0
        self._failed = False
        self._closed = False
        listener.settimeout(.1)
        self._acceptor = Thread(target=self._accept, name='bcf-fixed-listener', daemon=False)
        self._acceptor.start()

    def _fail(self) -> None:
        with self._lock:
            self._failed = True
        self._stop.set()

    def _accept(self) -> None:
        try:
            while not self._stop.is_set() and time.monotonic() < self._access_deadline:
                if self._accepted >= self._maximum_connections:
                    break
                try:
                    connection, _ = self._listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if not self._stop.is_set():
                        self._fail()
                    break
                with self._lock:
                    if self._stop.is_set() or time.monotonic() >= self._access_deadline:
                        connection.close()
                        break
                    self._connections.add(connection)
                    self._accepted += 1
                    worker = Thread(target=self._forward, args=(connection,),
                                    name='bcf-fixed-stream', daemon=False)
                    self._workers.append(worker)
                worker.start()
        finally:
            self._listener.close()

    def _forward(self, incoming: socket.socket) -> None:
        outgoing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self._lock:
                self._connections.add(outgoing)
            remaining = self._access_deadline-time.monotonic()
            if self._stop.is_set() or remaining <= 0:
                return
            outgoing.settimeout(min(5.0, remaining))
            outgoing.connect((self._endpoint.address, self._endpoint.port))
            incoming.settimeout(.2)
            outgoing.settimeout(.2)
            directions = {incoming: outgoing, outgoing: incoming}
            while directions and not self._stop.is_set():
                remaining = self._access_deadline-time.monotonic()
                if remaining <= 0:
                    break
                readable, _, _ = select.select(list(directions), [], [], min(.1, remaining))
                for source in readable:
                    destination = directions[source]
                    raw = source.recv(65536)
                    if not raw:
                        del directions[source]
                        destination.shutdown(socket.SHUT_WR)
                        continue
                    with self._lock:
                        if self._bytes+len(raw) > self._maximum_bytes:
                            raise OwnerAdmissionError('fixed relay byte bound exhausted')
                        self._bytes += len(raw)
                    if self._stop.is_set() or time.monotonic() >= self._access_deadline:
                        break
                    destination.sendall(raw)
        except (OSError, ValueError, OwnerAdmissionError):
            if not self._stop.is_set():
                self._fail()
        finally:
            incoming.close()
            outgoing.close()
            with self._lock:
                self._connections.discard(incoming)
                self._connections.discard(outgoing)

    def close(self) -> None:
        """Return only after every owned thread and network FD has closed."""
        if self._closed:
            return
        self._stop.set()
        self._listener.close()
        with self._lock:
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self._acceptor.join(max(0.0, self._cleanup_deadline-time.monotonic()))
        if self._acceptor.is_alive():
            raise OwnerAdmissionError('fixed relay acceptor cleanup is uncertain')
        for worker in self._workers:
            worker.join(max(0.0, self._cleanup_deadline-time.monotonic()))
            if worker.is_alive():
                raise OwnerAdmissionError('fixed relay stream cleanup is uncertain')
        with self._lock:
            if self._connections or self._listener.fileno() != -1:
                raise OwnerAdmissionError('fixed relay descriptor cleanup is uncertain')
            self._closed = True

    def result(self) -> tuple[int, int, bool]:
        if not self._closed:
            raise OwnerAdmissionError('fixed relay has not closed')
        return self._accepted, self._bytes, self._failed
