"""Elapsed body deadlines below stdlib HTTP chunk framing.

Only the qualified stdlib HTTPResponse/BufferedReader/SocketIO chain and finite
in-memory BytesIO responses are accepted. Header setup is a separate bound.
"""
from __future__ import annotations

from contextlib import contextmanager
from http.client import HTTPResponse
from io import BufferedReader, BytesIO
import math
import socket
import ssl
import time


class ProviderResponseError(OSError):
    """A response transport cannot establish its required elapsed bound."""


def validate_provider_timeout(timeout):
    """Reject unusable elapsed budgets before the caller allocates a request."""
    try:
        valid = (not isinstance(timeout, bool) and isinstance(timeout, (float, int))
                 and math.isfinite(timeout) and timeout > 0)
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("provider response deadline requires a finite positive timeout")


class _DeadlineReader:
    def __init__(self, stream, transport, deadline, inactivity_timeout):
        self.stream = stream
        self.transport = transport
        self.deadline = deadline
        self.inactivity_timeout = inactivity_timeout

    def read1(self, size=-1):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("provider response body deadline expired")
        if size == 0:
            return b""
        if self.transport is not None:
            self.transport.settimeout(min(remaining, self.inactivity_timeout)
                                      if self.inactivity_timeout is not None else remaining)
        amount = 65536 if size < 0 else min(size, 65536)
        value = (BytesIO.read1(self.stream, amount) if self.transport is None
                 else self.stream.read1(amount))
        if time.monotonic() >= self.deadline:
            raise TimeoutError("provider response body deadline expired")
        return value

    def read(self, size=-1):
        values = []
        remaining = size
        while remaining != 0:
            value = self.read1(remaining)
            if not value:
                break
            values.append(value)
            if remaining > 0:
                remaining -= len(value)
        return b"".join(values)

    def readline(self, size=-1):
        value = bytearray()
        while size < 0 or len(value) < size:
            byte = self.read1(1)
            if not byte:
                break
            value.extend(byte)
            if byte == b"\n":
                break
        return bytes(value)

    def readinto(self, buffer):
        value = self.read(len(buffer))
        buffer[:len(value)] = value
        return len(value)

    def close(self):
        self.stream.close()


@contextmanager
def provider_response_deadline(response, *, timeout):
    """Bound body and chunk framing; never retry or authorize the operation.

    The caller owns the response context, byte limit, decoding and validation.
    One absolute deadline survives every read in this context. The original
    socket inactivity timeout is also retained as an upper bound per read.
    Unsupported adapters fail closed rather than claiming an elapsed bound.
    """
    validate_provider_timeout(timeout)
    if isinstance(response, BytesIO):
        yield _DeadlineReader(response, None, time.monotonic() + timeout, None)
        return
    if type(response) is not HTTPResponse:
        raise ProviderResponseError("provider response transport is not qualified for body deadlines")
    stream = response.fp
    raw = getattr(stream, "raw", None)
    transport = getattr(raw, "_sock", None)
    if (type(stream) is not BufferedReader or type(raw) is not socket.SocketIO
            or type(transport) not in {socket.socket, ssl.SSLSocket}):
        raise ProviderResponseError("provider response stream is not qualified for body deadlines")
    previous_timeout = transport.gettimeout()
    # The body budget is absolute, not reset at each application read. A shorter
    # existing socket timeout must remain in force without shortening that budget.
    reader = _DeadlineReader(stream, transport, time.monotonic() + timeout, previous_timeout)
    response.fp = reader
    try:
        yield response
    finally:
        if response.fp is reader:
            response.fp = stream
        if transport.fileno() >= 0:
            transport.settimeout(previous_timeout)
