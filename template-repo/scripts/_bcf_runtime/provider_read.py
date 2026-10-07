"""Bounded retry for immutable provider GET operations only."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import Message
import hashlib
import time
from typing import Any, Callable, ContextManager
from urllib.error import HTTPError, URLError
from urllib.request import Request

from .ci_recovery_frontier import provider_read_frontier


RETRYABLE_HTTP = frozenset({429, 500, 502, 503, 504})
BACKOFF_SECONDS = (1.0, 2.0)
MAX_RETRY_AFTER_SECONDS = 30.0


class ProviderReadError(ValueError):
    """An immutable provider read exhausted or violated its closed contract."""


@dataclass(frozen=True)
class ProviderReadAttempt:
    ordinal: int
    outcome: str
    request_sha256: str
    delay_seconds: float | None = None


def _retry_after(headers: Message | None, fallback: float) -> float:
    value = headers.get("Retry-After") if headers is not None else None
    if value is None:
        return fallback
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ProviderReadError("provider Retry-After is invalid") from exc
    if seconds < 0 or seconds > MAX_RETRY_AFTER_SECONDS:
        raise ProviderReadError("provider Retry-After is outside the bounded policy")
    return seconds


def _transient_url_error(exc: URLError) -> bool:
    reason = exc.reason
    return isinstance(reason, (TimeoutError, ConnectionResetError)) or any(
        marker in str(reason).lower()
        for marker in ("timed out", "connection reset")
    )


def open_provider_get(
    request: Request,
    *,
    timeout: int,
    opener: Callable[..., ContextManager[Any]],
    sleeper: Callable[[float], None] = time.sleep,
    observations: list[ProviderReadAttempt] | None = None,
) -> ContextManager[Any]:
    """Open one exact GET with a closed transient retry taxonomy.

    Callers still own response size, schema, digest, and identity validation.
    The request object is never rewritten between attempts.
    """

    if request.get_method() != "GET":
        raise ProviderReadError("provider retry transport accepts GET only")
    request_sha256 = hashlib.sha256(
        f"GET\0{request.full_url}".encode()
    ).hexdigest()
    attempts = len(BACKOFF_SECONDS) + 1

    def action(outcome: str) -> str:
        return str(
            provider_read_frontier(
                request_sha256=request_sha256, outcome=outcome
            )["action"]["kind"]
        )

    for index in range(attempts):
        ordinal = index + 1
        try:
            response = opener(request, timeout=timeout)
        except HTTPError as exc:
            if exc.code not in RETRYABLE_HTTP:
                if action("terminal") != "stop":
                    raise AssertionError("terminal provider read selected continuation")
                if observations is not None:
                    observations.append(ProviderReadAttempt(ordinal, f"http_{exc.code}", request_sha256))
                raise
            if index == attempts - 1:
                if action("exhausted") != "stop":
                    raise AssertionError("exhausted provider read selected continuation")
                if observations is not None:
                    observations.append(ProviderReadAttempt(ordinal, "exhausted", request_sha256))
                raise ProviderReadError("provider GET transient retry exhausted") from exc
            delay = _retry_after(exc.headers, BACKOFF_SECONDS[index])
            if action("transient") != "retry_identical_read":
                raise AssertionError("transient provider read did not select exact retry")
            if observations is not None:
                observations.append(ProviderReadAttempt(ordinal, f"http_{exc.code}", request_sha256, delay))
            sleeper(delay)
        except URLError as exc:
            if not _transient_url_error(exc):
                if action("terminal") != "stop":
                    raise AssertionError("terminal provider transport selected continuation")
                if observations is not None:
                    observations.append(ProviderReadAttempt(ordinal, "terminal_transport", request_sha256))
                raise
            if index == attempts - 1:
                if action("exhausted") != "stop":
                    raise AssertionError("exhausted provider transport selected continuation")
                if observations is not None:
                    observations.append(ProviderReadAttempt(ordinal, "exhausted", request_sha256))
                raise ProviderReadError("provider GET transient retry exhausted") from exc
            delay = BACKOFF_SECONDS[index]
            if action("transient") != "retry_identical_read":
                raise AssertionError("transient provider transport did not select exact retry")
            if observations is not None:
                observations.append(ProviderReadAttempt(ordinal, "transient_transport", request_sha256, delay))
            sleeper(delay)
        else:
            if action("success") != "consume_exact_read":
                raise AssertionError("successful provider read did not select consumption")
            if observations is not None:
                observations.append(ProviderReadAttempt(ordinal, "success", request_sha256))
            return response
    raise AssertionError("bounded provider GET loop did not terminate")
