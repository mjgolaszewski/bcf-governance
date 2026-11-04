from __future__ import annotations

from email.message import Message
from io import BytesIO
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from bcf_governance.tooling.provider_read import (
    ProviderReadAttempt,
    ProviderReadError,
    open_provider_get,
)


class _Response(BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@pytest.mark.parametrize("timeout", [True, False, 0, -1, float("nan"), float("inf"), "30", None])
def test_invalid_provider_get_timeout_precedes_opener_allocation(timeout):
    def opener(*_args, **_kwargs):
        pytest.fail("invalid timeout allocated a provider request")

    with pytest.raises(ProviderReadError, match="timeout"):
        open_provider_get(Request("https://api.github.test/value"), timeout=timeout, opener=opener)


def _http(code: int, retry_after: str | None = None) -> HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return HTTPError("https://api.github.test/value", code, "failed", headers, None)


@pytest.mark.parametrize("code", [500, 503])
def test_provider_get_retries_transient_without_rewriting_identity(code: int) -> None:
    request = Request("https://api.github.test/value", method="GET")
    seen: list[Request] = []
    delays: list[float] = []
    observations: list[ProviderReadAttempt] = []

    def opener(value: Request, *, timeout: int) -> _Response:
        assert timeout == 30
        seen.append(value)
        if len(seen) == 1:
            raise _http(code, "0")
        return _Response(b"exact")

    with open_provider_get(
        request,
        timeout=30,
        opener=opener,
        sleeper=delays.append,
        observations=observations,
    ) as response:
        assert response.read() == b"exact"
    assert seen == [request, request]
    assert delays == [0.0]
    assert observations == [
        ProviderReadAttempt(1, f"http_{code}", observations[0].request_sha256, 0.0),
        ProviderReadAttempt(2, "success", observations[0].request_sha256),
    ]
    assert len(observations[0].request_sha256) == 64


@pytest.mark.parametrize("code", [401, 403, 404])
def test_provider_get_never_retries_authority_or_absence(code: int) -> None:
    attempts = 0

    def opener(_request: Request, *, timeout: int) -> _Response:
        nonlocal attempts
        attempts += 1
        raise _http(code)

    with pytest.raises(HTTPError):
        open_provider_get(
            Request("https://api.github.test/value", method="GET"),
            timeout=30,
            opener=opener,
            sleeper=lambda _delay: pytest.fail("terminal response slept"),
        )
    assert attempts == 1


def test_provider_get_exhaustion_and_invalid_retry_after_fail_closed() -> None:
    attempts = 0

    def unavailable(_request: Request, *, timeout: int) -> _Response:
        nonlocal attempts
        attempts += 1
        raise URLError(TimeoutError("timed out"))

    with pytest.raises(ProviderReadError, match="exhausted"):
        open_provider_get(
            Request("https://api.github.test/value", method="GET"),
            timeout=30,
            opener=unavailable,
            sleeper=lambda _delay: None,
        )
    assert attempts == 3
    with pytest.raises(ProviderReadError, match="Retry-After"):
        open_provider_get(
            Request("https://api.github.test/value", method="GET"),
            timeout=30,
            opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(_http(503, "31")),
            sleeper=lambda _delay: None,
        )


def test_provider_get_retries_exact_read_after_tls_eof() -> None:
    request = Request("https://api.github.test/value", method="GET")
    seen: list[Request] = []
    delays: list[float] = []

    def opener(value: Request, *, timeout: int) -> _Response:
        assert timeout == 30
        seen.append(value)
        if len(seen) == 1:
            raise URLError(ssl.SSLEOFError(8, "EOF occurred in violation of protocol"))
        return _Response(b"exact")

    with open_provider_get(
        request,
        timeout=30,
        opener=opener,
        sleeper=delays.append,
    ) as response:
        assert response.read() == b"exact"
    assert seen == [request, request]
    assert delays == [1.0]


def test_provider_retry_rejects_mutation_method() -> None:
    with pytest.raises(ProviderReadError, match="GET only"):
        open_provider_get(
            Request("https://api.github.test/value", method="POST", data=b"{}"),
            timeout=30,
            opener=lambda *_args, **_kwargs: pytest.fail("mutation reached transport"),
        )


@pytest.mark.parametrize('value', ['NaN', 'nan', '+nan', '-nan', 'inf', '-inf', 'Infinity', '31', '-1', 'invalid'])
def test_provider_retry_rejects_invalid_delay_before_sleep_or_repeat(value: str) -> None:
    request = Request('https://api.github.test/value', method='GET')
    seen: list[Request] = []
    delays: list[float] = []

    def opener(current: Request, *, timeout: int) -> _Response:
        seen.append(current)
        if len(seen) == 1:
            raise _http(503, value)
        return _Response(b'exact')

    with pytest.raises(ProviderReadError, match='Retry-After'):
        open_provider_get(request, timeout=30, opener=opener, sleeper=delays.append)
    assert seen == [request]
    assert delays == []


@pytest.mark.parametrize('value', ['0', '0.5', '30'])
def test_provider_retry_preserves_finite_inclusive_delay_bounds(value: str) -> None:
    request = Request('https://api.github.test/value', method='GET')
    seen: list[Request] = []
    delays: list[float] = []
    observations: list[ProviderReadAttempt] = []

    def opener(current: Request, *, timeout: int) -> _Response:
        seen.append(current)
        if len(seen) == 1:
            raise _http(429, value)
        return _Response(b'exact')

    with open_provider_get(request, timeout=30, opener=opener, sleeper=delays.append, observations=observations) as response:
        assert response.read() == b'exact'
    assert seen == [request, request]
    assert delays == [float(value)]
    assert [row.ordinal for row in observations] == [1, 2]
    assert observations[0].request_sha256 == observations[1].request_sha256


class _OwnedErrorBody(BytesIO):
    def __init__(self, events, *, fail_close=False):
        super().__init__(b"provider failure")
        self.events = events
        self.fail_close = fail_close

    def close(self):
        self.events.append("close")
        if self.fail_close:
            raise OSError("owned response close failed")
        super().close()


def _owned_http(code, body, retry_after=None):
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return HTTPError("https://api.github.test/value", code, "failed", headers, body)


@pytest.mark.parametrize("code", [429, 503])
def test_provider_error_body_closes_before_retry_sleep_and_dispatch(code):
    events = []
    body = _OwnedErrorBody(events)
    failure = _owned_http(code, body, "0")
    attempts = []

    def opener(request, *, timeout):
        attempts.append(request)
        events.append("dispatch")
        if len(attempts) == 1:
            raise failure
        assert body.closed
        return _Response(b"exact")

    def sleeper(delay):
        assert body.closed
        events.append("sleep")

    with open_provider_get(Request("https://api.github.test/value"), timeout=30,
                           opener=opener, sleeper=sleeper) as response:
        assert response.read() == b"exact"
    assert events == ["dispatch", "close", "sleep", "dispatch"]
    assert attempts[0] is attempts[1]


@pytest.mark.parametrize("code", [401, 404])
def test_provider_terminal_error_body_closed_with_original_status_and_headers(code):
    events = []
    body = _OwnedErrorBody(events)
    failure = _owned_http(code, body)
    with pytest.raises(HTTPError) as raised:
        open_provider_get(Request("https://api.github.test/value"), timeout=30,
                          opener=lambda *a, **k: (_ for _ in ()).throw(failure),
                          sleeper=lambda delay: pytest.fail("terminal response slept"))
    assert raised.value is failure
    assert failure.code == code
    assert body.closed and events == ["close"]


def test_provider_invalid_retry_after_closes_body_without_continuation():
    events = []
    body = _OwnedErrorBody(events)
    failure = _owned_http(503, body, "invalid")
    with pytest.raises(ProviderReadError, match="Retry-After"):
        open_provider_get(Request("https://api.github.test/value"), timeout=30,
                          opener=lambda *a, **k: (_ for _ in ()).throw(failure),
                          sleeper=lambda delay: pytest.fail("invalid delay slept"))
    assert body.closed and events == ["close"]


def test_provider_exhausted_errors_close_each_body_before_terminal():
    events = []
    bodies = []
    failures = []

    def opener(*args, **kwargs):
        assert all(body.closed for body in bodies)
        body = _OwnedErrorBody(events)
        failure = _owned_http(503, body, "0")
        bodies.append(body)
        failures.append(failure)
        raise failure

    with pytest.raises(ProviderReadError, match="exhausted") as raised:
        open_provider_get(Request("https://api.github.test/value"), timeout=30,
                          opener=opener, sleeper=lambda delay: None)
    assert len(bodies) == 3 and all(body.closed for body in bodies)
    assert raised.value.__cause__ is failures[-1]
    assert events == ["close", "close", "close"]


def test_provider_error_close_failure_blocks_retry_and_preserves_first_cause():
    events = []
    body = _OwnedErrorBody(events, fail_close=True)
    failure = _owned_http(503, body, "0")
    attempts = []

    def opener(request, **kwargs):
        attempts.append(request)
        raise failure

    try:
        with pytest.raises(ProviderReadError, match="cleanup failed") as raised:
            open_provider_get(Request("https://api.github.test/value"), timeout=30,
                              opener=opener,
                              sleeper=lambda delay: pytest.fail("failed cleanup slept"))
        assert raised.value.__cause__ is failure
        assert "cleanup cause: OSError" in raised.value.__notes__
        assert len(attempts) == 1 and events == ["close"]
    finally:
        body.fail_close = False
        body.close()


def test_provider_retry_sleep_interruption_retains_retired_error_response():
    events = []
    body = _OwnedErrorBody(events)
    failure = _owned_http(503, body, "0")
    interrupted = KeyboardInterrupt()
    attempts = []

    def opener(request, **kwargs):
        attempts.append(request)
        raise failure

    def sleeper(delay):
        assert body.closed
        raise interrupted

    with pytest.raises(KeyboardInterrupt) as raised:
        open_provider_get(Request("https://api.github.test/value"), timeout=30,
                          opener=opener, sleeper=sleeper)
    assert raised.value is interrupted
    assert len(attempts) == 1 and body.closed and events == ["close"]


def test_provider_error_response_close_interruption_never_continues():
    events = []
    interrupted = KeyboardInterrupt()

    class InterruptedBody(_OwnedErrorBody):
        def close(self):
            events.append("interrupted-close")
            raise interrupted

    body = InterruptedBody(events)
    failure = _owned_http(503, body, "0")
    attempts = []

    def opener(request, **kwargs):
        attempts.append(request)
        raise failure

    try:
        with pytest.raises(KeyboardInterrupt) as raised:
            open_provider_get(Request("https://api.github.test/value"), timeout=30,
                              opener=opener,
                              sleeper=lambda delay: pytest.fail("cancelled close slept"))
        assert raised.value is interrupted
        assert raised.value.__context__ is failure
        assert len(attempts) == 1 and events == ["interrupted-close"]
    finally:
        BytesIO.close(body)
