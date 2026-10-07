from __future__ import annotations

from email.message import Message
from io import BytesIO
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


def test_provider_retry_rejects_mutation_method() -> None:
    with pytest.raises(ProviderReadError, match="GET only"):
        open_provider_get(
            Request("https://api.github.test/value", method="POST", data=b"{}"),
            timeout=30,
            opener=lambda *_args, **_kwargs: pytest.fail("mutation reached transport"),
        )
