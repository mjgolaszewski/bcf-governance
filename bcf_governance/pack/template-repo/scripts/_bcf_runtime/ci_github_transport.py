"""Bounded HTTP transport for the canonical GitHub API client."""

from __future__ import annotations

import json
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request

from .ci_github_downloads import GitHubDownloadKind, build_download_request
from .provider_read import ProviderReadAttempt, ProviderReadError, open_provider_get
from .ci_github_response import (
    ProviderResponseError, _retire_provider_error_response,
    provider_response_deadline, valid_provider_byte_limit,
)


class GitHubTransportError(ValueError):
    """A bounded GitHub transport operation failed."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def request_json(
    *,
    method: str,
    api_url: str,
    path: str,
    token: str,
    payload: dict[str, Any] | None,
    not_found_none: bool,
    opener: Callable[..., Any],
    observations: list[ProviderReadAttempt],
) -> Any:
    if not path.startswith("/") or "\n" in path or "\r" in path:
        raise GitHubTransportError("GitHub API path is unsafe")
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    request = Request(
        api_url + path,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "bcf-governance-trusted-control",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        operation = (
            open_provider_get(
                request, timeout=30, opener=opener, observations=observations
            )
            if method == "GET"
            else opener(request, timeout=30)
        )
        with operation as response, provider_response_deadline(response, timeout=30) as bounded:
            raw = bounded.read()
    except HTTPError as exc:
        if method != "GET":
            try:
                _retire_provider_error_response(exc)
            except ProviderResponseError as cleanup_error:
                raise GitHubTransportError(
                    f"GitHub API {method} {path} error response cleanup failed"
                ) from cleanup_error
        if not_found_none and method == "GET" and exc.code == 404:
            return None
        raise GitHubTransportError(
            f"GitHub API {method} {path} returned {exc.code}", status_code=exc.code
        ) from exc
    except (OSError, URLError, ProviderReadError) as exc:
        raise GitHubTransportError(f"GitHub API {method} {path} failed") from exc
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GitHubTransportError("GitHub API returned invalid JSON") from exc


def request_bytes(
    *,
    api_url: str,
    path: str,
    token: str,
    kind: GitHubDownloadKind,
    maximum_bytes: int,
    opener: Callable[..., Any],
    observations: list[ProviderReadAttempt],
) -> bytes:
    if not path.startswith("/") or "\n" in path or "\r" in path:
        raise GitHubTransportError("GitHub API path is unsafe")
    if not valid_provider_byte_limit(maximum_bytes):
        raise GitHubTransportError("GitHub byte response limit must be a positive integer")
    request = build_download_request(
        api_url=api_url,
        path=path,
        token=token,
        kind=kind,
        user_agent="bcf-governance-trusted-control",
    )
    try:
        with open_provider_get(
            request, timeout=30, opener=opener, observations=observations
        ) as response, provider_response_deadline(response, timeout=30) as bounded:
            raw = bounded.read(maximum_bytes + 1)
    except HTTPError as exc:
        raise GitHubTransportError(f"GitHub API GET {path} returned {exc.code}") from exc
    except (OSError, URLError, ProviderReadError) as exc:
        raise GitHubTransportError(f"GitHub API GET {path} failed") from exc
    if len(raw) > maximum_bytes:
        raise GitHubTransportError("GitHub artifact exceeds the closed size limit")
    return raw
