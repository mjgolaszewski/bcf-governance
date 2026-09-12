"""Closed GitHub download media types and credential-safe redirects."""

from __future__ import annotations

from enum import Enum
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

class GitHubDownloadKind(str, Enum):
    """Provider endpoint families with distinct GitHub media-type contracts."""

    ACTIONS_ARTIFACT = "actions_artifact"
    RELEASE_ASSET = "release_asset"


_DOWNLOAD_ACCEPT = {
    GitHubDownloadKind.ACTIONS_ARTIFACT: "application/vnd.github+json",
    GitHubDownloadKind.RELEASE_ASSET: "application/octet-stream",
}


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


class CredentialSafeRedirectHandler(HTTPRedirectHandler):
    """Follow provider downloads without forwarding credentials across origins."""

    def redirect_request(  # type: ignore[override]
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        if urlsplit(newurl).scheme.lower() != "https":
            raise _api_error("GitHub download redirect must use HTTPS")
        if _origin(req.full_url) != _origin(newurl):
            redirected.remove_header("Authorization")
            redirected.remove_header("Proxy-Authorization")
        return redirected


def build_download_request(
    *,
    api_url: str,
    path: str,
    token: str,
    kind: GitHubDownloadKind,
    user_agent: str,
) -> Request:
    """Build one authenticated first-hop request from a closed endpoint kind."""

    if not api_url.startswith("https://") or not token:
        raise _api_error("GitHub download authority must use authenticated HTTPS")
    if not path.startswith("/") or "\n" in path or "\r" in path:
        raise _api_error("GitHub download path is unsafe")
    return Request(
        api_url.rstrip("/") + path,
        method="GET",
        headers={
            "Accept": _DOWNLOAD_ACCEPT[kind],
            "Authorization": f"Bearer {token}",
            "User-Agent": user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )


def open_download(request: Request, *, timeout: int) -> Any:
    """Open one authenticated provider request with the sole redirect policy."""

    return build_opener(CredentialSafeRedirectHandler()).open(request, timeout=timeout)


def _api_error(message: str) -> ValueError:
    # Import lazily so ci_github_api can re-export its established public error type.
    from .ci_github_api import GitHubAPIError

    return GitHubAPIError(message)
