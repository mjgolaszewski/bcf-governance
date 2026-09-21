"""Repository-bound, GET-only provider view for trusted protection inspection.

The Administration-write installation token is observation-only BCF authority:
it must never be passed to the general GitHubAPI mutation client.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .ci_github_api import GitHubAPIError
from .ci_github_identity import positive_int


_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MAX_RESPONSE = 1_048_576


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_inspection(request: Request):
    return build_opener(_NoRedirect()).open(request, timeout=30)


class ProtectionInspectionClient:
    """Closed read capability for one App installation and one repository."""

    def __init__(
        self, *, token: str, repository: str, repository_id: object,
        installation_id: object, observed_installation_id: object,
        api_url: str = "https://api.github.com",
    ) -> None:
        if not token or not _REPOSITORY.fullmatch(repository) or any(
            part in {".", ".."} for part in repository.split("/")
        ):
            raise GitHubAPIError("protection inspection credential or repository is invalid")
        if api_url != "https://api.github.com":
            raise GitHubAPIError("protection inspection requires the canonical GitHub API")
        self._token = token
        self._repository = repository
        self._repository_id = positive_int(repository_id, field="repository ID")
        expected = positive_int(installation_id, field="installation ID")
        observed = positive_int(observed_installation_id, field="observed installation ID")
        if observed != expected:
            raise GitHubAPIError("protection inspection installation identity does not match")
        self._api_url = api_url
        self._verified = False

    def _request(self, method: str, path: str) -> Any:
        prefix = f"/repos/{self._repository}"
        allowed = {
            "/installation/repositories?per_page=100",
            prefix,
            f"{prefix}/rulesets?includes_parents=false&per_page=100",
        }
        if method != "GET" or (
            path not in allowed
            and not re.fullmatch(rf"{re.escape(prefix)}/rulesets/[1-9][0-9]*", path)
        ):
            raise GitHubAPIError("protection inspection permits only declared GET endpoints")
        request = Request(
            self._api_url + path, method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "bcf-protection-inspector",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with _open_inspection(request) as response:
                raw = response.read(_MAX_RESPONSE + 1)
        except HTTPError as exc:
            raise GitHubAPIError(f"protection inspection GET failed: {exc.code}") from exc
        except (OSError, URLError) as exc:
            raise GitHubAPIError("protection inspection GET failed") from exc
        if len(raw) > _MAX_RESPONSE:
            raise GitHubAPIError("protection inspection response is oversized")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubAPIError("protection inspection response is invalid JSON") from exc

    def verify_installation(self) -> None:
        value = self._request("GET", "/installation/repositories?per_page=100")
        repositories = value.get("repositories") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or type(value.get("total_count")) is not int
            or value["total_count"] != 1
            or not isinstance(repositories, list)
            or len(repositories) != 1
            or not isinstance(repositories[0], dict)
            or repositories[0].get("full_name") != self._repository
            or repositories[0].get("id") != self._repository_id
        ):
            raise GitHubAPIError("protection inspection installation repository scope is not exact")
        self._verified = True

    def repository(self, repository: str) -> dict[str, Any]:
        self._require_repository(repository)
        value = self._request("GET", f"/repos/{repository}")
        if not isinstance(value, dict) or value.get("id") != self._repository_id or value.get("full_name") != repository:
            raise GitHubAPIError("protection inspection repository identity is not exact")
        return value

    def repository_rulesets(self, repository: str) -> tuple[dict[str, Any], ...]:
        self._require_repository(repository)
        value = self._request(
            "GET", f"/repos/{repository}/rulesets?includes_parents=false&per_page=100"
        )
        if not isinstance(value, list) or len(value) >= 100 or any(
            not isinstance(item, dict) for item in value
        ):
            raise GitHubAPIError("protection inspection ruleset inventory is not exact")
        return tuple(value)

    def ruleset(self, repository: str, ruleset_id: object) -> dict[str, Any]:
        self._require_repository(repository)
        numeric = positive_int(ruleset_id, field="ruleset ID")
        value = self._request("GET", f"/repos/{repository}/rulesets/{numeric}")
        if not isinstance(value, dict) or value.get("id") != numeric:
            raise GitHubAPIError("protection inspection ruleset identity is not exact")
        if "bypass_actors" not in value or not isinstance(value["bypass_actors"], list):
            raise GitHubAPIError("protection inspection bypass actors are absent or redacted")
        return value

    def _require_repository(self, repository: str) -> None:
        if repository != self._repository:
            raise GitHubAPIError("protection inspection repository is not authorized")
        if not self._verified:
            raise GitHubAPIError("protection inspection installation is not verified")
