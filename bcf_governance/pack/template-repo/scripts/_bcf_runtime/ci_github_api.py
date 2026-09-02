"""Minimal authenticated GitHub REST client for the trusted CI control plane."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .release_versions import ReleaseVersionError, parse_release_tag


REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubAPIError(ValueError):
    """Raised when provider state cannot be obtained or authenticated safely."""


@dataclass(frozen=True)
class GitHubContent:
    path: str
    blob_oid: str
    content: bytes


class GitHubAPI:
    """Small JSON-only client whose token is supplied by the trusted workflow."""

    def __init__(self, *, token: str, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise GitHubAPIError("trusted GitHub token is required")
        if not api_url.startswith("https://"):
            raise GitHubAPIError("GitHub API URL must use HTTPS")
        self._token = token
        self._api_url = api_url.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise GitHubAPIError("GitHub API path is unsafe")
        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
        request = Request(
            self._api_url + path,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "bcf-governance-trusted-control",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed HTTPS origin
                raw = response.read()
        except HTTPError as exc:
            raise GitHubAPIError(f"GitHub API {method} {path} returned {exc.code}") from exc
        except (OSError, URLError) as exc:
            raise GitHubAPIError(f"GitHub API {method} {path} failed") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GitHubAPIError("GitHub API returned invalid JSON") from exc

    def _request_bytes(self, path: str, *, maximum_bytes: int) -> bytes:
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise GitHubAPIError("GitHub API path is unsafe")
        if maximum_bytes < 1:
            raise GitHubAPIError("GitHub byte response limit must be positive")
        request = Request(
            self._api_url + path,
            method="GET",
            headers={
                "Accept": "application/octet-stream",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "bcf-governance-trusted-control",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed HTTPS origin
                raw = response.read(maximum_bytes + 1)
        except HTTPError as exc:
            raise GitHubAPIError(f"GitHub API GET {path} returned {exc.code}") from exc
        except (OSError, URLError) as exc:
            raise GitHubAPIError(f"GitHub API GET {path} failed") from exc
        if len(raw) > maximum_bytes:
            raise GitHubAPIError("GitHub artifact exceeds the closed size limit")
        return raw

    def _upload_bytes(
        self, url: str, *, payload: bytes, media_type: str
    ) -> dict[str, Any]:
        if not url.startswith("https://uploads.github.com/") or len(payload) > 104_857_600:
            raise GitHubAPIError("GitHub release upload target or size is unsafe")
        request = Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "bcf-governance-trusted-control",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": media_type,
            },
        )
        try:
            with urlopen(request, timeout=60) as response:  # noqa: S310 - closed HTTPS origin
                raw = response.read(1_048_577)
        except HTTPError as exc:
            raise GitHubAPIError(f"GitHub release asset upload returned {exc.code}") from exc
        except (OSError, URLError) as exc:
            raise GitHubAPIError("GitHub release asset upload failed") from exc
        if len(raw) > 1_048_576:
            raise GitHubAPIError("GitHub release asset response is oversized")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GitHubAPIError("GitHub release asset response is invalid JSON") from exc
        if not isinstance(value, dict):
            raise GitHubAPIError("GitHub release asset response must be an object")
        return value

    @staticmethod
    def _repository(repository: str) -> str:
        parts = repository.split("/")
        if (
            not REPOSITORY_PATTERN.fullmatch(repository)
            or len(parts) != 2
            or any(part in {".", ".."} for part in parts)
        ):
            raise GitHubAPIError("repository must be exact owner/name identity")
        return repository

    def repository(self, repository: str) -> dict[str, Any]:
        value = self._request("GET", f"/repos/{self._repository(repository)}")
        if not isinstance(value, dict):
            raise GitHubAPIError("repository response must be an object")
        return value

    def run(self, repository: str, run_id: str | int) -> dict[str, Any]:
        numeric = _positive_id(run_id, field="run ID")
        value = self._request(
            "GET", f"/repos/{self._repository(repository)}/actions/runs/{numeric}"
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("workflow run response must be an object")
        return value

    def workflow(self, repository: str, workflow_id: str | int) -> dict[str, Any]:
        reference = _workflow_reference(workflow_id)
        value = self._request(
            "GET", f"/repos/{self._repository(repository)}/actions/workflows/{reference}"
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("workflow response must be an object")
        return value

    def commit(self, repository: str, sha: str) -> dict[str, Any]:
        exact = _sha(sha, field="commit SHA")
        value = self._request(
            "GET", f"/repos/{self._repository(repository)}/git/commits/{exact}"
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("commit response must be an object")
        return value

    def reference(self, repository: str, ref: str) -> dict[str, Any]:
        if not ref or ".." in ref or not re.fullmatch(r"[A-Za-z0-9._/-]+", ref):
            raise GitHubAPIError("Git reference is unsafe")
        value = self._request(
            "GET", f"/repos/{self._repository(repository)}/git/ref/{quote(ref)}"
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("Git reference response must be an object")
        return value

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        if path.startswith("/") or ".." in path.split("/") or not path:
            raise GitHubAPIError("repository content path is unsafe")
        query = urlencode({"ref": ref})
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/contents/{quote(path)}?{query}",
        )
        if not isinstance(value, dict) or value.get("type") != "file":
            raise GitHubAPIError("repository content response must be a file")
        encoded = value.get("content")
        if not isinstance(encoded, str) or value.get("encoding") != "base64":
            raise GitHubAPIError("repository content must use base64 encoding")
        try:
            content = base64.b64decode("".join(encoded.split()), validate=True)
        except ValueError as exc:
            raise GitHubAPIError("repository content is not valid base64") from exc
        return GitHubContent(path=path, blob_oid=_sha(value.get("sha"), field="blob OID"), content=content)

    def workflow_runs(
        self,
        repository: str,
        workflow_id: str | int,
        *,
        head_sha: str,
        event: str,
    ) -> tuple[dict[str, Any], ...]:
        reference = _workflow_reference(workflow_id)
        query = urlencode({"head_sha": _sha(head_sha, field="head SHA"), "event": event, "per_page": 100})
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/actions/workflows/{reference}/runs?{query}",
        )
        runs = value.get("workflow_runs") if isinstance(value, dict) else None
        if not isinstance(runs, list) or any(not isinstance(run, dict) for run in runs):
            raise GitHubAPIError("workflow runs response must contain an object list")
        if int(value.get("total_count", len(runs))) > len(runs):
            raise GitHubAPIError("workflow run inventory exceeds one authenticated page")
        return tuple(runs)

    def jobs(
        self,
        repository: str,
        run_id: str | int,
        *,
        attempt: int,
    ) -> tuple[dict[str, Any], ...]:
        numeric = _positive_id(run_id, field="run ID")
        if isinstance(attempt, bool) or attempt < 1:
            raise GitHubAPIError("run attempt must be positive")
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/actions/runs/{numeric}/attempts/{attempt}/jobs?per_page=100",
        )
        jobs = value.get("jobs") if isinstance(value, dict) else None
        if not isinstance(jobs, list) or any(not isinstance(job, dict) for job in jobs):
            raise GitHubAPIError("workflow jobs response must contain an object list")
        if int(value.get("total_count", len(jobs))) != len(jobs):
            raise GitHubAPIError("workflow job inventory exceeds one authenticated page")
        return tuple(jobs)

    def artifacts(
        self, repository: str, run_id: str | int
    ) -> tuple[dict[str, Any], ...]:
        numeric = _positive_id(run_id, field="run ID")
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/actions/runs/{numeric}/artifacts?per_page=100",
        )
        artifacts = value.get("artifacts") if isinstance(value, dict) else None
        if not isinstance(artifacts, list) or any(
            not isinstance(item, dict) for item in artifacts
        ):
            raise GitHubAPIError("artifact response must contain an object list")
        if int(value.get("total_count", len(artifacts))) != len(artifacts):
            raise GitHubAPIError("artifact inventory exceeds one authenticated page")
        return tuple(artifacts)

    def artifact_bytes(
        self,
        repository: str,
        artifact_id: str | int,
        *,
        maximum_bytes: int = 104_857_600,
    ) -> bytes:
        numeric = _positive_id(artifact_id, field="artifact ID")
        return self._request_bytes(
            f"/repos/{self._repository(repository)}/actions/artifacts/{numeric}/zip",
            maximum_bytes=maximum_bytes,
        )

    def immutable_releases(self, repository: str) -> dict[str, Any]:
        value = self._request(
            "GET", f"/repos/{self._repository(repository)}/immutable-releases"
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("immutable-release setting must be an object")
        return value

    def release_by_tag(self, repository: str, tag: str) -> dict[str, Any]:
        try:
            parse_release_tag(tag)
        except ReleaseVersionError as exc:
            raise GitHubAPIError("release tag must be one canonical public version") from exc
        value = self._request(
            "GET", f"/repos/{self._repository(repository)}/releases/tags/{quote(tag)}"
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("release response must be an object")
        return value

    def create_draft_release(
        self, repository: str, *, tag: str, name: str, body: str
    ) -> dict[str, Any]:
        try:
            release_version = parse_release_tag(tag)
        except ReleaseVersionError as exc:
            raise GitHubAPIError("draft release identity must be one canonical public version") from exc
        if name != tag:
            raise GitHubAPIError("draft release name must equal its canonical tag")
        value = self._request(
            "POST",
            f"/repos/{self._repository(repository)}/releases",
            payload={
                "tag_name": tag,
                "name": name,
                "body": body,
                "draft": True,
                "prerelease": release_version.prerelease,
                "generate_release_notes": False,
            },
        )
        if not isinstance(value, dict) or value.get("draft") is not True:
            raise GitHubAPIError("provider did not create an exact draft release")
        return value

    def upload_release_asset(
        self,
        *,
        upload_url: str,
        repository: str,
        release_id: object,
        name: str,
        payload: bytes,
    ) -> dict[str, Any]:
        numeric = _positive_id(release_id, field="release ID")
        base = upload_url.split("{", 1)[0]
        expected = (
            f"https://uploads.github.com/repos/{self._repository(repository)}"
            f"/releases/{numeric}/assets"
        )
        if base != expected or Path(name).name != name or not name:
            raise GitHubAPIError("release asset upload identity is unsafe")
        return self._upload_bytes(
            f"{base}?{urlencode({'name': name})}",
            payload=payload,
            media_type="application/octet-stream",
        )

    def publish_release(self, repository: str, release_id: object) -> dict[str, Any]:
        numeric = _positive_id(release_id, field="release ID")
        value = self._request(
            "PATCH",
            f"/repos/{self._repository(repository)}/releases/{numeric}",
            payload={"draft": False},
        )
        if not isinstance(value, dict) or value.get("draft") is not False:
            raise GitHubAPIError("provider did not publish the release")
        return value

    def tag_object(self, repository: str, tag_object_sha: str) -> dict[str, Any]:
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/git/tags/{_sha(tag_object_sha, field='tag object SHA')}",
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("annotated tag response must be an object")
        return value

    def attestations(
        self, repository: str, subject_digest: str
    ) -> tuple[dict[str, Any], ...]:
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", subject_digest):
            raise GitHubAPIError("attestation subject digest must be SHA-256")
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/attestations/{subject_digest}",
        )
        attestations = value.get("attestations") if isinstance(value, dict) else None
        if not isinstance(attestations, list) or any(
            not isinstance(item, dict) for item in attestations
        ):
            raise GitHubAPIError("attestation response must contain an object list")
        return tuple(attestations)

    def dispatch(self, repository: str, *, event_type: str, client_payload: dict[str, Any]) -> None:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", event_type):
            raise GitHubAPIError("repository dispatch event type is unsafe")
        self._request(
            "POST",
            f"/repos/{self._repository(repository)}/dispatches",
            payload={"event_type": event_type, "client_payload": client_payload},
        )

    def status(
        self,
        repository: str,
        *,
        sha: str,
        state: str,
        context: str,
        description: str,
        target_url: str,
    ) -> None:
        if state not in {"error", "failure", "pending", "success"}:
            raise GitHubAPIError("commit status state is unsupported")
        self._request(
            "POST",
            f"/repos/{self._repository(repository)}/statuses/{_sha(sha, field='status SHA')}",
            payload={
                "state": state,
                "context": context,
                "description": description[:140],
                "target_url": target_url,
            },
        )

    def commit_statuses(self, repository: str, *, sha: str) -> tuple[dict[str, Any], ...]:
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/commits/{_sha(sha, field='status SHA')}/statuses?per_page=100",
        )
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise GitHubAPIError("commit statuses response must contain an object list")
        if len(value) == 100:
            raise GitHubAPIError("commit status inventory exceeds one authenticated page")
        return tuple(value)


def _positive_id(value: object, *, field: str) -> str:
    text = str(value)
    if not text.isdigit() or int(text) < 1:
        raise GitHubAPIError(f"{field} must be a positive numeric provider ID")
    return text


def _workflow_reference(value: object) -> str:
    text = str(value)
    if text.isdigit():
        return _positive_id(text, field="workflow ID")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", text):
        raise GitHubAPIError("workflow reference must be a numeric ID or exact file name")
    return quote(text, safe="")


def _sha(value: object, *, field: str) -> str:
    text = str(value)
    if not re.fullmatch(r"[a-f0-9]{40}", text):
        raise GitHubAPIError(f"{field} must be an exact 40-character Git SHA")
    return text
