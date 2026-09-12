"""Streaming GitHub Release transport dedicated to durable evidence inputs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request

from .ci_github_api import GitHubAPI, GitHubAPIError, _positive_id, _sha
from .ci_github_downloads import (
    GitHubDownloadKind,
    build_download_request,
    open_download,
)


EVIDENCE_TAG = re.compile(r"^bcf-evidence-[a-z0-9-]+-[a-f0-9]{64}$")


class GitHubEvidenceAPI(GitHubAPI):
    """Narrow GitHub adapter whose release namespace cannot overlap product tags."""

    @staticmethod
    def _tag(tag: str) -> str:
        if not EVIDENCE_TAG.fullmatch(tag):
            raise GitHubAPIError("evidence release tag identity is unsafe")
        return tag

    def evidence_release_by_tag(self, repository: str, tag: str) -> dict[str, Any]:
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/releases/tags/{quote(self._tag(tag))}",
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("evidence release response must be an object")
        return value

    def repository_artifacts(self, repository: str) -> tuple[dict[str, Any], ...]:
        """Read the complete current artifact inventory without caller pagination."""

        first = self._request(
            "GET", f"/repos/{self._repository(repository)}/actions/artifacts?per_page=100&page=1"
        )
        if not isinstance(first, dict) or not isinstance(first.get("artifacts"), list):
            raise GitHubAPIError("repository artifact inventory is malformed")
        total = first.get("total_count")
        if not isinstance(total, int) or total < 0 or total > 100_000:
            raise GitHubAPIError("repository artifact total is unsafe")
        result = list(first["artifacts"])
        pages = (total + 99) // 100
        for page in range(2, pages + 1):
            value = self._request(
                "GET",
                f"/repos/{self._repository(repository)}/actions/artifacts?per_page=100&page={page}",
            )
            items = value.get("artifacts") if isinstance(value, dict) else None
            if not isinstance(items, list):
                raise GitHubAPIError("repository artifact page is malformed")
            result.extend(items)
        if len(result) != total or any(not isinstance(item, dict) for item in result):
            raise GitHubAPIError("repository artifact inventory is incomplete")
        return tuple(result)

    def delete_action_artifact(self, repository: str, artifact_id: object) -> None:
        """Delete one exact Actions artifact; no name or glob selection is allowed."""

        numeric = _positive_id(artifact_id, field="Actions artifact ID")
        result = self._request(
            "DELETE",
            f"/repos/{self._repository(repository)}/actions/artifacts/{numeric}",
        )
        if result is not None:
            raise GitHubAPIError("Actions artifact deletion returned unexpected content")

    def evidence_releases(self, repository: str) -> tuple[dict[str, Any], ...]:
        """Read all evidence-namespace releases through bounded direct API calls."""

        result: list[dict[str, Any]] = []
        for page in range(1, 1001):
            value = self._request(
                "GET",
                f"/repos/{self._repository(repository)}/releases?per_page=100&page={page}",
            )
            if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
                raise GitHubAPIError("release inventory page is malformed")
            result.extend(
                item
                for item in value
                if isinstance(item.get("tag_name"), str)
                and EVIDENCE_TAG.fullmatch(item["tag_name"])
            )
            if len(value) < 100:
                return tuple(result)
        raise GitHubAPIError("release inventory exceeds the closed page limit")

    def create_evidence_draft_release(
        self,
        repository: str,
        *,
        tag: str,
        target_commit: str,
        body: str,
    ) -> dict[str, Any]:
        exact_tag = self._tag(tag)
        value = self._request(
            "POST",
            f"/repos/{self._repository(repository)}/releases",
            payload={
                "tag_name": exact_tag,
                "target_commitish": _sha(target_commit, field="evidence target commit"),
                "name": f"BCF evidence inputs {exact_tag.rsplit('-', 1)[-1][:12]}",
                "body": body,
                "draft": True,
                "prerelease": True,
                "generate_release_notes": False,
                "make_latest": "false",
            },
        )
        if not isinstance(value, dict) or value.get("draft") is not True:
            raise GitHubAPIError("provider did not create an exact evidence draft")
        return value

    def upload_evidence_asset(
        self,
        *,
        upload_url: str,
        repository: str,
        release_id: object,
        name: str,
        path: Path,
        maximum_bytes: int,
    ) -> dict[str, Any]:
        numeric = _positive_id(release_id, field="release ID")
        base = upload_url.split("{", 1)[0]
        expected = (
            f"https://uploads.github.com/repos/{self._repository(repository)}"
            f"/releases/{numeric}/assets"
        )
        if base != expected or Path(name).name != name or not name:
            raise GitHubAPIError("evidence asset upload identity is unsafe")
        if path.is_symlink() or not path.is_file():
            raise GitHubAPIError("evidence asset upload source must be a regular file")
        size = path.stat().st_size
        if size < 1 or size > maximum_bytes:
            raise GitHubAPIError("evidence asset exceeds the closed size limit")
        request = Request(
            f"{base}?{urlencode({'name': name})}",
            data=None,
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "bcf-governance-trusted-control",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
            },
        )
        try:
            with path.open("rb") as stream:
                request.data = stream
                with open_download(request, timeout=300) as response:
                    raw = response.read(1_048_577)
        except HTTPError as exc:
            raise GitHubAPIError(f"GitHub evidence asset upload returned {exc.code}") from exc
        except (OSError, URLError) as exc:
            raise GitHubAPIError("GitHub evidence asset upload failed") from exc
        if len(raw) > 1_048_576:
            raise GitHubAPIError("GitHub evidence asset response is oversized")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GitHubAPIError("GitHub evidence asset response is invalid JSON") from exc
        if not isinstance(value, dict):
            raise GitHubAPIError("GitHub evidence asset response must be an object")
        return value

    def download_evidence_asset(
        self,
        repository: str,
        asset_id: object,
        *,
        destination: Path,
        maximum_bytes: int,
    ) -> None:
        numeric = _positive_id(asset_id, field="release asset ID")
        if destination.exists() or destination.is_symlink():
            raise GitHubAPIError("evidence asset destination must not already exist")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.parent.is_symlink():
            raise GitHubAPIError("evidence asset destination parent is symlinked")
        path = f"/repos/{self._repository(repository)}/releases/assets/{numeric}"
        self._download_endpoint(
            path,
            kind=GitHubDownloadKind.RELEASE_ASSET,
            destination=destination,
            maximum_bytes=maximum_bytes,
        )

    def download_action_artifact(
        self,
        repository: str,
        artifact_id: object,
        *,
        destination: Path,
        maximum_bytes: int,
    ) -> None:
        numeric = _positive_id(artifact_id, field="Actions artifact ID")
        if destination.exists() or destination.is_symlink():
            raise GitHubAPIError("Actions artifact destination must not already exist")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.parent.is_symlink():
            raise GitHubAPIError("Actions artifact destination parent is symlinked")
        path = f"/repos/{self._repository(repository)}/actions/artifacts/{numeric}/zip"
        self._download_endpoint(
            path,
            kind=GitHubDownloadKind.ACTIONS_ARTIFACT,
            destination=destination,
            maximum_bytes=maximum_bytes,
        )

    def _download_endpoint(
        self,
        path: str,
        *,
        kind: GitHubDownloadKind,
        destination: Path,
        maximum_bytes: int,
    ) -> None:
        if maximum_bytes < 1:
            raise GitHubAPIError("GitHub evidence download limit must be positive")
        request = build_download_request(
            api_url=self._api_url,
            path=path,
            token=self._token,
            kind=kind,
            user_agent="bcf-governance-evidence-resolver",
        )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        temporary = Path(temporary_name)
        total = 0
        try:
            with os.fdopen(descriptor, "wb") as output:
                with open_download(request, timeout=300) as response:  # noqa: S310
                    for chunk in iter(lambda: response.read(1024 * 1024), b""):
                        total += len(chunk)
                        if total > maximum_bytes:
                            raise GitHubAPIError(
                                "GitHub evidence asset exceeds the closed size limit"
                            )
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            if total < 1:
                raise GitHubAPIError("GitHub evidence asset is empty")
            temporary.chmod(0o600)
            temporary.replace(destination)
        except HTTPError as exc:
            raise GitHubAPIError(f"GitHub evidence asset download returned {exc.code}") from exc
        except (OSError, URLError) as exc:
            raise GitHubAPIError("GitHub evidence asset download failed") from exc
        finally:
            if temporary.exists():
                temporary.unlink()
