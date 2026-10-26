"""Narrow GitHub API facet for immutable release publication."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode

from .ci_github_errors import GitHubAPIError
from .ci_github_values import GitHubValueError, positive_id, sha
from .release_versions import ReleaseVersionError, parse_release_tag


class GitHubReleaseAPIMixin:
    """Provider operations owned solely by release publication and custody."""

    if TYPE_CHECKING:
        # Required composition ports supplied by GitHubAPI; no runtime fallback.
        @staticmethod
        def _repository(repository: str) -> str:
            raise NotImplementedError

        def _request(
            self, method: str, path: str, *,
            payload: dict[str, object] | None = None,
            not_found_none: bool = False,
        ) -> object:
            raise NotImplementedError

        def _upload_bytes(
            self, url: str, *, payload: bytes, media_type: str
        ) -> dict[str, object]:
            raise NotImplementedError

    def immutable_releases(self, repository: str) -> dict[str, Any]:
        value = self._request(
            "GET", f"/repos/{self._repository(repository)}/immutable-releases"
        )
        if not isinstance(value, dict):
            raise GitHubAPIError("immutable-release setting must be an object")
        return value

    def release_by_tag(self, repository: str, tag: str) -> dict[str, Any]:
        value = self._release_by_tag(repository, tag, optional=False)
        if not isinstance(value, dict):
            raise GitHubAPIError("release response must be an object")
        return value

    def optional_release_by_tag(
        self, repository: str, tag: str
    ) -> dict[str, Any] | None:
        return self._release_by_tag(repository, tag, optional=True)

    def _release_by_tag(
        self, repository: str, tag: str, *, optional: bool
    ) -> dict[str, Any] | None:
        try:
            parse_release_tag(tag)
        except ReleaseVersionError as exc:
            raise GitHubAPIError("release tag must be one canonical public version") from exc
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/releases/tags/{quote(tag)}",
            not_found_none=optional,
        )
        if value is not None and not isinstance(value, dict):
            raise GitHubAPIError("release response must be an object")
        return value

    def releases(self, repository: str, *, page: int) -> tuple[dict[str, Any], ...]:
        if page < 1 or page > 100:
            raise GitHubAPIError("release inventory page is outside the bounded range")
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/releases?per_page=100&page={page}",
        )
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise GitHubAPIError("release inventory response must be an object list")
        return tuple(value)

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
        try:
            numeric = positive_id(release_id, field="release ID")
        except GitHubValueError as exc:
            raise GitHubAPIError(str(exc)) from exc
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
        try:
            numeric = positive_id(release_id, field="release ID")
        except GitHubValueError as exc:
            raise GitHubAPIError(str(exc)) from exc
        value = self._request(
            "PATCH",
            f"/repos/{self._repository(repository)}/releases/{numeric}",
            payload={"draft": False},
        )
        if not isinstance(value, dict) or value.get("draft") is not False:
            raise GitHubAPIError("provider did not publish the release")
        return value

    def tag_object(self, repository: str, tag_object_sha: str) -> dict[str, Any]:
        try:
            exact_sha = sha(tag_object_sha, field="tag object SHA")
        except GitHubValueError as exc:
            raise GitHubAPIError(str(exc)) from exc
        value = self._request(
            "GET",
            f"/repos/{self._repository(repository)}/git/tags/{exact_sha}",
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
