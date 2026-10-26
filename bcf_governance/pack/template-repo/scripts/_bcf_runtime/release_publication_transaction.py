"""Idempotent immutable-release publication from one certified byte inventory."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .ci_github_api import GitHubAPI, GitHubAPIConflictError
from .ci_github_artifacts import provider_digest
from .ci_github_identity import GitHubControllerError
from .release_asset_inventory import exact_assets, release_asset_version
from .release_tag_publication import ensure_release_tag


def _require_attestations(
    api: GitHubAPI, repository: str, digests: Iterable[str], error: str
) -> None:
    for digest in digests:
        if not api.attestations(repository, f"sha256:{digest}"):
            raise GitHubControllerError(error)


def _asset_inventory(release: dict[str, Any]) -> dict[str, str]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise GitHubControllerError("release asset inventory is invalid")
    observed: dict[str, str] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise GitHubControllerError("release asset inventory is invalid")
        name = str(asset["name"])
        if not name or name in observed:
            raise GitHubControllerError("release asset inventory is invalid")
        observed[name] = provider_digest(asset.get("digest")).removeprefix("sha256:")
    return observed


def _matching_release(
    api: GitHubAPI, repository: str, tag: str
) -> dict[str, Any] | None:
    published = api.optional_release_by_tag(repository, tag)
    if published is not None:
        return published
    matches: list[dict[str, Any]] = []
    for page in range(1, 101):
        releases = api.releases(repository, page=page)
        matches.extend(item for item in releases if item.get("tag_name") == tag)
        if len(releases) < 100:
            break
    else:
        raise GitHubControllerError("release inventory exceeds the bounded scan")
    if len(matches) > 1:
        raise GitHubControllerError("release tag resolves to ambiguous provider state")
    return matches[0] if matches else None


def _validate_release_identity(
    release: dict[str, Any], *, tag: str, body: str
) -> None:
    prerelease = release_asset_version_from_tag(tag)
    if (
        release.get("tag_name") != tag
        or release.get("name") != tag
        or release.get("body") != body
        or release.get("prerelease") is not prerelease
    ):
        raise GitHubControllerError("release provider identity conflicts with transaction")
    if release.get("draft") not in {True, False}:
        raise GitHubControllerError("release provider lifecycle is invalid")


def release_asset_version_from_tag(tag: str) -> bool:
    """Return the canonical prerelease bit without accepting tag aliases."""

    from .release_versions import parse_release_tag

    try:
        return parse_release_tag(tag).prerelease
    except ValueError as exc:
        raise GitHubControllerError("release tag is not canonical") from exc


def _transaction_digest(
    *, repository: str, tag: str, commit: str, assets: dict[str, str], body: str
) -> str:
    payload = {
        "repository": repository,
        "tag": tag,
        "commit_sha": commit,
        "assets": dict(sorted(assets.items())),
        "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def inspect_release(
    api: GitHubAPI,
    *,
    repository: str,
    tag: str,
    expected_commit: str,
    expected_assets: dict[str, str],
) -> dict[str, Any]:
    """Fail closed unless a release has exact immutable provider custody."""

    immutable = api.immutable_releases(repository)
    if immutable.get("enabled") is not True:
        raise GitHubControllerError("repository immutable releases are not enabled")
    reference = api.reference(repository, f"tags/{tag}")
    target = reference.get("object")
    if not isinstance(target, dict) or target.get("type") != "tag":
        raise GitHubControllerError("release publication requires an annotated tag")
    tag_object = api.tag_object(repository, str(target.get("sha")))
    tag_target = tag_object.get("object")
    verification = tag_object.get("verification")
    if tag_object.get("tag") != tag or not isinstance(tag_target, dict) or (
        tag_target.get("type") != "commit" or tag_target.get("sha") != expected_commit
    ):
        raise GitHubControllerError(
            "release publication tag does not match certified commit"
        )
    if not isinstance(verification, dict) or verification.get("verified") is not False or (
        verification.get("reason") != "unsigned"
    ):
        raise GitHubControllerError("release tag does not match annotated unsigned policy")
    release = api.release_by_tag(repository, tag)
    if release.get("immutable") is not True or release.get("draft") is not False:
        raise GitHubControllerError("published release must be immutable and non-draft")
    observed = _asset_inventory(release)
    if observed != expected_assets:
        raise GitHubControllerError("published release assets are not exact")
    _require_attestations(
        api, repository, observed.values(), "published release asset lacks attestation"
    )
    return {
        "status": "verified",
        "tag": tag,
        "commit_sha": expected_commit,
        "immutable": True,
        "draft": False,
        "assets": dict(sorted(observed.items())),
    }


def publish_release(
    api: GitHubAPI,
    *,
    repository: str,
    tag: str,
    expected_commit: str,
    release_artifacts: Iterable[Path],
    body: str,
) -> dict[str, Any]:
    """Converge one exact transaction or reject conflicting provider state."""

    paths = tuple(release_artifacts)
    if release_asset_version(paths).tag != tag:
        raise GitHubControllerError("release tag does not match the closed archive version")
    if api.immutable_releases(repository).get("enabled") is not True:
        raise GitHubControllerError("immutable releases must be enabled before publication")
    expected_assets = exact_assets(paths)
    attestation_error = "release assets must be attested before provider mutation"
    _require_attestations(api, repository, expected_assets.values(), attestation_error)
    transaction = _transaction_digest(
        repository=repository,
        tag=tag,
        commit=expected_commit,
        assets=expected_assets,
        body=body,
    )
    existing = _matching_release(api, repository, tag)
    if existing is not None:
        _validate_release_identity(existing, tag=tag, body=body)
        if existing["draft"] is False:
            result = inspect_release(
                api,
                repository=repository,
                tag=tag,
                expected_commit=expected_commit,
                expected_assets=expected_assets,
            )
            return {**result, "transaction_sha256": transaction, "decision": "already_published"}
        observed = _asset_inventory(existing)
        if any(expected_assets.get(name) != digest for name, digest in observed.items()):
            raise GitHubControllerError("draft release assets conflict with transaction")

    ensure_release_tag(api, repository=repository, tag=tag, commit_sha=expected_commit)
    draft = existing
    if draft is None:
        try:
            draft = api.create_draft_release(repository, tag=tag, name=tag, body=body)
        except GitHubAPIConflictError:
            draft = _matching_release(api, repository, tag)
        if draft is None:
            raise GitHubControllerError("release creation conflict did not converge")
        _validate_release_identity(draft, tag=tag, body=body)
        if draft["draft"] is False:
            result = inspect_release(
                api,
                repository=repository,
                tag=tag,
                expected_commit=expected_commit,
                expected_assets=expected_assets,
            )
            return {**result, "transaction_sha256": transaction, "decision": "race_converged"}

    release_id = draft.get("id")
    upload_url = str(draft.get("upload_url", ""))
    observed = _asset_inventory(draft)
    for path in paths:
        if path.name in observed:
            continue
        try:
            api.upload_release_asset(
                upload_url=upload_url,
                repository=repository,
                release_id=release_id,
                name=path.name,
                payload=path.read_bytes(),
            )
        except GitHubAPIConflictError:
            pass
        current = _matching_release(api, repository, tag)
        if current is None:
            raise GitHubControllerError("release disappeared during publication")
        _validate_release_identity(current, tag=tag, body=body)
        observed = _asset_inventory(current)
        if observed.get(path.name) != expected_assets[path.name]:
            raise GitHubControllerError("provider release asset bytes differ before publication")

    current = _matching_release(api, repository, tag)
    if current is None or _asset_inventory(current) != expected_assets:
        raise GitHubControllerError("provider release asset inventory is incomplete")
    if current["draft"] is True:
        try:
            api.publish_release(repository, current.get("id"))
        except GitHubAPIConflictError:
            pass
    result = inspect_release(
        api,
        repository=repository,
        tag=tag,
        expected_commit=expected_commit,
        expected_assets=expected_assets,
    )
    return {**result, "transaction_sha256": transaction, "decision": "published"}
