"""Immutable GitHub Release identities for durable evidence inputs."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from .ci_github_api import GitHubAPIError
from .evidence_storage_contracts import EvidenceStorageError, parse_utc
from .evidence_storage_github_api import GitHubEvidenceAPI
from .evidence_storage_manifests import MANIFEST_NAME


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def provider_digest(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise EvidenceStorageError("GitHub asset lacks an exact SHA-256 provider digest")
    return value


def asset_inventory(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = release.get("assets")
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        raise EvidenceStorageError("GitHub evidence release asset inventory is malformed")
    result: dict[str, dict[str, Any]] = {}
    for item in raw:
        name = item.get("name")
        if not isinstance(name, str) or Path(name).name != name or name in result:
            raise EvidenceStorageError("GitHub evidence release asset identity is ambiguous")
        result[name] = item
    return result


def durable_release_records(
    api: GitHubEvidenceAPI,
    *,
    contract: dict[str, Any],
    repository: str,
) -> dict[str, tuple[int, int]]:
    """Return every namespaced tag with its release ID and retained bytes."""

    durable_releases: dict[str, tuple[int, int]] = {}
    release_ids: set[int] = set()
    prefix = str(contract["provider"]["tag_prefix"]) + "-"
    for release in api.evidence_releases(repository):
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not tag.startswith(prefix):
            continue
        suffix = tag.removeprefix(prefix)
        if suffix.startswith("object-"):
            role = "object"
            tag_digest = suffix.removeprefix("object-")
            expected_name = f"sha256-{tag_digest}.tar.gz"
        elif suffix.startswith("manifest-"):
            role = "manifest"
            tag_digest = suffix.removeprefix("manifest-")
            expected_name = MANIFEST_NAME
        else:
            raise EvidenceStorageError("storage budget found an unknown evidence release role")
        if not re.fullmatch(r"[a-f0-9]{64}", tag_digest):
            raise EvidenceStorageError("storage budget found a malformed evidence release tag")
        draft = release.get("draft")
        immutable = release.get("immutable")
        if draft is True:
            if immutable is not False:
                raise EvidenceStorageError("storage budget found a malformed evidence draft")
        elif draft is not False or immutable is not True:
            raise EvidenceStorageError("storage budget found mutable published evidence")
        assets = asset_inventory(release)
        if len(assets) > 1 or (draft is False and len(assets) != 1):
            raise EvidenceStorageError("storage budget found ambiguous evidence object")
        release_id = release.get("id")
        if (
            not isinstance(release_id, int)
            or release_id < 1
            or release_id in release_ids
        ):
            raise EvidenceStorageError("storage budget found ambiguous evidence release IDs")
        size = 0
        if assets:
            if set(assets) != {expected_name}:
                raise EvidenceStorageError(
                    f"storage budget found a noncanonical {role} asset"
                )
            asset = assets[expected_name]
            digest = provider_digest(asset.get("digest")).removeprefix("sha256:")
            size_value = asset.get("size")
            if (
                digest != tag_digest
                or not isinstance(size_value, int)
                or size_value < 1
            ):
                raise EvidenceStorageError("storage budget found malformed evidence bytes")
            size = size_value
        if tag in durable_releases:
            raise EvidenceStorageError("storage budget found duplicate evidence tags")
        release_ids.add(release_id)
        durable_releases[tag] = (release_id, size)
    return durable_releases


def durable_release_inventory(
    api: GitHubEvidenceAPI,
    *,
    contract: dict[str, Any],
    repository: str,
) -> dict[int, int]:
    """Return every namespaced release ID and its currently retained bytes."""

    return {
        release_id: size
        for release_id, size in durable_release_records(
            api, contract=contract, repository=repository
        ).values()
    }


def release_target(
    api: GitHubEvidenceAPI,
    repository: str,
    tag: str,
    expected_commit: str | None = None,
) -> str:
    reference = api.reference(repository, f"tags/{tag}")
    target = reference.get("object")
    if not isinstance(target, dict):
        raise EvidenceStorageError("evidence release tag target is malformed")
    resolved: str | None = None
    if target.get("type") == "commit" and isinstance(target.get("sha"), str):
        resolved = target["sha"]
    if target.get("type") == "tag":
        tag_object = api.tag_object(repository, str(target.get("sha")))
        nested = tag_object.get("object")
        if isinstance(nested, dict) and nested.get("type") == "commit" and isinstance(
            nested.get("sha"), str
        ):
            resolved = nested["sha"]
    if resolved is None or (expected_commit is not None and resolved != expected_commit):
        raise EvidenceStorageError("evidence release tag does not bind the exact commit")
    return resolved


def verify_release(
    api: GitHubEvidenceAPI,
    *,
    repository: str,
    contract: dict[str, Any],
    tag: str,
    expected_commit: str | None,
    expected: dict[str, tuple[int, str]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], str]:
    release = api.evidence_release_by_tag(repository, tag)
    if (
        release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("immutable") is not True
        or release.get("prerelease") is not True
    ):
        raise EvidenceStorageError("GitHub evidence release is not an immutable prerelease")
    parse_utc(release.get("published_at"), label="evidence release published_at")
    target_commit = release_target(api, repository, tag, expected_commit)
    assets = asset_inventory(release)
    if set(assets) != set(expected):
        raise EvidenceStorageError("GitHub evidence release assets differ from the manifest")
    for name, (size, digest) in expected.items():
        asset = assets[name]
        if (
            asset.get("state") != "uploaded"
            or asset.get("size") != size
            or provider_digest(asset.get("digest")) != f"sha256:{digest}"
        ):
            raise EvidenceStorageError("GitHub evidence release asset identity mismatch")
        if contract["provider"]["attestation_required"] and not api.attestations(
            repository, f"sha256:{digest}"
        ):
            raise EvidenceStorageError("GitHub evidence release asset lacks attestation")
    return release, assets, target_commit


def publish_release_assets(
    api: GitHubEvidenceAPI,
    *,
    repository: str,
    contract: dict[str, Any],
    tag: str,
    target_commit: str,
    body: str,
    paths: dict[str, Path],
    reusable: bool,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], str]:
    expected = {
        name: (path.stat().st_size, file_sha256(path)) for name, path in paths.items()
    }
    try:
        release = api.evidence_release_by_tag(repository, tag)
    except GitHubAPIError as exc:
        if "returned 404" not in str(exc):
            raise
        try:
            release = api.create_evidence_draft_release(
                repository,
                tag=tag,
                target_commit=target_commit,
                body=body,
            )
        except GitHubAPIError as create_exc:
            if "returned 422" not in str(create_exc):
                raise
            release = api.evidence_release_by_tag(repository, tag)
    if (
        release.get("tag_name") != tag
        or release.get("prerelease") is not True
        or release.get("draft") not in {True, False}
    ):
        raise EvidenceStorageError("GitHub evidence draft identity is inconsistent")
    if release.get("draft") is True:
        assets = asset_inventory(release)
        if set(assets) - set(expected):
            raise EvidenceStorageError("draft evidence release contains undeclared assets")
        release_id = release.get("id")
        upload_url = str(release.get("upload_url", ""))
        for name, path in paths.items():
            if name in assets:
                item = assets[name]
                if item.get("size") != expected[name][0] or provider_digest(
                    item.get("digest")
                ) != f"sha256:{expected[name][1]}":
                    raise EvidenceStorageError(
                        "draft evidence release asset is contradictory"
                    )
                continue
            try:
                api.upload_evidence_asset(
                    upload_url=upload_url,
                    repository=repository,
                    release_id=release_id,
                    name=name,
                    path=path,
                    maximum_bytes=int(contract["provider"]["max_asset_bytes"]),
                )
            except GitHubAPIError as upload_exc:
                if "returned 422" not in str(upload_exc):
                    raise
                observed = api.evidence_release_by_tag(repository, tag)
                observed_asset = asset_inventory(observed).get(name)
                if observed_asset is None or (
                    observed_asset.get("size") != expected[name][0]
                    or provider_digest(observed_asset.get("digest"))
                    != f"sha256:{expected[name][1]}"
                ):
                    raise EvidenceStorageError(
                        "concurrent evidence publication produced contradictory bytes"
                    ) from upload_exc
        release = api.evidence_release_by_tag(repository, tag)
        if release.get("draft") is True:
            release = api.publish_release(repository, release_id)
    resolved_target = None if reusable else target_commit
    return verify_release(
        api,
        repository=repository,
        contract=contract,
        tag=tag,
        expected_commit=resolved_target,
        expected=expected,
    )
