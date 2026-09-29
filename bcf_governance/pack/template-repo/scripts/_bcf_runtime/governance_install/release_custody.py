"""Authenticated release custody for ordinary adopter installation."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request
import zipfile

from jsonschema import Draft202012Validator

from ..ci_github_downloads import open_download
from ..ci_github_artifacts import provider_digest
from ..release_asset_inventory import (
    exact_assets,
    release_asset_paths,
    release_asset_version,
)
from .preservation import preserved_consumer_inventory


OFFICIAL_RELEASE_REPOSITORY = "mjgolaszewski/bcf-governance"
MAXIMUM_WHEEL_BYTES = 100 * 1024 * 1024
MAXIMUM_WHEEL_MEMBERS = 5_000
MAXIMUM_WHEEL_EXPANDED_BYTES = 100 * 1024 * 1024


class ReleaseCustodyError(ValueError):
    """Raised when release or installed-runtime custody is not exact."""


class ReleaseProvider(Protocol):
    def repository(self, repository: str) -> dict[str, Any]: ...
    def immutable_releases(self, repository: str) -> dict[str, Any]: ...
    def reference(self, repository: str, ref: str) -> dict[str, Any]: ...
    def tag_object(self, repository: str, sha: str) -> dict[str, Any]: ...
    def release_by_tag(self, repository: str, tag: str) -> dict[str, Any]: ...
    def attestations(self, repository: str, digest: str) -> tuple[dict[str, Any], ...]: ...


class ReadOnlyReleaseProvider:
    """Closed GitHub GET client for official immutable release inspection."""

    def __init__(self, token: str, *, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise ReleaseCustodyError("GITHUB_TOKEN is required for release custody")
        if api_url != "https://api.github.com":
            raise ReleaseCustodyError("release custody API must be canonical GitHub HTTPS")
        self._token = token
        self._api_url = api_url

    def _get(self, path: str) -> dict[str, Any]:
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise ReleaseCustodyError("release custody API path is unsafe")
        request = Request(
            self._api_url + path,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "bcf-governance-release-custody",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with open_download(request, timeout=30) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
        except (HTTPError, OSError, URLError) as exc:
            raise ReleaseCustodyError(f"release custody GET failed: {path}") from exc
        if len(raw) > 4 * 1024 * 1024:
            raise ReleaseCustodyError("release custody response exceeds size limit")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ReleaseCustodyError("release custody response is not JSON") from exc
        if not isinstance(payload, dict):
            raise ReleaseCustodyError("release custody response must be an object")
        return payload

    @staticmethod
    def _repository(repository: str) -> str:
        if repository != OFFICIAL_RELEASE_REPOSITORY:
            raise ReleaseCustodyError("release custody repository is not official BCF")
        return repository

    def repository(self, repository: str) -> dict[str, Any]:
        return self._get(f"/repos/{self._repository(repository)}")

    def immutable_releases(self, repository: str) -> dict[str, Any]:
        return self._get(f"/repos/{self._repository(repository)}/immutable-releases")

    def reference(self, repository: str, ref: str) -> dict[str, Any]:
        if not re.fullmatch(r"tags/v[0-9][A-Za-z0-9.]*", ref):
            raise ReleaseCustodyError("release custody tag reference is invalid")
        return self._get(f"/repos/{self._repository(repository)}/git/ref/{quote(ref)}")

    def tag_object(self, repository: str, sha: str) -> dict[str, Any]:
        if re.fullmatch(r"[a-f0-9]{40}", sha) is None:
            raise ReleaseCustodyError("release custody tag object is invalid")
        return self._get(f"/repos/{self._repository(repository)}/git/tags/{sha}")

    def release_by_tag(self, repository: str, tag: str) -> dict[str, Any]:
        if not re.fullmatch(r"v[0-9][A-Za-z0-9.]*", tag):
            raise ReleaseCustodyError("release custody tag is invalid")
        return self._get(
            f"/repos/{self._repository(repository)}/releases/tags/{quote(tag)}"
        )

    def attestations(self, repository: str, digest: str) -> tuple[dict[str, Any], ...]:
        if re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
            raise ReleaseCustodyError("release custody attestation digest is invalid")
        payload = self._get(
            f"/repos/{self._repository(repository)}/attestations/{digest}"
        )
        values = payload.get("attestations")
        if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
            raise ReleaseCustodyError("release custody attestations are malformed")
        return tuple(values)


@dataclass(frozen=True)
class ReleaseCustody:
    version: str
    source_commit: str
    repository_id: int
    release_id: int
    release_url: str
    wheel_sha256: str
    source_archive_sha256: str
    checksum_manifest_sha256: str
    released_template_files: dict[str, bytes]


@dataclass(frozen=True)
class UpgradeReleaseCustody:
    """Prepared custody and preservation inputs for one atomic upgrade."""

    release: ReleaseCustody | None
    preserved: dict[str, str]

    @property
    def excluded_paths(self) -> frozenset[str]:
        return frozenset(self.preserved)

    def project(
        self,
        target_root: Path,
        manifest_entries: dict[str, dict[str, Any]],
        upgrade_paths: tuple[str, ...],
        placeholder_values: dict[str, str],
    ) -> None:
        project_upgrade_runtime_lock(
            target_root,
            custody=self.release,
            manifest_entries=manifest_entries,
            upgrade_paths=upgrade_paths,
            preserved=self.preserved,
            placeholder_values=placeholder_values,
        )


def _positive_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ReleaseCustodyError(f"{label} must be a positive integer")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _wheel_template_files(wheel: Path) -> dict[str, bytes]:
    if wheel.stat().st_size > MAXIMUM_WHEEL_BYTES:
        raise ReleaseCustodyError("release wheel exceeds size limit")
    prefix = "bcf_governance/pack/template-repo/"
    files: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = archive.infolist()
            if len(members) > MAXIMUM_WHEEL_MEMBERS or sum(
                member.file_size for member in members
            ) > MAXIMUM_WHEEL_EXPANDED_BYTES:
                raise ReleaseCustodyError("release wheel expansion exceeds limits")
            names: set[str] = set()
            for member in members:
                if member.filename in names:
                    raise ReleaseCustodyError("release wheel contains duplicate members")
                names.add(member.filename)
                if member.is_dir() or not member.filename.startswith(prefix):
                    continue
                relative = member.filename.removeprefix(prefix)
                path = Path(relative)
                mode = member.external_attr >> 16
                if (
                    not relative
                    or path.is_absolute()
                    or ".." in path.parts
                    or (mode & 0o170000) == 0o120000
                ):
                    raise ReleaseCustodyError("release wheel template member is unsafe")
                files[path.as_posix()] = archive.read(member)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReleaseCustodyError("release wheel is unreadable") from exc
    manifest_bytes = files.pop(".bcf-pack-manifest.json", None)
    if manifest_bytes is None:
        raise ReleaseCustodyError("release wheel lacks its pack manifest")
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise ReleaseCustodyError("release wheel pack manifest is invalid") from exc
    declared = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(declared, dict) or set(declared) != set(files):
        raise ReleaseCustodyError("release wheel pack inventory differs from manifest")
    for relative, value in declared.items():
        digest = value.get("sha256") if isinstance(value, dict) else None
        if digest != _sha256_bytes(files[relative]):
            raise ReleaseCustodyError("release wheel pack digest differs from manifest")
    return files


def _provider_source_commit(api: ReleaseProvider, repository: str, tag: str) -> str:
    reference = api.reference(repository, f"tags/{tag}")
    target = reference.get("object")
    if not isinstance(target, dict) or target.get("type") != "tag":
        raise ReleaseCustodyError("release tag must be annotated")
    tag_sha = target.get("sha")
    tag_object = api.tag_object(repository, str(tag_sha))
    commit = tag_object.get("object")
    verification = tag_object.get("verification")
    if (
        tag_object.get("tag") != tag
        or not isinstance(commit, dict)
        or commit.get("type") != "commit"
        or re.fullmatch(r"[a-f0-9]{40}", str(commit.get("sha"))) is None
        or not isinstance(verification, dict)
        or verification.get("verified") is not False
        or verification.get("reason") != "unsigned"
    ):
        raise ReleaseCustodyError("release tag identity does not match BCF policy")
    return str(commit["sha"])


def prepare_release_custody(
    assets_root: Path,
    *,
    installed_version: str,
    template_root: Path,
    token: str,
    api: ReleaseProvider | None = None,
) -> ReleaseCustody:
    """Authenticate one immutable BCF release before repository mutation."""

    paths = release_asset_paths(assets_root.resolve())
    version = release_asset_version(paths)
    if version.value != installed_version:
        raise ReleaseCustodyError("release assets differ from the executing BCF version")
    assets = exact_assets(paths)
    wheel = next(path for path in paths if path.suffix == ".whl")
    sdist = next(path for path in paths if path.name.endswith(".tar.gz"))
    sums = next(path for path in paths if path.name == "SHA256SUMS")
    released_files = _wheel_template_files(wheel)
    local_files = {
        path.relative_to(template_root).as_posix(): path.read_bytes()
        for path in sorted(template_root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
        and path.name != ".bcf-pack-manifest.json"
    }
    if local_files != released_files:
        raise ReleaseCustodyError("executing BCF template bytes differ from release wheel")

    provider = api or ReadOnlyReleaseProvider(token)
    repository = OFFICIAL_RELEASE_REPOSITORY
    repo = provider.repository(repository)
    if repo.get("full_name") != repository:
        raise ReleaseCustodyError("release provider repository identity is not exact")
    repository_id = _positive_integer(repo.get("id"), "release repository ID")
    if provider.immutable_releases(repository).get("enabled") is not True:
        raise ReleaseCustodyError("official BCF immutable releases are not enabled")
    source_commit = _provider_source_commit(provider, repository, version.tag)
    release = provider.release_by_tag(repository, version.tag)
    expected_url = f"https://github.com/{repository}/releases/tag/{version.tag}"
    if (
        release.get("tag_name") != version.tag
        or release.get("immutable") is not True
        or release.get("draft") is not False
        or release.get("prerelease") is not version.prerelease
        or release.get("html_url") != expected_url
    ):
        raise ReleaseCustodyError("official BCF release state is not exact")
    observed: dict[str, str] = {}
    for item in release.get("assets", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ReleaseCustodyError("official BCF release asset inventory is malformed")
        name = str(item["name"])
        if name in observed or item.get("state") != "uploaded":
            raise ReleaseCustodyError("official BCF release asset inventory is ambiguous")
        observed[name] = provider_digest(item.get("digest")).removeprefix("sha256:")
    if observed != assets:
        raise ReleaseCustodyError("local assets differ from immutable BCF release")
    for digest in observed.values():
        if not provider.attestations(repository, f"sha256:{digest}"):
            raise ReleaseCustodyError("official BCF release asset lacks attestation")
    return ReleaseCustody(
        version=version.value,
        source_commit=source_commit,
        repository_id=repository_id,
        release_id=_positive_integer(release.get("id"), "release ID"),
        release_url=expected_url,
        wheel_sha256=assets[wheel.name],
        source_archive_sha256=assets[sdist.name],
        checksum_manifest_sha256=assets[sums.name],
        released_template_files=released_files,
    )


def _project_bytes(raw: bytes, values: dict[str, str]) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    for key, value in values.items():
        text = text.replace(f"{{{{{key}}}}}", value)
    return text.encode("utf-8")


def write_runtime_lock(
    target_root: Path,
    *,
    custody: ReleaseCustody,
    manifest_entries: dict[str, dict[str, Any]],
    upgrade_paths: tuple[str, ...],
    preserved: dict[str, str],
    placeholder_values: dict[str, str],
) -> None:
    """Project exact provider and installed-byte custody into one canonical lock."""

    def selected(relative: str) -> bool:
        path = Path(relative)
        return any(path == Path(root) or path.is_relative_to(Path(root)) for root in upgrade_paths)

    files: dict[str, str] = {}
    adaptations: dict[str, dict[str, str]] = {}
    expected = {
        relative
        for relative, entry in manifest_entries.items()
        if selected(relative)
        and entry.get("installation_scope", "ordinary_adopter") == "ordinary_adopter"
        and relative not in preserved
    }
    if not expected:
        raise ReleaseCustodyError("release custody runtime inventory is empty")
    for relative in sorted(expected):
        path = target_root / relative
        released = custody.released_template_files.get(relative)
        if released is None or not path.is_file() or path.is_symlink():
            raise ReleaseCustodyError(f"installed release runtime is incomplete: {relative}")
        installed = path.read_bytes()
        projected = _project_bytes(released, placeholder_values)
        if installed != projected:
            raise ReleaseCustodyError(f"installed release runtime differs from projection: {relative}")
        installed_digest = _sha256_bytes(installed)
        files[relative] = installed_digest
        released_digest = _sha256_bytes(released)
        if released_digest != installed_digest:
            adaptations[relative] = {
                "released_sha256": released_digest,
                "installed_sha256": installed_digest,
                "reason": "Canonical installer substitutes declared template values in the installed consumer runtime.",
            }
    payload = {
        "schema_version": "1.0",
        "version": custody.version,
        "source_repository": OFFICIAL_RELEASE_REPOSITORY,
        "source_repository_id": custody.repository_id,
        "source_commit": custody.source_commit,
        "release_id": custody.release_id,
        "release_url": custody.release_url,
        "wheel_sha256": custody.wheel_sha256,
        "source_archive_sha256": custody.source_archive_sha256,
        "checksum_manifest_sha256": custody.checksum_manifest_sha256,
        "official_installer_adaptations": adaptations,
        "files": files,
        "preserved_consumer_files": dict(sorted(preserved.items())),
    }
    lock = target_root / "governance/bcf-runtime-lock.json"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def validate_installed_runtime_lock(
    repo_root: Path, *, expected_version: str, schema_path: Path
) -> dict[str, Any]:
    """Validate typed lock shape, version, and every exact installed byte."""

    lock_path = repo_root / "governance/bcf-runtime-lock.json"
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseCustodyError("BCF runtime lock or schema is unreadable") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise ReleaseCustodyError(f"BCF runtime lock schema violation: {errors[0].message}")
    if payload["version"] != expected_version:
        raise ReleaseCustodyError("BCF runtime lock version differs from executing BCF")
    inventories = (payload["files"], payload["preserved_consumer_files"])
    overlap = set(inventories[0]) & set(inventories[1])
    if overlap:
        raise ReleaseCustodyError("BCF runtime lock ownership inventories overlap")
    for inventory in inventories:
        for relative, expected in inventory.items():
            path = repo_root / relative
            if not path.is_file() or path.is_symlink() or _sha256_bytes(path.read_bytes()) != expected:
                raise ReleaseCustodyError(f"BCF runtime lock byte mismatch: {relative}")
    return payload


def release_custody_requested(assets: Path | None) -> bool:
    return assets is not None


def prepare_upgrade_release_custody(
    target_root: Path,
    release_assets: Path | None,
    upgrade: bool,
    template_root: Path,
    api: ReleaseProvider | None = None,
) -> UpgradeReleaseCustody:
    """Fail before mutation unless an upgrade can advance existing custody."""

    if release_assets is not None and not upgrade:
        raise RuntimeError("--release-assets requires --upgrade")
    lock = target_root / "governance/bcf-runtime-lock.json"
    release_bound = False
    if lock.is_file() and not lock.is_symlink():
        try:
            payload = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("BCF runtime lock is unreadable before upgrade") from exc
        release_bound = isinstance(payload, dict) and "version" in payload
    if upgrade and release_bound and release_assets is None:
        raise RuntimeError(
            "release-bound upgrade requires --release-assets; stale custody cannot be preserved"
        )
    if release_assets is None:
        return UpgradeReleaseCustody(None, preserved_consumer_inventory(target_root))
    from bcf_governance import __version__

    release = prepare_release_custody(
        release_assets,
        installed_version=__version__,
        template_root=template_root,
        token=os.environ.get("GITHUB_TOKEN", ""),
        api=api,
    )
    return UpgradeReleaseCustody(release, preserved_consumer_inventory(target_root))


def project_upgrade_runtime_lock(
    target_root: Path,
    *,
    custody: ReleaseCustody | None,
    manifest_entries: dict[str, dict[str, Any]],
    upgrade_paths: tuple[str, ...],
    preserved: dict[str, str],
    placeholder_values: dict[str, str],
) -> None:
    """Project custody only when exact release inputs authorized this upgrade."""

    if custody is not None:
        write_runtime_lock(
            target_root,
            custody=custody,
            manifest_entries=manifest_entries,
            upgrade_paths=tuple(dict.fromkeys(upgrade_paths)),
            preserved=preserved,
            placeholder_values=placeholder_values,
        )
