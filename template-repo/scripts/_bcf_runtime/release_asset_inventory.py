"""Exact release-asset and checksum inventory validation."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Iterable

from .ci_github_identity import GitHubControllerError
from .release_versions import ReleaseVersion, ReleaseVersionError, parse_release_version


_WHEEL_IDENTITY = re.compile(
    r"^(?P<distribution>[A-Za-z0-9_]+)-"
    r"(?P<version>[0-9][A-Za-z0-9.]*)-py3-none-any\.whl$"
)
_SDIST_IDENTITY = re.compile(
    r"^(?P<distribution>[A-Za-z0-9_.-]+)-"
    r"(?P<version>[0-9][A-Za-z0-9.]*)\.tar\.gz$"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_assets(paths: Iterable[Path]) -> dict[str, str]:
    assets: dict[str, str] = {}
    for path in paths:
        if path.name in assets:
            raise GitHubControllerError("release asset inventory contains duplicates")
        assets[path.name] = _sha256(path)
    if not assets:
        raise GitHubControllerError("release asset inventory is empty")
    return dict(sorted(assets.items()))


def release_asset_paths(root: Path) -> tuple[Path, ...]:
    """Select the exact closed release inventory from one safe directory."""

    if root.is_symlink() or not root.is_dir():
        raise GitHubControllerError("release asset directory must be a regular directory")
    paths = tuple(sorted(root.iterdir(), key=lambda path: path.name))
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise GitHubControllerError("release asset directory contains an unsafe member")
    release_asset_version(paths)
    return paths


def release_asset_version(paths: tuple[Path, ...]) -> ReleaseVersion:
    """Derive one canonical release version from the closed archive inventory."""

    verify_checksum_inventory(paths)
    wheel = next(path for path in paths if path.suffix == ".whl")
    sdist = next(path for path in paths if path.name.endswith(".tar.gz"))
    wheel_identity = _WHEEL_IDENTITY.fullmatch(wheel.name)
    sdist_identity = _SDIST_IDENTITY.fullmatch(sdist.name)
    if wheel_identity is None or sdist_identity is None:
        raise GitHubControllerError("release archive identity is not canonical")
    distributions = {
        re.sub(r"[-_.]+", "-", match.group("distribution")).lower()
        for match in (wheel_identity, sdist_identity)
    }
    try:
        versions = {
            parse_release_version(match.group("version"))
            for match in (wheel_identity, sdist_identity)
        }
    except ReleaseVersionError as exc:
        raise GitHubControllerError("release archive version is not canonical") from exc
    if len(distributions) != 1 or len(versions) != 1:
        raise GitHubControllerError("release wheel and source archive identity differs")
    return versions.pop()


def verify_checksum_inventory(paths: tuple[Path, ...]) -> None:
    archives = tuple(
        path for path in paths if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    checksums = tuple(path for path in paths if path.name == "SHA256SUMS")
    if len(paths) != 3 or len(archives) != 2 or len(checksums) != 1 or not any(
        path.suffix == ".whl" for path in archives
    ) or not any(path.name.endswith(".tar.gz") for path in archives):
        raise GitHubControllerError(
            "release assets must be one wheel, one source archive, and SHA256SUMS"
        )
    declared: dict[str, str] = {}
    for line in checksums[0].read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(
            r"([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,254})", line
        )
        if match is None or match.group(2) in declared:
            raise GitHubControllerError("release checksum inventory is invalid")
        declared[match.group(2)] = match.group(1)
    expected = {path.name: _sha256(path) for path in archives}
    if declared != expected:
        raise GitHubControllerError("release checksum inventory is not exact")
