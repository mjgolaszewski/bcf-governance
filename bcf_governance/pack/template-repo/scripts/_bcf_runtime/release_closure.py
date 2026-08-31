"""Closed release dependency and archive verification contracts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
import tarfile
from typing import Any
import zipfile

import yaml


class ReleaseClosureError(ValueError):
    """Raised when release inputs are open, unsafe, or not exact."""


@dataclass(frozen=True)
class WheelhouseVerification:
    python: str
    platform: str
    lock_sha256: str
    wheels: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": "verified",
            "python": self.python,
            "platform": self.platform,
            "lock_sha256": self.lock_sha256,
            "wheels": dict(self.wheels),
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseClosureError("wheelhouse manifest must be a regular file")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReleaseClosureError("wheelhouse manifest is invalid YAML") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "subject", "resolution", "wheels",
    }:
        raise ReleaseClosureError("wheelhouse manifest top-level inventory is not exact")
    if payload["schema_version"] != "1.0":
        raise ReleaseClosureError("wheelhouse manifest schema version is unsupported")
    subject = payload["subject"]
    resolution = payload["resolution"]
    wheels = payload["wheels"]
    if not all(isinstance(value, dict) for value in (subject, resolution, wheels)):
        raise ReleaseClosureError("wheelhouse manifest sections must be mappings")
    if subject != {
        "python": "3.12.14",
        "implementation": "CPython",
        "operating_system": "ubuntu-24.04",
        "platform": "linux_x86_64",
        "wheel_platform": "manylinux_2_17_x86_64",
        "abi": "cp312",
    }:
        raise ReleaseClosureError("release interpreter and platform identity are not exact")
    for filename, digest in wheels.items():
        if (
            not isinstance(filename, str)
            or Path(filename).name != filename
            or not filename.endswith(".whl")
            or not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
        ):
            raise ReleaseClosureError("wheelhouse filename or digest is unsafe")
    if not wheels:
        raise ReleaseClosureError("wheelhouse manifest is empty")
    return payload


def verify_release_lock(manifest_path: Path, lock_path: Path) -> WheelhouseVerification:
    """Verify that one lock closes exactly the hashes named by its wheel manifest."""

    payload = _load_manifest(manifest_path)
    if lock_path.is_symlink() or not lock_path.is_file():
        raise ReleaseClosureError("release lock must be a regular file")
    lock_digest = _sha256(lock_path)
    resolution = payload["resolution"]
    if resolution.get("lock_sha256") != lock_digest:
        raise ReleaseClosureError("release lock digest does not match manifest")
    lines = [
        value.strip() for value in lock_path.read_text(encoding="utf-8").splitlines()
        if value.strip() and not value.lstrip().startswith("#")
    ]
    if not lines or any("==" not in value for value in lines):
        raise ReleaseClosureError("every release dependency must be exactly versioned")
    hashes: list[str] = []
    names: list[str] = []
    for line in lines:
        matches = re.findall(r"--hash=sha256:([a-f0-9]{64})(?:\s|$)", line)
        if len(matches) != 1:
            raise ReleaseClosureError("every release dependency must have one admitted hash")
        hashes.extend(matches)
        names.append(re.split(r"==", line, maxsplit=1)[0].lower().replace("_", "-"))
    if len(set(names)) != len(names):
        raise ReleaseClosureError("release lock contains duplicate distributions")
    wheels = payload["wheels"]
    if set(hashes) != set(wheels.values()) or len(hashes) != len(wheels):
        raise ReleaseClosureError("release lock and wheel manifest are not an exact closure")
    return WheelhouseVerification(
        python=str(payload["subject"]["python"]),
        platform=str(payload["subject"]["platform"]),
        lock_sha256=lock_digest,
        wheels=tuple(sorted((str(key), str(value)) for key, value in wheels.items())),
    )


def verify_wheelhouse(
    manifest_path: Path, lock_path: Path, wheelhouse: Path
) -> WheelhouseVerification:
    """Verify a nonsymlink wheelhouse has the exact admitted filenames and bytes."""

    result = verify_release_lock(manifest_path, lock_path)
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise ReleaseClosureError("wheelhouse must be a regular directory")
    actual: dict[str, Path] = {}
    for path in wheelhouse.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ReleaseClosureError("wheelhouse entries must be regular files")
        actual[path.name] = path
    expected = dict(result.wheels)
    if set(actual) != set(expected):
        raise ReleaseClosureError("wheelhouse file inventory is not exact")
    for name, digest in expected.items():
        if _sha256(actual[name]) != digest:
            raise ReleaseClosureError(f"wheelhouse digest mismatch: {name}")
    return result


def _safe_member(name: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or "\x00" in name
    ):
        raise ReleaseClosureError(f"unsafe archive member: {name!r}")


def verify_archive(path: Path) -> tuple[str, ...]:
    """Reject path escapes, links, devices, and ambiguous members in wheel or sdist."""

    if path.is_symlink() or not path.is_file():
        raise ReleaseClosureError("release archive must be a regular file")
    members: list[str] = []
    if path.suffix == ".whl":
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    _safe_member(info.filename)
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == 0o120000:
                        raise ReleaseClosureError("wheel cannot contain symbolic links")
                    members.append(info.filename)
        except zipfile.BadZipFile as exc:
            raise ReleaseClosureError("wheel archive is invalid") from exc
    elif path.name.endswith(".tar.gz"):
        try:
            with tarfile.open(path, mode="r:gz") as archive:
                for tar_info in archive.getmembers():
                    _safe_member(tar_info.name)
                    if not (tar_info.isfile() or tar_info.isdir()):
                        raise ReleaseClosureError(
                            "source distribution cannot contain links or special files"
                        )
                    members.append(tar_info.name)
        except tarfile.TarError as exc:
            raise ReleaseClosureError("source distribution archive is invalid") from exc
    else:
        raise ReleaseClosureError("release archive type is unsupported")
    if not members or len(set(members)) != len(members):
        raise ReleaseClosureError("release archive member inventory is empty or duplicated")
    return tuple(members)
