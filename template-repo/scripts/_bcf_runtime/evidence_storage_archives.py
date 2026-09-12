"""Build and materialize deterministic, bounded evidence-input archives."""

from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile
from typing import Any, IO

from .evidence_storage_contracts import EvidenceStorageError


MEDIA_TYPE = "application/vnd.bcf.evidence-input.tar+gzip"


@dataclass(frozen=True)
class InputSpec:
    id: str
    source_path: str
    target_path: str
    freshness_class: str
    observed_at_utc: str | None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(value: str, *, label: str) -> Path:
    posix = PurePosixPath(value)
    if (
        not value
        or posix.is_absolute()
        or posix.as_posix() != value
        or ".." in posix.parts
        or any(part in {"", "."} for part in posix.parts)
    ):
        raise EvidenceStorageError(f"{label} must be one safe repository-relative path")
    return Path(*posix.parts)


def _source(repo_root: Path, relative: str) -> Path:
    path = _safe_relative(relative, label="evidence input source")
    candidate = repo_root / path
    root = repo_root.resolve()
    cursor = root
    for part in path.parts:
        cursor /= part
        if cursor.is_symlink():
            raise EvidenceStorageError(
                f"evidence input source is missing or symlinked: {relative}"
            )
    if not candidate.exists():
        raise EvidenceStorageError(f"evidence input source is missing or symlinked: {relative}")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise EvidenceStorageError(f"evidence input source escapes the repository: {relative}")
    return candidate


def _entries(source: Path) -> tuple[tuple[Path, str], ...]:
    if source.is_file():
        return ((source, "root"),)
    if not source.is_dir():
        raise EvidenceStorageError("evidence input source must be a regular file or directory")
    entries: list[tuple[Path, str]] = [(source, "root")]
    for current_root, directories, files in os.walk(source, topdown=True, followlinks=False):
        current = Path(current_root)
        directories.sort()
        files.sort()
        for name in directories + files:
            path = current / name
            if path.is_symlink():
                raise EvidenceStorageError(
                    f"evidence input contains a symlink: {path.relative_to(source)}"
                )
            relative = path.relative_to(source).as_posix()
            entries.append((path, f"root/{relative}"))
    return tuple(entries)


def _member(path: Path, archive_path: str) -> dict[str, Any]:
    metadata = path.lstat()
    if stat.S_ISREG(metadata.st_mode):
        kind = "file"
        size = metadata.st_size
        digest = _sha256_file(path)
    elif stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
        size = 0
        digest = None
    else:
        raise EvidenceStorageError(f"evidence input contains a special file: {archive_path}")
    return {
        "path": archive_path,
        "kind": kind,
        "mode": stat.S_IMODE(metadata.st_mode),
        "size": size,
        "sha256": digest,
    }


def _tar_info(member: dict[str, Any]) -> tarfile.TarInfo:
    info = tarfile.TarInfo(str(member["path"]))
    info.mode = int(member["mode"])
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = int(member["size"])
    info.type = tarfile.DIRTYPE if member["kind"] == "directory" else tarfile.REGTYPE
    info.pax_headers = {}
    return info


def build_archive(
    repo_root: Path,
    spec: InputSpec,
    output_dir: Path,
    safety: dict[str, Any],
) -> tuple[dict[str, Any], Path]:
    """Create one canonical archive and return its exact manifest entry."""

    source = _source(repo_root.resolve(), spec.source_path)
    _safe_relative(spec.target_path, label="evidence input target")
    entries = _entries(source)
    if len(entries) > int(safety["maximum_members"]):
        raise EvidenceStorageError("evidence input exceeds the member limit")
    members = [_member(path, archive_path) for path, archive_path in entries]
    expanded = sum(int(item["size"]) for item in members)
    if expanded > int(safety["maximum_expanded_bytes"]):
        raise EvidenceStorageError("evidence input exceeds the expanded-byte limit")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_dir.is_symlink():
        raise EvidenceStorageError("evidence input output directory must not be symlinked")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{spec.id}.", suffix=".tar.gz.tmp", dir=output_dir
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for (path, _), member in zip(entries, members, strict=True):
                        info = _tar_info(member)
                        if member["kind"] == "file":
                            with path.open("rb") as stream:
                                archive.addfile(info, stream)
                        else:
                            archive.addfile(info)
            raw.flush()
            os.fsync(raw.fileno())
        archive_size = temporary.stat().st_size
        if archive_size < 1 or archive_size > int(safety.get("maximum_asset_bytes", 2**63 - 1)):
            raise EvidenceStorageError("evidence input archive exceeds the asset-byte limit")
        digest = _sha256_file(temporary)
        asset_name = f"sha256-{digest}.tar.gz"
        destination = output_dir / asset_name
        if destination.exists():
            if destination.is_symlink() or _sha256_file(destination) != digest:
                raise EvidenceStorageError("content-addressed archive collision")
            temporary.unlink()
        else:
            temporary.replace(destination)
            destination.chmod(0o600)
        return (
            {
                "id": spec.id,
                "target_path": spec.target_path,
                "root_kind": "file" if source.is_file() else "directory",
                "asset_name": asset_name,
                "media_type": MEDIA_TYPE,
                "archive_sha256": digest,
                "archive_size": archive_size,
                "expanded_size": expanded,
                "members": members,
                "freshness": {
                    "class": spec.freshness_class,
                    "observed_at_utc": spec.observed_at_utc,
                },
            },
            destination,
        )
    finally:
        if temporary.exists():
            temporary.unlink()


def _safe_member_name(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or ".." in path.parts
        or not path.parts
        or path.parts[0] != "root"
        or any(part in {"", "."} for part in path.parts)
    ):
        raise EvidenceStorageError(f"unsafe evidence input archive member: {value}")
    return path


def _copy_bounded(source: IO[bytes], destination: IO[bytes], expected: int) -> str:
    digest = hashlib.sha256()
    remaining = expected
    while remaining:
        chunk = source.read(min(1024 * 1024, remaining))
        if not chunk:
            raise EvidenceStorageError("evidence input archive member is truncated")
        destination.write(chunk)
        digest.update(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise EvidenceStorageError("evidence input archive member exceeds its declared size")
    return digest.hexdigest()


def materialize_archive(
    archive_path: Path,
    item: dict[str, Any],
    output_root: Path,
    safety: dict[str, Any],
) -> Path:
    """Verify every original byte and atomically materialize one declared target."""

    if archive_path.is_symlink() or not archive_path.is_file():
        raise EvidenceStorageError("evidence input archive must be one regular nonsymlink file")
    if archive_path.stat().st_size != int(item["archive_size"]) or _sha256_file(
        archive_path
    ) != item["archive_sha256"]:
        raise EvidenceStorageError("evidence input archive identity mismatch")
    compressed_size = archive_path.stat().st_size
    expanded_size = int(item["expanded_size"])
    if expanded_size > int(safety["maximum_expanded_bytes"]) or (
        expanded_size > compressed_size * int(safety["maximum_expansion_ratio"])
    ):
        raise EvidenceStorageError("evidence input archive expansion exceeds policy")
    target_relative = _safe_relative(item["target_path"], label="evidence input target")
    root = output_root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_root.is_symlink():
        raise EvidenceStorageError("evidence materialization root must not be symlinked")
    target = root / target_relative
    if target.exists() or target.is_symlink():
        raise EvidenceStorageError(f"evidence input target already exists: {target_relative}")
    expected = {member["path"]: member for member in item["members"]}
    if len(expected) != len(item["members"]) or len(expected) > int(
        safety["maximum_members"]
    ):
        raise EvidenceStorageError("evidence input member inventory is ambiguous or oversized")
    with tempfile.TemporaryDirectory(prefix="bcf-evidence-materialize-", dir=root) as temp_name:
        staging = Path(temp_name)
        observed: set[str] = set()
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                name = _safe_member_name(member.name).as_posix()
                if name in observed or name not in expected:
                    raise EvidenceStorageError("evidence input archive has extra or duplicate members")
                observed.add(name)
                declaration = expected[name]
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise EvidenceStorageError("evidence input archive contains an unsafe member")
                kind = "directory" if member.isdir() else "file" if member.isfile() else "unsupported"
                if kind != declaration["kind"] or stat.S_IMODE(member.mode) != int(
                    declaration["mode"]
                ) or member.size != int(declaration["size"]):
                    raise EvidenceStorageError("evidence input archive member metadata mismatch")
                relative = Path(*PurePosixPath(name).parts)
                destination = staging / relative
                if kind == "directory":
                    destination.mkdir(parents=True, exist_ok=False)
                    destination.chmod(int(declaration["mode"]))
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise EvidenceStorageError("evidence input archive file is unreadable")
                with destination.open("xb") as output:
                    digest = _copy_bounded(stream, output, int(declaration["size"]))
                if digest != declaration["sha256"]:
                    raise EvidenceStorageError("evidence input archive member digest mismatch")
                destination.chmod(int(declaration["mode"]))
        if observed != set(expected):
            raise EvidenceStorageError("evidence input archive is missing declared members")
        staged_root = staging / "root"
        if item["root_kind"] == "file" and not staged_root.is_file():
            raise EvidenceStorageError("evidence input root kind mismatch")
        if item["root_kind"] == "directory" and not staged_root.is_dir():
            raise EvidenceStorageError("evidence input root kind mismatch")
        target.parent.mkdir(parents=True, exist_ok=True)
        if any(part.is_symlink() for part in [target.parent, *target.parents] if part != root.parent):
            raise EvidenceStorageError("evidence input target parent is symlinked")
        staged_root.replace(target)
    return target


def materialize_bundle(
    manifest: dict[str, Any], archive_root: Path, output_root: Path, safety: dict[str, Any]
) -> tuple[Path, ...]:
    return tuple(
        materialize_archive(archive_root / item["asset_name"], item, output_root, safety)
        for item in manifest["objects"]
    )
