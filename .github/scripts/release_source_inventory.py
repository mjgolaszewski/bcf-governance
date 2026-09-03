"""Prove that a source distribution contains its Git-owned source checkout."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import subprocess
import tarfile


def tracked_source_inventory(repo_root: Path) -> frozenset[str]:
    """Return the exact Git-owned source inventory."""

    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("source inventory requires Git custody")
    values = result.stdout.split(b"\0")
    if values and values[-1] == b"":
        values.pop()
    try:
        tracked = frozenset(value.decode("utf-8") for value in values)
    except UnicodeDecodeError as exc:
        raise ValueError("tracked source path is not UTF-8") from exc
    if not tracked:
        raise ValueError("source inventory is empty")
    return tracked


def sdist_source_inventory(sdist: Path) -> frozenset[str]:
    """Return safe regular-file paths beneath an archive's single source root."""

    try:
        with tarfile.open(sdist, "r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("source archive is unreadable") from exc
    roots: set[str] = set()
    files: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or len(path.parts) < 1:
            raise ValueError("source archive contains an unsafe path")
        roots.add(path.parts[0])
        if member.isfile() and len(path.parts) > 1:
            files.add(PurePosixPath(*path.parts[1:]).as_posix())
    if len(roots) != 1:
        raise ValueError("source archive must have one top-level directory")
    return frozenset(files)


def validate_sdist_source_inventory(repo_root: Path, sdist: Path) -> None:
    """Reject an sdist that omits any Git-owned source file."""

    missing = sorted(tracked_source_inventory(repo_root) - sdist_source_inventory(sdist))
    if missing:
        raise ValueError("source archive omits tracked source: " + ", ".join(missing))
