"""Current candidate source-path discovery for semantic analysis."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable


def candidate_source_files(
    repo_root: Path,
    patterns: tuple[str, ...],
    *,
    label: str,
    error: Callable[[str], Exception],
    allow_empty: bool = False,
) -> list[Path]:
    """Return the Git-known files present in the proposed working tree."""
    result = subprocess.run(
        [
            "git", "ls-files", "-z", "--cached", "--others",
            "--exclude-standard", "--", *patterns,
        ],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise error(f"{label} discovery requires a Git worktree")
    files: set[Path] = set()
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = Path(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise error(f"candidate {label} path is not UTF-8") from exc
        if relative.is_absolute() or ".." in relative.parts:
            raise error(f"candidate {label} path escapes the repository")
        path = repo_root / relative
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file():
            raise error(
                f"candidate {label} source must be a regular file: "
                f"{relative.as_posix()}"
            )
        files.add(path)
    if not files and not allow_empty:
        raise error(f"{label} discovery returned zero files")
    return sorted(files)
