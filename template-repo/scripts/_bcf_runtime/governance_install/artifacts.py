"""Application-owned artifact preservation and merge helpers."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path


def merge_gitignore(existing: bytes | None, template: bytes) -> bytes:
    begin = b"# BEGIN BCF GOVERNANCE"
    end = b"# END BCF GOVERNANCE"
    template_lines = [
        line
        for line in template.decode("utf-8").splitlines()
        if line.strip()
        and line.strip() not in {begin.decode("ascii"), end.decode("ascii")}
    ]
    block = b"\n".join(
        [begin, *[line.encode("utf-8") for line in template_lines], end]
    ) + b"\n"
    original = existing or b""
    if begin in original or end in original:
        if not (
            begin in original
            and end in original
            and original.index(begin) < original.index(end)
        ):
            raise ValueError("existing .gitignore contains an incomplete BCF managed block")
        start = original.index(begin)
        suffix_start = original.index(end, start) + len(end)
        if original[suffix_start : suffix_start + 2] == b"\r\n":
            suffix_start += 2
        elif original[suffix_start : suffix_start + 1] == b"\n":
            suffix_start += 1
        return original[:start] + block + original[suffix_start:]
    separator = b"" if not original or original.endswith(b"\n\n") else (
        b"\n" if original.endswith((b"\n", b"\r\n")) else b"\n\n"
    )
    return original + separator + block


def ensure_required_artifacts(
    *,
    template_root: Path,
    target_root: Path,
    relative_paths: tuple[str, ...],
    reject_destination: Callable[[Path, Path], None],
) -> tuple[int, list[Path]]:
    destinations: list[Path] = []
    for relative_value in relative_paths:
        relative_path = Path(relative_value)
        reject_destination(target_root, relative_path)
        destination = target_root / relative_path
        if destination.exists():
            if not destination.is_file():
                raise ValueError(f"required artifact is not a regular file: {relative_value}")
            continue
        shutil.copy2(template_root / relative_path, destination)
        destinations.append(destination)
    return len(destinations), destinations
