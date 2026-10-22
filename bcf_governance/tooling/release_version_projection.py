"""Deterministic release-version projection for governed package surfaces."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

import yaml


SURFACES = (
    (Path("manifest.yml"), "document", "version"),
    (Path("governance/public-contracts.yml"), "package", "version"),
)
TEXT_SURFACES = (Path("README.md"), Path("docs/USAGE.md"))
CURRENT_VERSION_MARKERS = (
    "Supported package version:",
    "Install the `v",
    "releases/download/v",
    "gh release download v",
    "--dir /tmp/bcf-v",
    "--release-assets /tmp/bcf-v",
)
_VERSION = re.compile(r"(?<![0-9])(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?![0-9])")


class ReleaseVersionProjectionError(ValueError):
    """Raised when a derived release version is absent, ambiguous, or stale."""


def _payload(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ReleaseVersionProjectionError(f"release version surface is unreadable: {path}") from exc
    if not isinstance(value, dict):
        raise ReleaseVersionProjectionError(f"release version surface is not an object: {path}")
    return value


def _replace_nested_scalar(path: Path, parent: str, key: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    parents = [index for index, line in enumerate(lines) if line == f"{parent}:"]
    if len(parents) != 1:
        raise ReleaseVersionProjectionError(
            f"release version parent is absent or ambiguous: {path}:{parent}"
        )
    start = parents[0] + 1
    stop = next(
        (index for index in range(start, len(lines)) if lines[index] and not lines[index].startswith(" ")),
        len(lines),
    )
    fields = [index for index in range(start, stop) if lines[index].startswith(f"  {key}:")]
    if len(fields) != 1:
        raise ReleaseVersionProjectionError(
            f"release version field is absent or ambiguous: {path}:{parent}.{key}"
        )
    lines[fields[0]] = f"  {key}: {value}"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def reconcile_release_version_surfaces(
    repo_root: Path, *, version: str, apply: bool
) -> tuple[str, ...]:
    """Check or project the package version through every mechanical owner."""

    present = tuple((repo_root / relative).exists() for relative, _, _ in SURFACES)
    if not any(present):
        return ()
    if not all(present):
        names = ", ".join(
            relative.as_posix()
            for (relative, _, _), exists in zip(SURFACES, present, strict=True)
            if not exists
        )
        raise ReleaseVersionProjectionError(
            f"release version ownership is partial; missing: {names}"
        )
    stale: list[tuple[Path, str, str]] = []
    for relative, parent, key in SURFACES:
        path = repo_root / relative
        payload = _payload(path)
        nested = payload.get(parent)
        if not isinstance(nested, dict) or nested.get(key) != version:
            stale.append((path, parent, key))
    if apply:
        for path, parent, key in stale:
            _replace_nested_scalar(path, parent, key, version)
    changed = [path.relative_to(repo_root).as_posix() for path, _, _ in stale]
    for relative in TEXT_SURFACES:
        path = repo_root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        projected = [
            _VERSION.sub(version, line)
            if any(marker in line for marker in CURRENT_VERSION_MARKERS)
            else line
            for line in lines
        ]
        rendered = "\n".join(projected) + ("\n" if text.endswith("\n") else "")
        if rendered == text:
            continue
        if not apply:
            stale.append((path, "", ""))
            continue
        path.write_text(rendered, encoding="utf-8")
        changed.append(relative.as_posix())
    if stale and not apply:
        names = ", ".join(
            dict.fromkeys(path.relative_to(repo_root).as_posix() for path, _, _ in stale)
        )
        raise ReleaseVersionProjectionError(f"release version projection is stale: {names}")
    return tuple(changed)
