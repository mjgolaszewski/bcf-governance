"""Derive exact governance-pack removal paths from installer ownership."""

from __future__ import annotations

from pathlib import PurePosixPath

from ..install_governance_pack import (
    INSTALL_MANAGED_PATHS,
    PRESERVED_REQUIRED_ARTIFACTS,
    _pack_manifest_entries,
    _template_root,
)


def _covered(path: str, roots: list[str] | tuple[str, ...]) -> bool:
    candidate = PurePosixPath(path)
    return any(
        candidate == PurePosixPath(root) or candidate.is_relative_to(root)
        for root in roots
    )


def _contains_manifest_path(root: str, paths: tuple[str, ...]) -> bool:
    return any(_covered(path, (root,)) for path in paths)


def governed_pack_removal_paths() -> tuple[str, ...]:
    """Return exact removable files without treating transaction roots as ownership."""

    retained = {*PRESERVED_REQUIRED_ARTIFACTS, ".gitignore"}
    entries = _pack_manifest_entries(_template_root())
    removable = {
        path
        for path, entry in entries.items()
        if entry.get("installation_scope", "ordinary_adopter") == "ordinary_adopter"
        and entry["operation"] not in {"merge", "preserve"}
    }
    uncovered = sorted(path for path in removable if not _covered(path, INSTALL_MANAGED_PATHS))
    if uncovered:
        raise ValueError(
            "installer removal ownership omits manifest paths: " + ", ".join(uncovered)
        )
    manifest_paths = tuple(entries)
    generated_files = {
        path
        for path in INSTALL_MANAGED_PATHS
        if path not in retained
        and not _contains_manifest_path(path, manifest_paths)
    }
    return tuple(sorted(removable | generated_files))
