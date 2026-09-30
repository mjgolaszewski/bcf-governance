"""Derive canonical governance-pack removal roots from installer ownership."""

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


def governed_pack_removal_roots() -> tuple[str, ...]:
    """Return minimal removable roots without deleting merged or preserved files."""

    retained = {*PRESERVED_REQUIRED_ARTIFACTS, ".gitignore"}
    candidates = sorted(
        (path for path in INSTALL_MANAGED_PATHS if path not in retained),
        key=lambda value: (len(PurePosixPath(value).parts), value),
    )
    roots: list[str] = []
    for candidate in candidates:
        if _covered(candidate, roots):
            continue
        roots.append(candidate)
    entries = _pack_manifest_entries(_template_root())
    uncovered = sorted(
        path
        for path, entry in entries.items()
        if entry.get("installation_scope", "ordinary_adopter") == "ordinary_adopter"
        and entry["operation"] not in {"merge", "preserve"}
        and not _covered(path, roots)
    )
    if uncovered:
        raise ValueError(
            "installer removal ownership omits manifest paths: " + ", ".join(uncovered)
        )
    return tuple(roots)
