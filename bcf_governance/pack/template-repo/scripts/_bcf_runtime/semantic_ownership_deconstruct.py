"""Deterministic, lossless flat-registry deconstruction into bounded local sources."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .governance_install.transaction import apply_transaction
from .semantic_ownership_layout import (
    MAX_SOURCES,
    ROOT,
    SOURCE_DIR,
    RegistryLayoutError,
    _metadata_budget,
    expand_sources,
)
from .semantic_ownership_registry import load_registry
from .semantic_yaml import load_unique_bytes, load_unique_mapping


def _render(payload: dict[str, Any]) -> bytes:
    return yaml.safe_dump(payload, sort_keys=False, width=1000, allow_unicode=True).encode()


def _clean_source(repo_root: Path) -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--", ROOT.as_posix(), SOURCE_DIR.as_posix()],
        cwd=repo_root, capture_output=True, text=True, check=False,
    )
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", ROOT.as_posix()],
        cwd=repo_root, capture_output=True, check=False,
    )
    if result.returncode or result.stdout or tracked.returncode:
        raise RegistryLayoutError("deconstruction requires a clean Git-tracked original registry")


def _planned(repo_root: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    original = load_unique_mapping(repo_root / ROOT)
    if "representation_sources" in original:
        raise RegistryLayoutError("registry is already indexed")
    before = load_registry(repo_root)
    families = {str(row["semantic_id"]): str(row["family"]) for row in original["representations"]}
    first_family = str(original["representations"][0]["family"])
    rows: list[tuple[str, str, dict[str, Any]]] = [
        ("representations", str(row["family"]), row) for row in original["representations"]
    ]
    for row in original.get("secondary_representations", []):
        family = families[str(row["canonical_semantic_id"])] if row["classification"] == "derived" else first_family
        rows.append(("secondary_representations", family, row))
    line_cap, byte_cap = _metadata_budget(repo_root)
    generated: dict[str, bytes] = {}
    refs: list[str] = []
    current_kind = ""
    current_family = ""
    current_rows: list[dict[str, Any]] = []

    def rendered(number: int, kind: str, family: str, items: list[dict[str, Any]]) -> tuple[str, bytes]:
        relative = SOURCE_DIR / f"representation-{number:04d}.yml"
        source = {
            "document": {
                "kind": "canonical_representation_source", "id": f"representation-{number:04d}",
                "version": "1.0.0", "status": "active", "path": relative.as_posix(),
                "family": family,
            },
            kind: items,
        }
        return relative.as_posix(), _render(source)

    def fits(encoded: bytes) -> bool:
        return len(encoded) <= byte_cap and len(encoded.splitlines()) <= line_cap

    def flush() -> None:
        if not current_rows:
            return
        relative, encoded = rendered(len(refs) + 1, current_kind, current_family, current_rows)
        if len(encoded) > byte_cap or len(encoded.splitlines()) > line_cap:
            raise RegistryLayoutError("representation exceeds inherited context budget")
        refs.append(relative)
        generated[relative] = encoded

    for kind, family, row in rows:
        if current_rows and (kind != current_kind or family != current_family):
            flush()
            current_rows = []
        if not current_rows:
            current_kind, current_family = kind, family
        trial = [*current_rows, row]
        _, encoded = rendered(len(refs) + 1, kind, family, trial)
        if current_rows and not fits(encoded):
            flush()
            current_rows = [row]
        else:
            current_rows = trial
        if len(refs) + 1 > MAX_SOURCES:
            raise RegistryLayoutError("deconstruction exceeds 512-source ceiling")
    flush()
    root = {key: value for key, value in original.items() if key not in {"representations", "secondary_representations"}}
    if "secondary_representations" in original and not original["secondary_representations"]:
        root["secondary_representations"] = []
    root["representation_sources"] = refs
    root_bytes = _render(root)
    if len(root_bytes) > byte_cap or len(root_bytes.splitlines()) > line_cap:
        # Render only the path list in flow style, preserving the same parsed values.
        base = _render({key: value for key, value in root.items() if key != "representation_sources"})
        root_bytes = base + ("representation_sources: [" + ", ".join(refs) + "]\n").encode()
    if len(root_bytes) > byte_cap or len(root_bytes.splitlines()) > line_cap:
        raise RegistryLayoutError("indexed registry root exceeds inherited context budget")
    if load_unique_bytes(root_bytes) != root:
        raise RegistryLayoutError("rendered registry root changed facts")
    generated[ROOT.as_posix()] = root_bytes
    logical, _ = expand_sources(
        repo_root, root,
        reader=lambda relative: generated[relative.as_posix()], check_orphans=False,
    )
    if logical != original or tuple(entry.raw for entry in before.entries) != tuple(logical["representations"]):
        raise RegistryLayoutError("deconstruction changed registry facts or order")
    return generated, {
        "status": "deconstruction_planned", "source_count": len(refs),
        "paths": sorted(generated),
        "original_sha256": hashlib.sha256((repo_root / ROOT).read_bytes()).hexdigest(),
    }


def deconstruct(repo_root: Path, *, apply: bool) -> dict[str, Any]:
    """Check a Git-backed plan or apply it transactionally with logical parity."""
    _clean_source(repo_root)
    generated, report = _planned(repo_root)
    if not apply:
        return report

    def mutate(shadow: Path) -> None:
        for relative, raw in generated.items():
            path = shadow / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        actual = load_registry(shadow)
        original = load_unique_mapping(repo_root / ROOT)
        if actual.raw != original:
            raise RegistryLayoutError("shadow registry parity failed")

    def validate_final() -> None:
        load_registry(repo_root)

    apply_transaction(
        repo_root,
        managed_paths=(ROOT.as_posix(), SOURCE_DIR.as_posix()),
        mutate_shadow=mutate,
        preserve_git_history=True,
        validate_final=validate_final,
    )
    return {**report, "status": "deconstruction_applied"}
