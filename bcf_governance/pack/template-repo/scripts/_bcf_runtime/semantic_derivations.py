"""Mechanical provenance checks for secondary semantic representations.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .semantic_ownership_registry import Registry


class SemanticDerivationError(ValueError):
    """Raised when a secondary representation lacks reproducible provenance."""


@dataclass(frozen=True)
class DerivationEvaluation:
    projection_outputs: tuple[dict[str, str], ...]
    derived_count: int
    exception_count: int


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_file(repo_root: Path, value: object, *, context: str) -> Path:
    if not isinstance(value, str) or not value:
        raise SemanticDerivationError(f"{context} must be a non-empty repository path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise SemanticDerivationError(f"{context} escapes the repository")
    target = repo_root / relative
    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        raise SemanticDerivationError(f"{context} is unreadable: {exc}") from exc
    if not resolved.is_relative_to(repo_root.resolve()) or target.is_symlink():
        raise SemanticDerivationError(f"{context} resolves outside the repository")
    if not target.is_file():
        raise SemanticDerivationError(f"{context} must identify a regular file")
    return target


def _canonical_source(roots: list[str], mirror: str) -> str:
    candidates = [root for root in roots if Path(root).name == Path(mirror).name]
    if len(candidates) == 1:
        return candidates[0]
    if len(roots) == 1:
        return roots[0]
    raise SemanticDerivationError(f"generated mirror {mirror} has ambiguous canonical source")


def legacy_generated_projections(
    repo_root: Path, registry: Registry
) -> list[dict[str, str]]:
    """Decode existing generated-source declarations as provenance, without duplication."""
    outputs: dict[str, dict[str, str]] = {}
    for entry in registry.entries:
        authority = entry.raw.get("generated_source_authority", {})
        roots = [str(value) for value in authority.get("authoritative_roots", [])]
        recipe = f"{authority.get('generator', '')}\n{authority.get('parity_proof', '')}".encode()
        for root in roots:
            _safe_file(repo_root, root, context=f"{entry.semantic_id} authoritative root")
        for raw_mirror in authority.get("generated_mirrors", []):
            mirror = str(raw_mirror)
            source = _canonical_source(roots, mirror)
            source_path = _safe_file(
                repo_root, source, context=f"{entry.semantic_id} canonical source"
            )
            output_path = _safe_file(
                repo_root, mirror, context=f"{entry.semantic_id} generated mirror"
            )
            if source_path.read_bytes() != output_path.read_bytes():
                raise SemanticDerivationError(
                    f"stale generated projection {mirror} differs from {source}"
                )
            row = {
                "path": mirror,
                "canonical_source": source,
                "recipe_sha256": _digest(recipe),
                "source_sha256": _digest(source_path.read_bytes()),
                "output_sha256": _digest(output_path.read_bytes()),
            }
            previous = outputs.get(mirror)
            if previous is not None and previous != row:
                raise SemanticDerivationError(
                    f"generated projection {mirror} has competing provenance"
                )
            outputs[mirror] = row
    return [outputs[key] for key in sorted(outputs)]


def _validate_tracked_argv(repo_root: Path, argv: list[str], context: str) -> None:
    if not argv or any("\x00" in value for value in argv):
        raise SemanticDerivationError(f"{context} must be a non-empty NUL-free argv")
    program = Path(argv[0])
    if program.is_absolute() or ".." in program.parts:
        raise SemanticDerivationError(f"{context} program must be repository-relative")
    if len(argv) > 1 and program.name.startswith("python"):
        _safe_file(repo_root, argv[1], context=f"{context} tracked program")
    elif "/" in argv[0] or argv[0].endswith((".py", ".sh")):
        _safe_file(repo_root, argv[0], context=f"{context} tracked program")


def _tree_hashes(root: Path, omitted: set[str]) -> dict[str, str]:
    ignored = {".git", ".artifacts", ".venv", "__pycache__", "node_modules"}
    rows: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in ignored for part in relative.parts) or relative.as_posix() in omitted:
            continue
        if path.is_symlink():
            raise SemanticDerivationError(
                f"derivation worktree contains a symlink: {relative.as_posix()}"
            )
        if path.is_file():
            rows[relative.as_posix()] = _digest(path.read_bytes())
    return rows


def _reproduce_outputs(
    repo_root: Path, entry: dict[str, Any], argv: list[str], outputs: list[str]
) -> None:
    with tempfile.TemporaryDirectory(prefix="bcf-semantic-derivation-") as temporary:
        shadow = Path(temporary) / "repo"
        shutil.copytree(
            repo_root,
            shadow,
            symlinks=True,
            ignore=shutil.ignore_patterns(
                ".git", ".artifacts", ".venv", "__pycache__", "node_modules"
            ),
        )
        omitted = set(outputs)
        before = _tree_hashes(shadow, omitted)
        for output in outputs:
            path = shadow / output
            if path.exists():
                path.unlink()
        command = [sys.executable, *argv[1:]] if Path(argv[0]).name.startswith("python") else argv
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            command,
            cwd=shadow,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise SemanticDerivationError(
                f"derived representation {entry['id']} recipe failed: {detail}"
            )
        if _tree_hashes(shadow, omitted) != before:
            raise SemanticDerivationError(
                f"derived representation {entry['id']} recipe changed undeclared files"
            )
        for output in outputs:
            reproduced = _safe_file(
                shadow, output, context=f"derived {entry['id']} reproduced output"
            )
            current = _safe_file(
                repo_root, output, context=f"derived {entry['id']} output"
            )
            if reproduced.read_bytes() != current.read_bytes():
                raise SemanticDerivationError(
                    f"derived representation {entry['id']} cannot reproduce {output}"
                )


def validate_explicit_provenance(
    repo_root: Path, registry: Registry, inventory: dict[str, Any]
) -> tuple[list[dict[str, str]], int, int]:
    entries = registry.raw.get("secondary_representations", [])
    ids = [str(row["id"]) for row in entries]
    duplicates = sorted({value for value in ids if ids.count(value) > 1})
    if duplicates:
        raise SemanticDerivationError(
            "secondary representation IDs must be unique: " + ", ".join(duplicates)
        )
    canonical_ids = {entry.semantic_id for entry in registry.entries}
    output_owners: dict[str, str] = {}
    projections: list[dict[str, str]] = []
    derived_count = 0
    exception_count = 0
    function_symbols = {str(row["symbol"]) for row in inventory.get("functions", [])}
    canonical_by_id = {entry.semantic_id: entry for entry in registry.entries}
    for entry in entries:
        if entry["classification"] == "exception":
            exception_count += 1
            if entry.get("expires_on") and date.fromisoformat(str(entry["expires_on"])) < date.today():
                raise SemanticDerivationError(f"representation exception {entry['id']} is expired")
            for index, location in enumerate(entry["locations"]):
                _safe_file(repo_root, location, context=f"exception {entry['id']} locations[{index}]")
                previous = output_owners.get(str(location))
                if previous is not None:
                    raise SemanticDerivationError(
                        f"secondary representation {location} is owned by both "
                        f"{previous} and {entry['id']}"
                    )
                output_owners[str(location)] = str(entry["id"])
            continue
        derived_count += 1
        if entry["canonical_semantic_id"] not in canonical_ids:
            raise SemanticDerivationError(f"derived representation {entry['id']} has no canonical source")
        sources = [str(value) for value in entry["source_inputs"]]
        outputs = [str(value) for value in entry["outputs"]]
        for index, source in enumerate(sources):
            _safe_file(repo_root, source, context=f"derived {entry['id']} source_inputs[{index}]")
        for output in outputs:
            previous = output_owners.get(output)
            if previous is not None:
                raise SemanticDerivationError(
                    f"secondary output {output} is owned by both {previous} and {entry['id']}"
                )
            output_owners[output] = str(entry["id"])
            _safe_file(repo_root, output, context=f"derived {entry['id']} output")
        recipe = entry["recipe"]
        if recipe["kind"] == "tracked_command":
            argv = [str(value) for value in recipe["argv"]]
            _validate_tracked_argv(repo_root, argv, f"derived {entry['id']} recipe.argv")
            program_index = 1 if Path(argv[0]).name.startswith("python") else 0
            program = _safe_file(
                repo_root,
                argv[program_index],
                context=f"derived {entry['id']} recipe program",
            )
            recipe_identity = (
                json.dumps(argv, separators=(",", ":")).encode() + program.read_bytes()
            )
            _reproduce_outputs(repo_root, entry, argv, outputs)
        elif recipe["kind"] == "runtime_symbol":
            if recipe["symbol"] not in function_symbols:
                raise SemanticDerivationError(
                    f"derived {entry['id']} runtime recipe symbol is absent"
                )
            canonical = canonical_by_id[str(entry["canonical_semantic_id"])]
            authorized_runtime_roles = {
                canonical.owner_symbol,
                *canonical.authorized_constructors,
                *canonical.authorized_delegates,
                str(canonical.raw["hostile_boundary_decoder"]["symbol"]),
                str(canonical.raw["persistence_codec_and_envelope"]["codec_symbol"]),
                *(
                    str(row["owner"])
                    for row in canonical.raw["intentional_projections"]
                ),
            }
            if recipe["symbol"] not in authorized_runtime_roles:
                raise SemanticDerivationError(
                    f"derived {entry['id']} runtime recipe is not an authorized "
                    "constructor, codec, decoder, delegate, or projection"
                )
            recipe_identity = str(recipe["symbol"]).encode()
        else:
            recipe_identity = str(recipe["identity"]).encode()
        source_material = b"".join((repo_root / source).read_bytes() for source in sources)
        for output in outputs:
            projections.append({
                "path": output,
                "canonical_source": sources[0],
                "recipe_sha256": _digest(recipe_identity),
                "source_sha256": _digest(source_material),
                "output_sha256": _digest((repo_root / output).read_bytes()),
            })
    return projections, derived_count, exception_count


def collect_provenance(
    repo_root: Path, registry: Registry, inventory: dict[str, Any]
) -> DerivationEvaluation:
    legacy = legacy_generated_projections(repo_root, registry)
    explicit, derived_count, exception_count = validate_explicit_provenance(
        repo_root, registry, inventory
    )
    projections: dict[str, dict[str, str]] = {}
    for row in [*legacy, *explicit]:
        path = row["path"]
        if path in projections:
            raise SemanticDerivationError(
                f"secondary representation {path} has competing legacy and explicit provenance"
            )
        projections[path] = row
    return DerivationEvaluation(
        projection_outputs=tuple(projections[key] for key in sorted(projections)),
        derived_count=len(legacy) + derived_count,
        exception_count=exception_count,
    )
