"""Classify audit-context files without conflating product code and evidence."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .common import (
    AUDIT_PATH_COMPONENTS,
    GovernanceValidationError,
    _iter_repo_files,
    _load_yaml,
    _relative_path_is_under,
    _relative_path_is_under_any,
    _repo_relative_path,
    _require_mapping,
    _require_path,
    _require_string_sequence,
    _validate_portable_relative_path,
)


FIRST_PARTY_CODE_SUFFIXES = frozenset({".py", ".pyi", ".ts", ".tsx"})


class AuditArtifactKind(str, Enum):
    """Closed classification used by audit-root enforcement."""

    UNRELATED = "unrelated"
    CANONICAL_EVIDENCE = "canonical_evidence"
    DECLARED_VENDOR = "declared_vendor"
    FIRST_PARTY_CODE = "first_party_code"
    MISPLACED_AUDIT_ARTIFACT = "misplaced_audit_artifact"


@dataclass(frozen=True)
class AuditArtifactClassification:
    """One deterministic classification for a discovered repository file."""

    relative_path: str
    kind: AuditArtifactKind


def _validated_code_root(repo_root: Path, value: str, *, context: str) -> str:
    _validate_portable_relative_path(value, context=context)
    normalized = value.rstrip("/")
    if not normalized or any(
        part.lower() in AUDIT_PATH_COMPONENTS for part in Path(normalized).parts
    ):
        raise GovernanceValidationError(
            f"{context} must identify a first-party code root, not an audit path: {value}"
        )
    path = repo_root / normalized
    if not path.exists():
        return normalized
    if path.is_symlink() or not path.is_dir():
        raise GovernanceValidationError(
            f"{context} must reference a regular directory: {normalized}"
        )
    try:
        path.resolve(strict=True).relative_to(repo_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise GovernanceValidationError(
            f"{context} must remain within the repository: {normalized}"
        ) from exc
    return normalized


def _declared_first_party_code_roots(repo_root: Path) -> list[str]:
    architecture = _require_mapping(
        _load_yaml(repo_root / "architecture-boundaries.yml").get("architecture"),
        context="architecture-boundaries.yml architecture",
    )
    source_roots = _require_string_sequence(
        architecture.get("source_roots"),
        context="architecture-boundaries.yml architecture.source_roots",
        min_items=1,
    )
    agents = _load_yaml(repo_root / "AGENTS.yml")
    testing = _require_mapping(
        agents.get("testing_governance"), context="AGENTS.yml testing_governance"
    )
    test_roots = _require_string_sequence(
        testing.get("test_roots"),
        context="AGENTS.yml testing_governance.test_roots",
        min_items=1,
    )
    roots = [
        _validated_code_root(repo_root, value, context=context)
        for context, values in (
            ("architecture-boundaries.yml architecture.source_roots", source_roots),
            ("AGENTS.yml testing_governance.test_roots", test_roots),
        )
        for value in values
    ]
    return sorted(set(roots))


def _is_declared_first_party_code(
    repo_root: Path,
    path: Path,
    relative_path: str,
    *,
    code_roots: list[str],
) -> bool:
    if not _relative_path_is_under_any(relative_path, code_roots):
        return False
    if path.suffix.lower() not in FIRST_PARTY_CODE_SUFFIXES:
        return False
    if path.is_symlink() or not path.is_file():
        return False
    try:
        path.resolve(strict=True).relative_to(repo_root.resolve(strict=True))
    except (OSError, ValueError):
        return False
    if path.suffix.lower() in {".py", ".pyi"}:
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        except (OSError, SyntaxError, UnicodeError):
            return False
    return True


def classify_audit_context_artifact(
    repo_root: Path,
    path: Path,
    relative_path: str,
    *,
    audit_root: str,
    vendor_prefixes: list[str],
    code_roots: list[str],
) -> AuditArtifactClassification:
    """Return the sole audit-context classification for one discovered file."""

    if _relative_path_is_under(relative_path, audit_root):
        kind = AuditArtifactKind.CANONICAL_EVIDENCE
    elif _relative_path_is_under_any(relative_path, vendor_prefixes):
        kind = AuditArtifactKind.DECLARED_VENDOR
    elif not any(
        part.lower() in AUDIT_PATH_COMPONENTS
        for part in Path(relative_path).parts[:-1]
    ):
        kind = AuditArtifactKind.UNRELATED
    elif _is_declared_first_party_code(
        repo_root, path, relative_path, code_roots=code_roots
    ):
        kind = AuditArtifactKind.FIRST_PARTY_CODE
    else:
        kind = AuditArtifactKind.MISPLACED_AUDIT_ARTIFACT
    return AuditArtifactClassification(relative_path=relative_path, kind=kind)


def validate_audit_root_policy(
    repo_root: Path,
    manifest: dict[str, object],
    *,
    root_paths: dict[str, str],
    vendor_prefixes: list[str],
) -> None:
    """Enforce audit evidence custody while admitting declared product code."""

    del manifest  # The decoded root and vendor projections are the only manifest inputs.
    audit_root = root_paths.get("audits")
    if audit_root is None:
        raise GovernanceValidationError(
            "governance/artifact-manifest.yml must declare artifact_roots.audits"
        )
    _require_path(
        repo_root,
        audit_root,
        context="governance/artifact-manifest.yml artifact_roots.audits.path",
    )
    code_roots = _declared_first_party_code_roots(repo_root)

    violations: list[str] = []
    for path in _iter_repo_files(repo_root):
        relative_path = _repo_relative_path(repo_root, path)
        classification = classify_audit_context_artifact(
            repo_root,
            path,
            relative_path,
            audit_root=audit_root,
            vendor_prefixes=vendor_prefixes,
            code_roots=code_roots,
        )
        if classification.kind is AuditArtifactKind.MISPLACED_AUDIT_ARTIFACT:
            violations.append(classification.relative_path)

    if violations:
        raise GovernanceValidationError(
            "audit artifacts must live under the declared audit root "
            f"{audit_root}: " + ", ".join(sorted(violations)[:20])
        )
