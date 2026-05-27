"""Validate core YAML governance artifacts for the template governance pack."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]


class GovernanceValidationError(ValueError):
    """Raised when governance artifacts are syntactically valid but semantically inconsistent."""


PLACEHOLDER_PATTERN = re.compile(r"(?<!\$)\{\{[^{}\n]+\}\}")
WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")
MAKE_TARGET_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?:\s|$)")
MAKE_INVOKED_TARGET_PATTERN = re.compile(r"(?:\$\((?:MAKE|make)\)|\bmake)\s+([A-Za-z0-9_.-]+)")
OPTIONAL_PLACEHOLDER_SCAN_PATHS = (
    "docs/OPERATIONS.md",
    "governance/REPO_CLEANUP.md",
    "governance/EXISTING_REPO_ADOPTION.md",
    "governance/existing-repo-adoption.yml",
    "Makefile.fragment",
    ".github/workflows/governance.yml",
    "phases/phase-NN-hotfixNN.yml",
)
OBSERVABILITY_CONTRACT_PATHS = (
    "contracts/observability/v1/telemetry.contract.yml",
    "contracts/observability/v1/logging.contract.yml",
)
OBSERVABILITY_CONTRACT_SCHEMA = "observability-contract.schema.json"
ARTIFACT_MANIFEST_SCHEMA = "artifact-manifest.schema.json"
REPO_CLEANUP_CONTRACT_SCHEMA = "repo-cleanup-contract.schema.json"
PHASE_HISTORY_SCHEMA = "phase-history.schema.json"
SCHEMA_ROOT = "schemas"
PHASE_CLOSEOUT_STATUSES = {"verified", "closed"}
PHASE_HISTORY_STATUSES = {"completed", "verified", "closed", "abandoned"}
ACTIVE_PHASE_LIFECYCLE_STATUSES = {
    "planned",
    "active",
    "blocked",
    "paused",
    "completed",
    "verified",
    "closed",
    "abandoned",
}
COMPLETED_RELEASE_TRAIN_STATUSES = {"completed", "closed", "released"}
HOTFIX_MODES = {"lite", "full"}
VALIDATION_OUTPUT_FORMATS = {"text", "json"}
RELEASE_GATE_PLACEHOLDER_MARKERS = (
    "replace with repo",
    "configure repo-specific",
    "placeholder",
)
RELEASE_GATE_REQUIRED_STATUSES = {"required"}
RELEASE_GATE_CONFIGURED_IF_INVOKED_STATUSES = {"required", "optional"}
RELEASE_GATE_INACTIVE_STATUSES = {"deferred", "not_applicable"}
RELEASE_GATE_MEANINGLESS_VERSION_PATTERN = re.compile(
    r"\b(?:python3?|pytest|node|npm|pnpm|yarn|ruff|mypy|pyright|go|cargo)\s+(?:--version|-V|version)\b"
)
RELEASE_GATE_POLICY_MARKERS = {
    "governance_validation": ("validate_governance_yaml.py", "bcf validate", "governance-validate"),
    "governance_exposure_scan": ("check_governance_exposure.py", "governance-exposure-scan"),
    "architecture_tests": ("architecture",),
    "architecture_module_size": ("architecture-module-size", "production_modules_respect_loc_cap", "module_size"),
    "architecture_layer_membership": (
        "architecture-layer-membership",
        "production_modules_map_to_exactly_one_layer",
        "layer_membership",
    ),
    "architecture_context_membership": (
        "architecture-context-membership",
        "production_modules_map_to_exactly_one_bounded_context",
        "context_membership",
    ),
    "architecture_import_boundaries": (
        "architecture-import-boundaries",
        "boundary",
        "import_boundaries",
        "do_not_import",
    ),
    "architecture_cqrs_side": ("architecture-cqrs-side", "cqrs", "command_side", "query_side"),
    "architecture_router_thinness": ("architecture-router-thinness", "routers_remain_thin", "router_thinness"),
    "architecture_duplication": ("architecture-duplication", "duplication", "bounded_context_duplication"),
    "lint": ("ruff", "flake8", "pylint", "eslint", "biome", "clippy", "golangci-lint"),
    "typecheck": ("mypy", "pyright", "pyre", "tsc", "typecheck"),
    "automated_tests": ("pytest", "go test", "cargo test", "npm test", "pnpm test", "yarn test"),
    "contract_tests": ("contract",),
    "security_secret_scan": ("gitleaks", "trufflehog", "detect-secrets", "secret"),
    "security_dependency_audit": ("pip-audit", "safety", "npm audit", "osv", "cargo audit"),
    "security_sbom": ("syft", "cyclonedx", "sbom"),
    "security_vulnerability_scan": ("trivy", "grype", "semgrep", "vulnerability"),
    "runtime_smoke": ("smoke", "docker", "compose", "health"),
}
DEFAULT_RELEASE_GATE_TARGETS = {
    "governance-validate",
    "governance-exposure-scan",
    "architecture-test",
    "architecture-module-size",
    "architecture-layer-membership",
    "architecture-context-membership",
    "architecture-import-boundaries",
    "architecture-cqrs-side",
    "architecture-router-thinness",
    "architecture-duplication",
    "lint",
    "typecheck",
    "test",
    "contract-test",
    "security-secret-scan",
    "security-dependency-audit",
    "security-sbom",
    "security-vulnerability-scan",
    "runtime-smoke",
}
DEFAULT_RELEASE_GATE_POLICIES = {
    "governance-validate": "governance_validation",
    "governance-exposure-scan": "governance_exposure_scan",
    "architecture-test": "architecture_tests",
    "architecture-module-size": "architecture_module_size",
    "architecture-layer-membership": "architecture_layer_membership",
    "architecture-context-membership": "architecture_context_membership",
    "architecture-import-boundaries": "architecture_import_boundaries",
    "architecture-cqrs-side": "architecture_cqrs_side",
    "architecture-router-thinness": "architecture_router_thinness",
    "architecture-duplication": "architecture_duplication",
    "lint": "lint",
    "typecheck": "typecheck",
    "test": "automated_tests",
    "contract-test": "contract_tests",
    "security-secret-scan": "security_secret_scan",
    "security-dependency-audit": "security_dependency_audit",
    "security-sbom": "security_sbom",
    "security-vulnerability-scan": "security_vulnerability_scan",
    "runtime-smoke": "runtime_smoke",
}
MANDATORY_STRUCTURAL_GATE_TARGETS = (
    "architecture-module-size",
    "architecture-layer-membership",
    "architecture-context-membership",
    "architecture-import-boundaries",
    "architecture-cqrs-side",
    "architecture-router-thinness",
    "architecture-duplication",
)
GOVERNANCE_MARKER_FILENAMES = {
    "AGENTS.yml",
    "CLAUDE.md",
    "MEMORY.yml",
    "architecture-boundaries.yml",
    "governance-profile.yml",
}
GOVERNANCE_MARKER_DIRS = {"plans", "phases"}
AUDIT_PATH_COMPONENTS = {"audit", "audits"}
CLOSED_WORKITEM_STATUSES = {"done", "complete", "completed", "verified", "closed"}
SKIPPED_DISCOVERY_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "artifacts",
    ".artifacts",
    "build",
    "dist",
    "node_modules",
    "venv",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise GovernanceValidationError(f"missing required path {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise GovernanceValidationError(f"{path} must deserialize to a mapping")
    return payload


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise GovernanceValidationError(f"missing required path {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GovernanceValidationError(f"{path} must contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise GovernanceValidationError(f"{path} must deserialize to a mapping")
    return payload


def _require_mapping(value: object, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GovernanceValidationError(f"{context} must be a mapping")
    return value


def _require_sequence(value: object, *, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise GovernanceValidationError(f"{context} must be a sequence")
    return value


def _require_string(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise GovernanceValidationError(f"{context} must be a non-empty string")
    return value


def _require_positive_int(value: object, *, context: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise GovernanceValidationError(f"{context} must be a positive integer") from exc
    if number <= 0:
        raise GovernanceValidationError(f"{context} must be a positive integer")
    return number


def _require_non_negative_int(value: object, *, context: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise GovernanceValidationError(f"{context} must be a non-negative integer") from exc
    if number < 0:
        raise GovernanceValidationError(f"{context} must be a non-negative integer")
    return number


def _require_string_sequence(
    value: object,
    *,
    context: str,
    min_items: int = 0,
    max_items: int | None = None,
) -> list[str]:
    sequence = _require_sequence(value, context=context)
    strings = [
        _require_string(item, context=f"{context}[{index}]")
        for index, item in enumerate(sequence, start=1)
    ]
    if len(strings) < min_items:
        raise GovernanceValidationError(f"{context} must contain at least {min_items} item(s)")
    if max_items is not None and len(strings) > max_items:
        raise GovernanceValidationError(f"{context} must contain at most {max_items} item(s)")
    return strings


def _validate_portable_relative_path(value: str, *, context: str) -> None:
    if Path(value).is_absolute() or WINDOWS_ABSOLUTE_PATH_PATTERN.match(value):
        raise GovernanceValidationError(f"{context} must be a repo-relative path, not an absolute path")
    if "\\" in value:
        raise GovernanceValidationError(f"{context} must use POSIX '/' separators")
    if any(part == ".." for part in value.split("/")):
        raise GovernanceValidationError(f"{context} must not escape the repository root")


def _repo_relative_path(repo_root: Path, path: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise GovernanceValidationError(f"{path} is outside repo root {repo_root}") from exc


def _require_path(repo_root: Path, relative_path: str, *, context: str) -> Path:
    _validate_portable_relative_path(relative_path, context=context)
    path = repo_root / relative_path
    if not path.exists():
        raise GovernanceValidationError(f"{context} references missing path {relative_path}")
    return path


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    deduped: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(path)
    return deduped


def _relative_display(repo_root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _iter_repo_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [name for name in dirnames if name not in SKIPPED_DISCOVERY_DIRS]
        root_path = Path(current_root)
        for filename in filenames:
            files.append(root_path / filename)
    return files


def _normalized_prefix(value: str) -> str:
    _validate_portable_relative_path(value, context="repo relative prefix")
    return value.rstrip("/")


def _relative_path_is_under(relative_path: str, prefix: str) -> bool:
    normalized = _normalized_prefix(prefix)
    return relative_path == normalized or relative_path.startswith(f"{normalized}/")


def _relative_path_is_under_any(relative_path: str, prefixes: list[str]) -> bool:
    return any(_relative_path_is_under(relative_path, prefix) for prefix in prefixes)


def _active_phase_id(repo_root: Path) -> str | None:
    ledger_path = repo_root / "plans" / "phase-ledger.yml"
    if not ledger_path.exists():
        return None
    try:
        ledger = _load_yaml(ledger_path)
    except GovernanceValidationError:
        return None
    active_phase = ledger.get("active_phase")
    if not isinstance(active_phase, dict):
        return None
    phase_id = active_phase.get("id")
    return phase_id if isinstance(phase_id, str) and phase_id else None


def _classify_failure(error: GovernanceValidationError) -> dict[str, str]:
    message = str(error)
    checks = {"schema": "pass", "semantic": "pass", "placeholders": "pass"}
    if "failed structural schema" in message:
        checks["schema"] = "fail"
        checks["semantic"] = "not_run"
        checks["placeholders"] = "not_run"
        return checks
    if "unresolved template placeholders remain" in message:
        checks["placeholders"] = "fail"
        return checks
    checks["semantic"] = "fail"
    checks["placeholders"] = "not_run"
    return checks


def _success_report(repo_root: Path, *, allow_placeholders: bool) -> dict[str, Any]:
    return {
        "status": "pass",
        "checks": {
            "schema": "pass",
            "semantic": "pass",
            "placeholders": "skipped" if allow_placeholders else "pass",
        },
        "active_phase": _active_phase_id(repo_root),
    }


def _failure_report(repo_root: Path, error: GovernanceValidationError) -> dict[str, Any]:
    return {
        "status": "fail",
        "checks": _classify_failure(error),
        "active_phase": _active_phase_id(repo_root),
        "error": str(error),
    }


def _emit_output(
    report: dict[str, Any],
    *,
    output_format: str,
    compact: bool,
    default_text: str | None = None,
) -> None:
    if output_format == "text":
        if default_text is not None:
            print(default_text)
            return
        print(report["error"], file=sys.stderr)
        return
    separators = (",", ":") if compact else None
    indent = None if compact else 2
    print(json.dumps(report, indent=indent, separators=separators, sort_keys=True))


def _load_schema(
    repo_root: Path, schema_name: str, schema_cache: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if schema_name not in schema_cache:
        schema_cache[schema_name] = _load_json(repo_root / SCHEMA_ROOT / schema_name)
    return schema_cache[schema_name]


def _schema_error_location(context: str, error: object) -> str:
    path = ".".join(str(token) for token in getattr(error, "absolute_path"))
    return f"{context}.{path}" if path else context


def _validate_schema(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    payload: dict[str, Any],
    *,
    schema_name: str,
    context: str,
) -> None:
    schema = _load_schema(repo_root, schema_name, schema_cache)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: ([str(token) for token in error.absolute_path], error.message),
    )
    if not errors:
        return
    first_error = errors[0]
    raise GovernanceValidationError(
        f"{_schema_error_location(context, first_error)} failed structural schema "
        f"{SCHEMA_ROOT}/{schema_name}: {first_error.message}"
    )


def _document_status(payload: dict[str, Any], *, context: str) -> str:
    document = _require_mapping(payload.get("document"), context=f"{context}.document")
    status = document.get("status")
    if not isinstance(status, str):
        raise GovernanceValidationError(f"{context}.document.status must be a string")
    return status


def _validate_document_path(
    repo_root: Path,
    payload: dict[str, Any],
    actual_path: Path,
    *,
    context: str,
) -> None:
    document = _require_mapping(payload.get("document"), context=f"{context}.document")
    document_path = _require_string(document.get("path"), context=f"{context}.document.path")
    _validate_portable_relative_path(document_path, context=f"{context}.document.path")
    expected_path = _repo_relative_path(repo_root, actual_path)
    if document_path != expected_path:
        raise GovernanceValidationError(
            f"{context}.document.path must be {expected_path!r}, got {document_path!r}"
        )


def _validate_no_unresolved_placeholders(repo_root: Path, paths: list[Path]) -> None:
    violations: list[str] = []
    for path in _dedupe_paths(paths):
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in PLACEHOLDER_PATTERN.finditer(line):
                violations.append(
                    f"{_relative_display(repo_root, path)}:{line_number}: {match.group(0)}"
                )

    if violations:
        preview_limit = 50
        preview = "\n".join(violations[:preview_limit])
        remainder = len(violations) - preview_limit
        suffix = f"\n... and {remainder} more" if remainder > 0 else ""
        raise GovernanceValidationError(
            "unresolved template placeholders remain in governed artifacts:\n"
            f"{preview}{suffix}"
        )


def _load_governance_profile(
    repo_root: Path, schema_cache: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any] | None, Path | None]:
    profile_path = repo_root / "governance-profile.yml"
    if not profile_path.exists():
        return None, None
    profile = _load_yaml(profile_path)
    _validate_schema(
        repo_root,
        schema_cache,
        profile,
        schema_name="governance-profile.schema.json",
        context=str(profile_path),
    )
    _validate_document_path(repo_root, profile, profile_path, context=str(profile_path))
    return profile, profile_path


def _load_architecture_boundaries(
    repo_root: Path, schema_cache: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any] | None, Path | None]:
    architecture_path = repo_root / "architecture-boundaries.yml"
    if not architecture_path.exists():
        return None, None
    architecture_rules = _load_yaml(architecture_path)
    _validate_schema(
        repo_root,
        schema_cache,
        architecture_rules,
        schema_name="architecture-boundaries.schema.json",
        context=str(architecture_path),
    )
    _validate_document_path(
        repo_root, architecture_rules, architecture_path, context=str(architecture_path)
    )
    return architecture_rules, architecture_path


def _load_artifact_manifest(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    profile: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, Path | None]:
    if profile is None:
        return None, None
    drift_guardrails = _require_mapping(
        profile.get("drift_guardrails"), context="governance-profile.yml drift_guardrails"
    )
    manifest_rel = _require_string(
        drift_guardrails.get("artifact_manifest"),
        context="governance-profile.yml drift_guardrails.artifact_manifest",
    )
    manifest_path = _require_path(
        repo_root,
        manifest_rel,
        context="governance-profile.yml drift_guardrails.artifact_manifest",
    )
    manifest = _load_yaml(manifest_path)
    _validate_schema(
        repo_root,
        schema_cache,
        manifest,
        schema_name=ARTIFACT_MANIFEST_SCHEMA,
        context=str(manifest_path),
    )
    _validate_document_path(repo_root, manifest, manifest_path, context=str(manifest_path))
    return manifest, manifest_path



__all__ = [name for name in globals() if not name.startswith("__")]
