"""Validate core YAML governance artifacts for the template governance pack."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


class GovernanceValidationError(ValueError):
    """Raised when governance artifacts are syntactically valid but semantically inconsistent."""


PLACEHOLDER_PATTERN = re.compile(r"\{\{[^{}\n]+\}\}")
OPTIONAL_PLACEHOLDER_SCAN_PATHS = (
    "docs/OPERATIONS.md",
    "Makefile.fragment",
    ".github/workflows/governance.yml",
)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise GovernanceValidationError(f"missing required path {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
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


def _require_path(repo_root: Path, relative_path: str, *, context: str) -> Path:
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


def _document_status(payload: dict[str, Any], *, context: str) -> str:
    document = _require_mapping(payload.get("document"), context=f"{context}.document")
    status = document.get("status")
    if not isinstance(status, str):
        raise GovernanceValidationError(f"{context}.document.status must be a string")
    return status


def _validate_agents(repo_root: Path, agents: dict[str, Any]) -> None:
    governance = _require_mapping(agents.get("governance"), context="AGENTS.yml governance")
    semantic = _require_mapping(
        governance.get("semantic_validation_contract"),
        context="AGENTS.yml governance.semantic_validation_contract",
    )
    if semantic.get("validator") != "scripts/validate_governance_yaml.py":
        raise GovernanceValidationError(
            "AGENTS.yml governance.semantic_validation_contract.validator must be "
            "scripts/validate_governance_yaml.py"
        )
    references = _require_mapping(agents.get("references"), context="AGENTS.yml references")
    for key in (
        "canonical_product_spec",
        "canonical_build_plan",
        "canonical_active_ledger",
        "canonical_memory",
        "governance_validator",
    ):
        value = references.get(key)
        if not isinstance(value, str):
            raise GovernanceValidationError(f"AGENTS.yml references.{key} must be a string")
        _require_path(repo_root, value, context=f"AGENTS.yml references.{key}")


def _validate_active_phase(
    repo_root: Path, ledger: dict[str, Any], memory: dict[str, Any]
) -> list[Path]:
    active_phase = _require_mapping(
        ledger.get("active_phase"), context="plans/phase-ledger.yml active_phase"
    )
    phase_id = active_phase.get("id")
    if not isinstance(phase_id, str):
        raise GovernanceValidationError("plans/phase-ledger.yml active_phase.id must be a string")

    plan_path = _require_path(repo_root, str(active_phase.get("plan")), context="active_phase.plan")
    workitems_path = _require_path(
        repo_root, str(active_phase.get("workitems")), context="active_phase.workitems"
    )
    log_path = _require_path(repo_root, str(active_phase.get("log")), context="active_phase.log")
    _require_path(repo_root, str(active_phase.get("memory")), context="active_phase.memory")
    _require_path(repo_root, str(active_phase.get("spec")), context="active_phase.spec")
    _require_path(repo_root, str(active_phase.get("build_plan")), context="active_phase.build_plan")

    plan = _load_yaml(plan_path)
    workitems = _load_yaml(workitems_path)
    log = _load_yaml(log_path)

    plan_phase = _require_mapping(plan.get("phase"), context=f"{plan_path} phase")
    if plan_phase.get("id") != phase_id:
        raise GovernanceValidationError(f"{plan_path} phase.id must match active phase {phase_id}")
    if plan_phase.get("build_block") != active_phase.get("build_block"):
        raise GovernanceValidationError(f"{plan_path} phase.build_block must match active phase")

    workitems_document = _require_mapping(
        workitems.get("document"), context=f"{workitems_path} document"
    )
    if workitems_document.get("phase_id") != phase_id:
        raise GovernanceValidationError(
            f"{workitems_path} document.phase_id must match active phase {phase_id}"
        )

    log_phase = _require_mapping(log.get("phase"), context=f"{log_path} phase")
    if log_phase.get("id") != phase_id:
        raise GovernanceValidationError(f"{log_path} phase.id must match active phase {phase_id}")
    if log_phase.get("build_block") != active_phase.get("build_block"):
        raise GovernanceValidationError(f"{log_path} phase.build_block must match active phase")

    environment_facts = _require_mapping(
        memory.get("environment_facts"), context="MEMORY.yml environment_facts"
    )
    active_artifacts = _require_mapping(
        environment_facts.get("active_artifacts"),
        context="MEMORY.yml environment_facts.active_artifacts",
    )
    expected_memory_paths = {
        "spec": active_phase.get("spec"),
        "build_plan": active_phase.get("build_plan"),
        "active_phase_ledger": "plans/phase-ledger.yml",
        "active_phase_plan": active_phase.get("plan"),
        "active_workitem_ledger": active_phase.get("workitems"),
        "active_phase_log": active_phase.get("log"),
    }
    for key, expected in expected_memory_paths.items():
        if active_artifacts.get(key) != expected:
            raise GovernanceValidationError(
                f"MEMORY.yml active_artifacts.{key} must be {expected!r}"
            )

    closeout_statuses = {"verified", "closed"}
    if _document_status(log, context=str(log_path)) in closeout_statuses:
        for field in (
            "all_tickets_closed",
            "required_suites_green",
            "ast_architecture_gates_green",
            "health_checks_green",
            "known_warnings",
            "known_constraints",
        ):
            if field not in log:
                raise GovernanceValidationError(f"{log_path} missing closeout field {field}")
        _require_sequence(log["required_suites_green"], context=f"{log_path} required_suites_green")
        _require_sequence(log["known_warnings"], context=f"{log_path} known_warnings")
        _require_sequence(log["known_constraints"], context=f"{log_path} known_constraints")

    return [plan_path, workitems_path, log_path]


def validate_repo_root(repo_root: Path, *, allow_placeholders: bool = False) -> None:
    agents = _load_yaml(repo_root / "AGENTS.yml")
    memory = _load_yaml(repo_root / "MEMORY.yml")
    product_spec_path = repo_root / "plans" / "product-spec.yml"
    build_plan_path = repo_root / "plans" / "build-plan.yml"
    _load_yaml(product_spec_path)
    _load_yaml(build_plan_path)
    ledger = _load_yaml(repo_root / "plans" / "phase-ledger.yml")
    _validate_agents(repo_root, agents)
    active_phase_paths = _validate_active_phase(repo_root, ledger, memory)

    if not allow_placeholders:
        optional_paths = [
            repo_root / relative_path
            for relative_path in OPTIONAL_PLACEHOLDER_SCAN_PATHS
            if (repo_root / relative_path).exists()
        ]
        _validate_no_unresolved_placeholders(
            repo_root,
            [
                repo_root / "AGENTS.yml",
                repo_root / "MEMORY.yml",
                product_spec_path,
                build_plan_path,
                repo_root / "plans" / "phase-ledger.yml",
                *active_phase_paths,
                *optional_paths,
            ],
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate governed YAML artifacts.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--allow-placeholders",
        action="store_true",
        help="Allow unresolved {{PLACEHOLDER}} tokens while validating the uninstantiated template pack.",
    )
    args = parser.parse_args()
    validate_repo_root(args.repo_root.resolve(), allow_placeholders=args.allow_placeholders)
    print("governance-yaml-ok")


if __name__ == "__main__":
    main()
