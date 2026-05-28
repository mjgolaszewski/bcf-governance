"""Upgrade migration helpers for governed repos."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


def _find_target_span(lines: list[str], target: str) -> tuple[int, int] | None:
    start: int | None = None
    for index, line in enumerate(lines):
        if not line or line.startswith("\t") or line.startswith(" "):
            continue
        if not line.startswith(f"{target}:"):
            if start is not None and ":" in line:
                return start, index
            continue
        start = index
    if start is None:
        return None
    return start, len(lines)

def _replace_placeholders_in_files(paths: list[Path], values: dict[str, str]) -> None:
    for path in sorted(set(paths)):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        updated = text
        for key, value in values.items():
            updated = updated.replace(f"{{{{{key}}}}}", value)
        if updated != text:
            path.write_text(updated, encoding="utf-8")



def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}



def _write_yaml_mapping(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False, default_flow_style=None, width=4096),
        encoding="utf-8",
    )



def _template_yaml(template_root: Path, relative_path: str) -> dict[str, Any]:
    return _load_yaml_mapping(template_root / relative_path)



def _ensure_mapping(parent: dict[str, Any], key: str, template_value: object) -> dict[str, Any]:
    value = parent.get(key)
    if isinstance(value, dict):
        return value
    replacement = template_value if isinstance(template_value, dict) else {}
    parent[key] = dict(replacement)
    return parent[key]



def _ensure_list_items(target: dict[str, Any], key: str, template_items: object) -> None:
    if not isinstance(template_items, list):
        return
    current = target.get(key)
    if not isinstance(current, list):
        target[key] = list(template_items)
        return
    for item in template_items:
        if item not in current:
            current.append(item)



def _copy_template_file_if_missing(
    *,
    template_root: Path,
    target_root: Path,
    relative_path: str,
    values: dict[str, str],
) -> list[Path]:
    destination = target_root / relative_path
    if destination.exists():
        return []
    source = template_root / relative_path
    if not source.exists():
        return []
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    _replace_placeholders_in_files([destination], values)
    return [destination]



def _upgrade_agents_yaml(template_root: Path, target_root: Path) -> None:
    path = target_root / "AGENTS.yml"
    if not path.exists():
        return
    payload = _load_yaml_mapping(path)
    template = _template_yaml(template_root, "AGENTS.yml")
    governance = _ensure_mapping(payload, "governance", template.get("governance"))
    template_governance = template.get("governance") if isinstance(template.get("governance"), dict) else {}

    schema_contract = _ensure_mapping(
        governance,
        "structural_schema_contract",
        template_governance.get("structural_schema_contract"),
    )
    template_schema_contract = template_governance.get("structural_schema_contract")
    if isinstance(template_schema_contract, dict):
        _ensure_list_items(
            schema_contract,
            "required_schemas",
            template_schema_contract.get("required_schemas"),
        )

    semantic_contract = _ensure_mapping(
        governance,
        "semantic_validation_contract",
        template_governance.get("semantic_validation_contract"),
    )
    template_semantic_contract = template_governance.get("semantic_validation_contract")
    if isinstance(template_semantic_contract, dict):
        _ensure_list_items(
            semantic_contract,
            "required_checks",
            template_semantic_contract.get("required_checks"),
        )

    ownership_contract = _ensure_mapping(
        governance,
        "artifact_ownership_contract",
        template_governance.get("artifact_ownership_contract"),
    )
    template_ownership_contract = template_governance.get("artifact_ownership_contract")
    if isinstance(template_ownership_contract, dict):
        canonical_owners = _ensure_mapping(
            ownership_contract,
            "canonical_owners",
            template_ownership_contract.get("canonical_owners"),
        )
        template_owners = template_ownership_contract.get("canonical_owners")
        if isinstance(template_owners, dict):
            for key, value in template_owners.items():
                canonical_owners.setdefault(key, value)

    governance.setdefault(
        "phase_retention_contract",
        template_governance.get("phase_retention_contract"),
    )

    guardrails = _ensure_mapping(
        payload,
        "structural_guardrails",
        template.get("structural_guardrails"),
    )
    template_guardrails = template.get("structural_guardrails")
    if isinstance(template_guardrails, dict):
        guardrails.setdefault(
            "agent_deconstruction_contract",
            template_guardrails.get("agent_deconstruction_contract"),
        )
    _write_yaml_mapping(path, payload)



def _upgrade_memory_yaml(template_root: Path, target_root: Path) -> None:
    path = target_root / "MEMORY.yml"
    if not path.exists():
        return
    payload = _load_yaml_mapping(path)
    template = _template_yaml(template_root, "MEMORY.yml")
    stable = _ensure_mapping(payload, "stable_decisions", template.get("stable_decisions"))
    template_stable = template.get("stable_decisions") if isinstance(template.get("stable_decisions"), dict) else {}
    stable.setdefault("canonical_phase_history", template_stable.get("canonical_phase_history"))

    environment = _ensure_mapping(payload, "environment_facts", template.get("environment_facts"))
    template_environment = template.get("environment_facts")
    template_artifacts: dict[str, Any] = {}
    if isinstance(template_environment, dict) and isinstance(template_environment.get("active_artifacts"), dict):
        template_artifacts = template_environment["active_artifacts"]
    active_artifacts = _ensure_mapping(
        environment,
        "active_artifacts",
        template_artifacts,
    )
    active_artifacts.setdefault("phase_history", template_artifacts.get("phase_history"))

    references = _ensure_mapping(payload, "references", template.get("references"))
    template_references = template.get("references")
    if isinstance(template_references, dict):
        _ensure_list_items(references, "governance", template_references.get("governance"))
    _write_yaml_mapping(path, payload)



def _upgrade_artifact_manifest(template_root: Path, target_root: Path) -> None:
    path = target_root / "governance" / "artifact-manifest.yml"
    if not path.exists():
        return
    payload = _load_yaml_mapping(path)
    template = _template_yaml(template_root, "governance/artifact-manifest.yml")
    artifact_roots = _ensure_mapping(payload, "artifact_roots", template.get("artifact_roots"))
    template_roots = template.get("artifact_roots")
    if isinstance(template_roots, dict):
        for key in ("phase_archive",):
            artifact_roots.setdefault(key, template_roots.get(key))

    payload.setdefault("phase_retention_policy", template.get("phase_retention_policy"))
    policy = payload.get("phase_retention_policy")
    template_policy = template.get("phase_retention_policy")
    if isinstance(policy, dict) and isinstance(template_policy, dict):
        policy.setdefault("history_path", template_policy.get("history_path"))
        policy.setdefault("active_window", template_policy.get("active_window"))
        policy.setdefault("archive", template_policy.get("archive"))
    context_budgets = _ensure_mapping(
        payload,
        "context_budgets",
        template.get("context_budgets"),
    )
    template_budgets = template.get("context_budgets")
    if isinstance(template_budgets, dict):
        agent_required = _ensure_mapping(
            context_budgets,
            "agent_required_files",
            template_budgets.get("agent_required_files"),
        )
        template_required = template_budgets.get("agent_required_files")
        if isinstance(template_required, dict):
            agent_required.setdefault(
                "plans/phase-history.yml",
                template_required.get("plans/phase-history.yml"),
            )
    _write_yaml_mapping(path, payload)
    (target_root / "governance/archive/phase-artifacts").mkdir(parents=True, exist_ok=True)
    if isinstance(policy, dict) and str(policy.get("mode")).replace("-", "_") == "archive":
        _ensure_archive_gitignore(target_root, policy)



def _upgrade_governance_profile(template_root: Path, target_root: Path) -> None:
    path = target_root / "governance-profile.yml"
    if not path.exists():
        return
    payload = _load_yaml_mapping(path)
    template = _template_yaml(template_root, "governance-profile.yml")
    release_profile = _ensure_mapping(
        payload,
        "release_gate_profile",
        template.get("release_gate_profile"),
    )
    gates = _ensure_mapping(
        release_profile,
        "gates",
        (template.get("release_gate_profile") or {}).get("gates")
        if isinstance(template.get("release_gate_profile"), dict)
        else {},
    )
    template_release = template.get("release_gate_profile")
    if isinstance(template_release, dict) and isinstance(template_release.get("gates"), dict):
        gates.setdefault("governance_exposure_scan", template_release["gates"].get("governance_exposure_scan"))

    ci_profile = _ensure_mapping(payload, "ci_profile", template.get("ci_profile"))
    template_ci = template.get("ci_profile")
    if isinstance(template_ci, dict):
        _ensure_list_items(ci_profile, "required_push_jobs", ["governance-exposure-scan"])
    _write_yaml_mapping(path, payload)



def _upgrade_makefile_fragment(target_root: Path) -> None:
    path = target_root / "Makefile.fragment"
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    if ".PHONY:" in text and "governance-exposure-scan" not in text.splitlines()[0]:
        text = text.replace(
            "governance-validate",
            "governance-validate governance-exposure-scan",
            1,
        )
    if "\ngovernance-exposure-scan:" not in text:
        marker = "\ngovernance-scaffold-help:"
        block = "\ngovernance-exposure-scan:\n\t$(PYTHON) scripts/check_governance_exposure.py --repo-root .\n"
        text = text.replace(marker, f"{block}{marker}", 1) if marker in text else text + block
    release_span = _find_target_span(text.splitlines(), "release-check")
    if release_span is not None and "$(MAKE) governance-exposure-scan" not in text:
        lines = text.splitlines()
        start, _ = release_span
        insert_at = start + 1
        for index in range(start + 1, len(lines)):
            if lines[index].strip() == "@$(MAKE) governance-validate":
                insert_at = index + 1
                break
        lines.insert(insert_at, "\t@$(MAKE) governance-exposure-scan")
        text = "\n".join(lines) + "\n"
    path.write_text(text, encoding="utf-8")


def _ensure_archive_gitignore(target_root: Path, policy: dict[str, Any]) -> None:
    archive = policy.get("archive")
    archive_root = "governance/archive/phase-artifacts"
    if isinstance(archive, dict) and isinstance(archive.get("root"), str):
        archive_root = archive["root"].rstrip("/")
    gitkeep = target_root / archive_root / ".gitkeep"
    gitkeep.parent.mkdir(parents=True, exist_ok=True)
    gitkeep.touch()
    ignored_pattern = f"{archive_root}/*"
    keep_pattern = f"!{archive_root}/.gitkeep"
    gitignore = target_root / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8").splitlines() if gitignore.exists() else []
    normalized = {line.strip() for line in existing}
    lines = list(existing)
    if ignored_pattern not in normalized:
        lines.append(ignored_pattern)
    if keep_pattern not in normalized:
        lines.append(keep_pattern)
    gitignore.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")



def _upgrade_state_files(
    *,
    template_root: Path,
    target_root: Path,
    values: dict[str, str],
    reset_options: bool = False,
) -> list[Path]:
    created = _copy_template_file_if_missing(
        template_root=template_root,
        target_root=target_root,
        relative_path="plans/phase-history.yml",
        values=values,
    )
    _copy_template_file_if_missing(
        template_root=template_root,
        target_root=target_root,
        relative_path="governance/archive/phase-artifacts/.gitkeep",
        values=values,
    )
    _upgrade_agents_yaml(template_root, target_root)
    _upgrade_memory_yaml(template_root, target_root)
    _upgrade_artifact_manifest(template_root, target_root)
    if not reset_options:
        _upgrade_governance_profile(template_root, target_root)
        _upgrade_makefile_fragment(target_root)
    return created



replace_placeholders_in_files = _replace_placeholders_in_files
upgrade_state_files = _upgrade_state_files
