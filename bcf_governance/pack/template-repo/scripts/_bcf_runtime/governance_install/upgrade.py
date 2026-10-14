"""Upgrade migration helpers for governed repos."""

from __future__ import annotations

import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import yaml  # type: ignore[import-untyped]

from ..ci_graph_yaml import render_yaml
from ..ci_graph_defaults import evidence_capture_environment
from ..ci_graph_provider_permissions import project_provider_permission_edges
from ..profile_surface_generation import reconcile_makefile
from ..profile_yaml import render_governance_profile
from ..runtime_capacity import EXECUTION_STATE_POLICY
from ..repository_comparison_context import comparison_base_input_contract
from ..test_duration_observations import (
    OBSERVATIONS_PATH,
    reconcile_test_duration_observations,
)


def retire_self_authority_pack_surfaces(
    *,
    target_root: Path,
    entries: Mapping[str, Mapping[str, Any]],
    reject_destination: Callable[[Path, Path], None],
    prune_empty_parents: Callable[[Path, Path], None],
) -> list[Path]:
    """Remove only exact pack-owned destinations now classified as self-only."""

    removed: list[Path] = []
    for value, entry in sorted(entries.items()):
        if entry.get("installation_scope") != "self_authority":
            continue
        relative = Path(value)
        reject_destination(target_root, relative)
        destination = target_root / relative
        if not destination.exists():
            continue
        if not destination.is_file():
            raise ValueError(f"self-only pack destination is not a file: {value}")
        destination.unlink()
        prune_empty_parents(target_root, destination)
        removed.append(destination)
    return removed


def copy_selected_template_paths(
    *,
    template_root: Path,
    target_root: Path,
    relative_paths: tuple[str, ...],
    entries: Mapping[str, Mapping[str, Any]],
    iter_template_files: Callable[[Path], Iterable[Path]],
    reject_destination: Callable[[Path, Path], None],
    excluded_paths: frozenset[str] = frozenset(),
) -> tuple[int, list[Path]]:
    """Refresh ordinary pack-owned upgrade paths from the scoped manifest."""

    destinations: list[Path] = []
    for relative_path in relative_paths:
        source = template_root / relative_path
        destination = target_root / relative_path
        sources = iter_template_files(source) if source.is_dir() else (source,)
        for source_file in sources:
            if not source_file.exists():
                continue
            destination_file = (
                destination / source_file.relative_to(source)
                if source.is_dir()
                else destination
            )
            destination_relative = destination_file.relative_to(target_root).as_posix()
            entry = entries.get(destination_relative)
            if entry is None:
                raise ValueError(
                    f"upgrade path is absent from pack manifest: {destination_relative}"
                )
            if (
                destination_relative in excluded_paths
                or entry.get("installation_scope", "ordinary_adopter")
                != "ordinary_adopter"
            ):
                continue
            reject_destination(target_root, destination_file.relative_to(target_root))
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination_file)
            destinations.append(destination_file)
    return len(destinations), destinations


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


def _upgrade_runtime_contract(target_root: Path) -> list[Path]:
    """Migrate only the closed prior runtime contract to isolated state v1.1."""

    path = target_root / "governance/ci-runtime.yml"
    if not path.exists():
        return []
    payload = _load_yaml_mapping(path)
    if payload.get("schema_version") == "1.1":
        return []
    legacy_fields = {
        "schema_version",
        "runtime_root",
        "minimum_free_bytes",
        "maximum_owned_containers",
        "database",
        "cleanup",
    }
    if payload.get("schema_version") != "1.0" or set(payload) != legacy_fields:
        raise ValueError("runtime contract is not an exact migratable v1.0 shape")
    raw = path.read_text(encoding="utf-8")
    marker = "schema_version: '1.0'"
    if raw.count(marker) != 1:
        raise ValueError("runtime contract v1.0 version bytes are ambiguous")
    execution = yaml.safe_dump(
        {"execution_state": deepcopy(EXECUTION_STATE_POLICY)},
        sort_keys=False,
        default_flow_style=None,
        width=4096,
    )
    path.write_text(
        raw.replace(marker, "schema_version: '1.1'", 1).rstrip() + "\n" + execution,
        encoding="utf-8",
    )
    return [path]


def _upgrade_direct_comparison_input(target_root: Path) -> list[Path]:
    """Project the exact new reusable input into a preserved legacy direct graph."""

    path = target_root / "governance/ci-graph.yml"
    if not path.exists():
        return []
    payload = _load_yaml_mapping(path)
    workflows = payload.get("workflows")
    if not isinstance(workflows, list):
        raise ValueError("upgrade CI graph workflow inventory is invalid")
    if any(isinstance(item, dict) and item.get("id") == "exact-main" for item in workflows):
        return []
    direct = []
    for item in workflows:
        if not isinstance(item, dict) or item.get("role") != "exact-main":
            continue
        events = item.get("events")
        if not isinstance(events, list):
            continue
        types = {
            event.get("type") for event in events if isinstance(event, dict)
        }
        if {"pull_request", "workflow_call", "push"}.issubset(types):
            direct.append(item)
    if not direct:
        return []
    if len(direct) != 1:
        raise ValueError("upgrade direct protected-main workflow is ambiguous")
    calls = [
        event
        for event in direct[0]["events"]
        if isinstance(event, dict) and event.get("type") == "workflow_call"
    ]
    if len(calls) != 1 or not isinstance(calls[0].get("inputs"), dict):
        raise ValueError("upgrade direct workflow-call contract is invalid")
    inputs = calls[0]["inputs"]
    expected = comparison_base_input_contract()
    current = inputs.get("comparison_base_sha")
    if current == expected:
        return []
    if current is not None:
        raise ValueError("upgrade comparison-base input is malformed")
    calls[0]["inputs"] = {"comparison_base_sha": expected, **inputs}
    path.write_bytes(render_yaml(payload))
    return [path]


def _upgrade_evidence_capture_environment(target_root: Path) -> list[Path]:
    """Close the exact legacy capture component's provider-input edge."""

    path = target_root / "governance/ci-graph.yml"
    if not path.exists():
        return []
    payload = _load_yaml_mapping(path)
    commands = payload.get("commands")
    components = payload.get("step_components")
    if not isinstance(commands, dict) or not isinstance(components, dict):
        return []
    command = commands.get("v3-capture-shard")
    component = components.get("capture-shard")
    if command is None and component is None:
        return []
    if not isinstance(command, dict) or not isinstance(component, dict):
        raise ValueError("upgrade evidence capture edge is incomplete")
    if component.get("command") != "v3-capture-shard":
        raise ValueError("upgrade evidence capture edge is ambiguous")
    expected = evidence_capture_environment()
    environment = component.get("environment")
    if environment == expected:
        return []
    if environment != {}:
        raise ValueError("upgrade evidence capture environment is customized")
    component["environment"] = expected
    path.write_bytes(render_yaml(payload))
    return [path]


def _upgrade_provider_permission_edges(target_root: Path) -> list[Path]:
    """Project provider reads required by preserved executable components."""

    path = target_root / "governance/ci-graph.yml"
    if not path.exists():
        return []
    payload = _load_yaml_mapping(path)
    if not project_provider_permission_edges(payload):
        return []
    path.write_bytes(render_yaml(payload))
    return [path]


def upgrade_graph_contracts(target_root: Path) -> list[Path]:
    """Project every closed legacy graph migration in canonical order."""

    changed = [
        *_upgrade_direct_comparison_input(target_root),
        *_upgrade_evidence_capture_environment(target_root),
        *_upgrade_provider_permission_edges(target_root),
    ]
    return list(dict.fromkeys(changed))


def _upgrade_interpreter_contract(target_root: Path) -> list[Path]:
    """Close the exact v2/v3 Python-gate state before strict validation."""

    path = target_root / "governance/gate-contracts.yml"
    if not path.is_file() or path.is_symlink():
        return []
    payload = _load_yaml_mapping(path)
    if str(payload.get("profile_contract_version", "1.0")) not in {"2.0", "3.0"}:
        return []
    if payload.get("interpreter_contract") is not None:
        return []
    gates = payload.get("gates")
    if not isinstance(gates, dict):
        raise ValueError("upgrade gate registry is invalid")
    from ..interpreter_contract_projection import project_interpreter_contract

    projected = project_interpreter_contract(
        gates, None, default_if_required=True
    )
    if projected is None:
        return []
    dependency_source = target_root / "requirements-governance.txt"
    if dependency_source.is_symlink() or not dependency_source.is_file():
        raise ValueError(
            "profile-v2/v3 Python gates lack an authenticated interpreter dependency source"
        )
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines(keepends=True)
    anchors = [
        index
        for index, line in enumerate(lines)
        if line.startswith("gates:")
    ]
    if len(anchors) != 1:
        raise ValueError("upgrade interpreter contract insertion point is ambiguous")
    insertion = yaml.safe_dump(
        {"interpreter_contract": projected}, sort_keys=False
    )
    lines.insert(anchors[0], insertion)
    path.write_text("".join(lines), encoding="utf-8")
    from ..interpreter_environment import (
        derive_interpreter_environment,
        verify_interpreter_environment_projection,
    )

    plan = derive_interpreter_environment(target_root)
    if plan is None:
        raise ValueError("upgrade interpreter dependency contract was not derivable")
    verify_interpreter_environment_projection(plan)
    return [path]



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

    phase_log_contract = _ensure_mapping(
        governance,
        "phase_log_contract",
        template_governance.get("phase_log_contract"),
    )
    template_phase_log = template_governance.get("phase_log_contract")
    if isinstance(template_phase_log, dict):
        phase_log_contract["status_taxonomy"] = template_phase_log.get("status_taxonomy")
        phase_log_contract["computed_states"] = template_phase_log.get("computed_states")
        phase_log_contract["final_closeout_required_fields"] = template_phase_log.get(
            "final_closeout_required_fields"
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

    phase_transition = _ensure_mapping(
        governance,
        "phase_transition_contract",
        template_governance.get("phase_transition_contract"),
    )
    template_transition = template_governance.get("phase_transition_contract")
    if isinstance(template_transition, dict):
        phase_transition["active_phase_lifecycle_taxonomy"] = template_transition.get(
            "active_phase_lifecycle_taxonomy"
        )
        phase_transition["rollover_rules"] = template_transition.get("rollover_rules")

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


def _upgrade_context_budget(existing: Any, template_budget: Any) -> Any:
    if not isinstance(template_budget, dict):
        return template_budget if existing is None else existing

    if isinstance(existing, int):
        upgraded = {"line_hard_cap": existing}
    elif isinstance(existing, dict):
        upgraded = dict(existing)
    else:
        upgraded = {}

    if isinstance(existing, dict) and "line_hard_cap" not in upgraded:
        legacy_line_cap = existing.get("line_budget") or existing.get("budget")
        if isinstance(legacy_line_cap, int):
            upgraded["line_hard_cap"] = legacy_line_cap
    if isinstance(upgraded.get("target"), str) and "intent" not in upgraded:
        upgraded["intent"] = upgraded["target"]
    for legacy_key in ("line_budget", "budget", "target"):
        upgraded.pop(legacy_key, None)

    for key in ("line_hard_cap", "kib_hard_cap", "line_target", "kib_target", "intent"):
        if key in template_budget:
            upgraded.setdefault(key, template_budget[key])
    return upgraded



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
        if isinstance(policy.get("archive"), dict) and isinstance(template_policy.get("archive"), dict):
            policy["archive"]["closed_phase_statuses"] = template_policy["archive"].get(
                "closed_phase_statuses"
            )
    context_budgets = _ensure_mapping(
        payload,
        "context_budgets",
        template.get("context_budgets"),
    )
    template_budgets = template.get("context_budgets")
    if isinstance(template_budgets, dict):
        context_budgets.setdefault(
            "aggregate_agent_required_kib_advisory",
            template_budgets.get("aggregate_agent_required_kib_advisory"),
        )
        agent_required = _ensure_mapping(
            context_budgets,
            "agent_required_files",
            template_budgets.get("agent_required_files"),
        )
        template_required = template_budgets.get("agent_required_files")
        if isinstance(template_required, dict):
            for relative_path, template_budget in template_required.items():
                agent_required[relative_path] = _upgrade_context_budget(
                    agent_required.get(relative_path),
                    template_budget,
                )
    _write_yaml_mapping(path, payload)
    (target_root / "governance/archive/phase-artifacts").mkdir(parents=True, exist_ok=True)
    _ensure_gitignore_pattern(target_root, ".artifacts/")
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
    path.write_text(render_governance_profile(payload), encoding="utf-8")



def _upgrade_makefile_fragment(target_root: Path) -> None:
    """Project the sole profile-owned Makefile from the preserved gate registry."""

    reconcile_makefile(target_root, apply=True)


def _ensure_gitignore_pattern(target_root: Path, pattern: str) -> None:
    gitignore = target_root / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8").splitlines() if gitignore.exists() else []
    if pattern not in {line.strip() for line in existing}:
        existing.append(pattern)
        gitignore.write_text("\n".join(existing).rstrip() + "\n", encoding="utf-8")


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
    _ensure_gitignore_pattern(target_root, ignored_pattern)
    _ensure_gitignore_pattern(target_root, keep_pattern)



def _upgrade_state_files(
    *,
    template_root: Path,
    target_root: Path,
    values: dict[str, str],
    reset_options: bool = False,
) -> list[Path]:
    """Create newly introduced state artifacts without rewriting existing state.

    Upgrade refreshes pack-owned executable/support files elsewhere.  Product-owned
    governance files are deliberately byte-preserved: parsing and re-emitting YAML
    here used to normalize formatting and could also merge template assumptions
    into a repository's intentionally customized governance model.
    """
    created = _copy_template_file_if_missing(
        template_root=template_root,
        target_root=target_root,
        relative_path="plans/phase-history.yml",
        values=values,
    )
    created += _copy_template_file_if_missing(
        template_root=template_root,
        target_root=target_root,
        relative_path="requirements-governance.txt",
        values=values,
    )
    _copy_template_file_if_missing(
        template_root=template_root,
        target_root=target_root,
        relative_path="governance/archive/phase-artifacts/.gitkeep",
        values=values,
    )
    created.extend(
        _copy_template_file_if_missing(
            template_root=template_root,
            target_root=target_root,
            relative_path="governance/evidence-policy.yml",
            values=values,
        )
    )
    created.extend(
        _copy_template_file_if_missing(
            template_root=template_root,
            target_root=target_root,
            relative_path="governance/findings.yml",
            values=values,
        )
    )
    _upgrade_makefile_fragment(target_root)
    interpreter_paths = _upgrade_interpreter_contract(target_root)
    created.extend(interpreter_paths)
    if interpreter_paths and (target_root / OBSERVATIONS_PATH).is_file():
        reconcile_test_duration_observations(target_root, apply=True)
        created.append(target_root / OBSERVATIONS_PATH)
    created.extend(_upgrade_runtime_contract(target_root))
    created.extend(upgrade_graph_contracts(target_root))
    return created



replace_placeholders_in_files = _replace_placeholders_in_files
upgrade_state_files = _upgrade_state_files
