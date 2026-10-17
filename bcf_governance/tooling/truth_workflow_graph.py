"""Resolve truth workflow ownership from the canonical compiled CI graph."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import re
from typing import Any

from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_render import check_ci_graph


def graph_workflow_gate_issues(
    repo_root: Path,
    *,
    paths: list[Any],
    required_events: list[Any],
    gate_ids: set[str],
) -> list[str]:
    try:
        compiled = validate_ci_graph(repo_root)
        parity = check_ci_graph(repo_root)
    except CIGraphError:
        return ["ci_graph_invalid"]
    if parity.status != "clean":
        return [f"ci_graph_workflow_drift_{path}" for path in parity.changed_paths]
    by_path = {workflow["path"]: workflow for workflow in compiled.workflows}
    queue = [str(value) for value in paths if isinstance(value, str)]
    visited: set[str] = set()
    resolved_gates: set[str] = set()
    discovered_events: set[str] = set()
    issues: list[str] = []
    while queue:
        relative_path = queue.pop(0)
        if relative_path in visited:
            continue
        visited.add(relative_path)
        workflow = by_path.get(relative_path)
        if workflow is None:
            issues.append(f"workflow_path_{relative_path}_missing_from_ci_graph")
            continue
        discovered_events.update(event["type"] for event in workflow["events"])
        for job in workflow["jobs"]:
            executor = job["executor"]
            if executor["kind"] in {"gate_group", "gate_shard"}:
                resolved_gates.update(executor["gates"])
            elif executor["kind"] == "reusable_workflow":
                queue.append(executor["path"])
    issues.extend(
        f"workflow_event_{event}_missing"
        for event in required_events
        if isinstance(event, str) and event not in discovered_events
    )
    issues.extend(
        f"workflow_gate_{gate_id}_unresolved"
        for gate_id in sorted(gate_ids - resolved_gates)
    )
    return sorted(set(issues))


def _safe_contract_file(repo_root: Path, value: str) -> bool:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        return False
    candidate = repo_root / relative
    try:
        candidate.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return False
    return candidate.is_file() and not candidate.is_symlink()


def workflow_gate_issues(
    repo_root: Path, policy: dict[str, Any], gate_ids: set[str],
    *, load_yaml: Callable[[Path], dict[str, Any]],
) -> list[str]:
    contract = policy.get("workflow_contract")
    if not isinstance(contract, dict):
        return ["workflow_contract_missing"]
    paths = contract.get("paths")
    required_events = contract.get("required_events", [])
    if not isinstance(paths, list) or not paths:
        return ["workflow_paths_missing"]
    graph_path = repo_root / "governance/ci-graph.yml"
    if graph_path.is_file():
        return graph_workflow_gate_issues(
            repo_root,
            paths=paths,
            required_events=required_events,
            gate_ids=gate_ids,
        )
    resolved_gates: set[str] = set()
    discovered_events: set[str] = set()
    issues: list[str] = []
    queue = [str(value) for value in paths if isinstance(value, str)]
    roots = set(queue)
    visited: set[str] = set()
    raw_resolvers = contract.get("gate_resolvers", [])
    resolvers = raw_resolvers if isinstance(raw_resolvers, list) else []
    while queue:
        relative_path = queue.pop(0)
        if relative_path in visited:
            continue
        visited.add(relative_path)
        path = repo_root / relative_path
        if not path.is_file():
            issues.append(f"workflow_path_{relative_path}_missing")
            continue
        payload = load_yaml(path)
        if relative_path in roots:
            on_value = payload.get("on", payload.get(True))
            if isinstance(on_value, dict):
                discovered_events.update(str(key) for key in on_value)
            elif isinstance(on_value, list):
                discovered_events.update(str(value) for value in on_value)
            elif isinstance(on_value, str):
                discovered_events.add(on_value)
        jobs = payload.get("jobs")
        if not isinstance(jobs, dict):
            issues.append(f"workflow_{relative_path}_jobs_unresolved")
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            reusable = job.get("uses")
            if isinstance(reusable, str):
                if reusable.startswith("./"):
                    reusable_path = reusable[2:].split("@", 1)[0]
                    if reusable_path.startswith(".github/workflows/"):
                        queue.append(reusable_path)
                    else:
                        issues.append(f"workflow_job_{job_id}_local_reusable_path_invalid")
                else:
                    issues.append(f"workflow_job_{job_id}_external_reusable_unresolved")
                continue
            strategy = job.get("strategy")
            matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
            job_matrix_gates: set[str] = set()
            if isinstance(matrix, dict):
                for key in ("gate", "target"):
                    values = matrix.get(key)
                    if isinstance(values, list):
                        job_matrix_gates.update(str(value) for value in values)
                    elif values is not None:
                        issues.append(f"workflow_job_{job_id}_{key}_matrix_dynamic")
            steps = job.get("steps")
            runs = "\n".join(
                str(step.get("run"))
                for step in steps
                if isinstance(step, dict) and isinstance(step.get("run"), str)
            ) if isinstance(steps, list) else ""
            wrapper_present = bool(
                re.search(
                    r"(?:governance_evidence\.py[\s\S]{0,300}\brun\b|bcf\s+evidence\s+run)"
                    r"[\s\S]{0,300}--gate",
                    runs,
                )
            )
            matching_resolvers = [
                resolver
                for resolver in resolvers
                if isinstance(resolver, dict)
                and resolver.get("workflow_path") == relative_path
                and resolver.get("job_id") == str(job_id)
            ]
            resolver_valid = False
            for resolver in matching_resolvers:
                resolver_id = str(resolver.get("id", job_id))
                matrix_key = resolver.get("matrix_key")
                script_path = resolver.get("script_path")
                gate_contract_path = resolver.get("gate_contract_path")
                profile_path = resolver.get("profile_path")
                values = matrix.get(matrix_key) if isinstance(matrix, dict) else None
                if (
                    resolver.get("kind") != "canonical_contract_shards"
                    or not isinstance(matrix_key, str)
                    or not isinstance(script_path, str)
                    or not isinstance(gate_contract_path, str)
                    or not isinstance(profile_path, str)
                    or not isinstance(values, list)
                    or any(not isinstance(value, int) for value in values)
                    or values != list(range(len(values)))
                    or not values
                    or not _safe_contract_file(repo_root, script_path)
                    or not _safe_contract_file(repo_root, gate_contract_path)
                    or not _safe_contract_file(repo_root, profile_path)
                ):
                    issues.append(f"workflow_gate_resolver_{resolver_id}_invalid")
                    continue
                index_pattern = re.compile(
                    rf"--shard-index(?:=|\s+)[\"']?\$\{{\{{\s*matrix\.{re.escape(matrix_key)}\s*\}}\}}[\"']?"
                )
                count_pattern = re.compile(
                    rf"--shard-count(?:=|\s+)[\"']?{len(values)}(?:[\"'\s]|$)"
                )
                if (
                    script_path not in runs
                    or index_pattern.search(runs) is None
                    or count_pattern.search(runs) is None
                ):
                    issues.append(
                        f"workflow_gate_resolver_{resolver_id}_invocation_invalid"
                    )
                    continue
                resolver_valid = True
            if resolver_valid:
                resolved_gates.update(gate_ids)
            if wrapper_present:
                resolved_gates.update(job_matrix_gates)
                for gate_id in gate_ids:
                    if re.search(rf"--gate(?:=|\s+)[\"']?{re.escape(gate_id)}(?:[\"'\s]|$)", runs):
                        resolved_gates.add(gate_id)
            elif job_matrix_gates.intersection(gate_ids):
                issues.append(f"workflow_job_{job_id}_evidence_wrapper_missing")
    issues.extend(
        f"workflow_event_{event}_missing"
        for event in required_events
        if isinstance(event, str) and event not in discovered_events
    )
    for gate_id in sorted(gate_ids):
        if gate_id not in resolved_gates:
            issues.append(f"workflow_gate_{gate_id}_unresolved")
    return sorted(set(issues))
