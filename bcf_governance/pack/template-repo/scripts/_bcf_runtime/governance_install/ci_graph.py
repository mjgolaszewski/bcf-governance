"""Install-time construction of a repository's canonical CI graph."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..ci_graph_defaults import build_reference_ci_graph
from ..ci_graph_render import apply_ci_graph
from ..ci_graph_yaml import load_yaml_path, render_yaml


def _sync_evidence_workflow_contract(
    target_root: Path, graph: dict[str, Any]
) -> None:
    """Project actual graph roots/events into the evidence requirement surface."""

    governance = next(
        workflow for workflow in graph["workflows"] if workflow["id"] == "governance"
    )
    policy_path = target_root / "governance/evidence-policy.yml"
    policy = load_yaml_path(policy_path)
    contract = policy.get("workflow_contract")
    if not isinstance(contract, dict):
        raise RuntimeError("evidence policy requires a workflow_contract mapping")
    contract["paths"] = [governance["path"]]
    contract["required_events"] = [
        event["type"] for event in governance["events"]
    ]
    policy_path.write_bytes(render_yaml(policy))


def _runner_mapping(
    args: Any, *, contract_version: str
) -> tuple[list[str], list[str], bool, bool]:
    if args.profile == "lite" or contract_version == "1.0":
        candidate = list(args.candidate_runner_label or [args.runner_labels])
        trusted = list(args.trusted_runner_label or candidate)
        return (
            candidate,
            trusted,
            (args.candidate_runner_kind or "hosted") == "hosted",
            (args.trusted_runner_kind or args.candidate_runner_kind or "hosted")
            == "hosted",
        )
    missing = [
        name
        for name, value in (
            ("--candidate-runner-label", args.candidate_runner_label),
            ("--trusted-runner-label", args.trusted_runner_label),
            ("--candidate-runner-kind", args.candidate_runner_kind),
            ("--trusted-runner-kind", args.trusted_runner_kind),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Standard-v2 CI graph requires explicit runner mapping: "
            + ", ".join(missing)
        )
    return (
        list(args.candidate_runner_label),
        list(args.trusted_runner_label),
        args.candidate_runner_kind == "hosted",
        args.trusted_runner_kind == "hosted",
    )


def write_reference_ci_graph(
    args: Any, target_root: Path, contract: dict[str, Any]
) -> None:
    contract_version = str(contract.get("profile_contract_version", "1.0"))
    candidate, trusted, candidate_hosted, trusted_hosted = _runner_mapping(
        args, contract_version=contract_version
    )
    graph = build_reference_ci_graph(
        project_id=args.project_id,
        profile=args.profile,
        profile_contract_version=contract_version,
        gates=list(contract["gates"]),
        candidate_labels=candidate,
        trusted_labels=trusted,
        candidate_hosted=candidate_hosted,
        trusted_hosted=trusted_hosted,
    )
    graph_path = target_root / "governance/ci-graph.yml"
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    graph_path.write_bytes(render_yaml(graph))
    _sync_evidence_workflow_contract(target_root, graph)
    (target_root / "governance/ci-extensions").mkdir(parents=True, exist_ok=True)
    apply_ci_graph(target_root)
