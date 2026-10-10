"""Classify evidence storage and compile a non-mutating migration plan."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

TOPOLOGY_STATES = {
    "available_not_adopted",
    "compact_run_evidence",
    "durable",
    "legacy",
    "mixed",
    "unknown",
}
_COMPACT_PATHS = {
    ".artifacts/bcf/sessions",
    ".artifacts/bcf/truth-report.json",
    ".artifacts/bcf/prior-evidence",
    ".artifacts/bcf/exact-main-certification",
}


@dataclass(frozen=True)
class StorageTopology:
    state: str
    activation: str
    durable_sources: tuple[str, ...]
    durable_references: tuple[str, ...]
    legacy_candidates: tuple[str, ...]
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "governance.evidence-storage-topology.v1",
            "state": self.state,
            "activation": self.activation,
            "durable_sources": list(self.durable_sources),
            "durable_references": list(self.durable_references),
            "legacy_candidates": list(self.legacy_candidates),
            "reasons": list(self.reasons),
        }


def _edges(graph: Mapping[str, Any], artifact_id: str, operation: str) -> tuple[str, ...]:
    rows = []
    for workflow in graph.get("workflows", []):
        for job in workflow.get("jobs", []):
            if artifact_id in job.get(operation, []):
                rows.append(f"{workflow.get('id')}/{job.get('id')}")
    return tuple(sorted(rows))


def classify_storage_topology(
    graph: Mapping[str, Any], contract: Mapping[str, Any] | None,
) -> StorageTopology:
    """Derive one closed topology state without inferring adoption from capability."""

    artifacts = graph.get("artifacts")
    workflows = graph.get("workflows")
    if not isinstance(artifacts, Mapping) or not isinstance(workflows, list):
        return StorageTopology("unknown", "unknown", (), (), (), ("graph_unreadable",))
    activation = "absent" if contract is None else str(contract.get("activation", "unknown"))
    sources = tuple(sorted(
        str(key) for key, value in artifacts.items()
        if isinstance(value, Mapping) and value.get("kind") == "durable-source"
    ))
    references = tuple(sorted(
        str(key) for key, value in artifacts.items()
        if isinstance(value, Mapping) and value.get("kind") == "durable-reference"
    ))
    legacy = []
    ambiguous = []
    for key, value in artifacts.items():
        if not isinstance(value, Mapping):
            ambiguous.append(str(key))
            continue
        kind = value.get("kind")
        path = value.get("path")
        if kind in {"durable-source", "durable-reference"}:
            continue
        producers = _edges(graph, str(key), "produces")
        consumers = _edges(graph, str(key), "consumes")
        if kind == "lane-input" and producers and consumers and path not in _COMPACT_PATHS:
            semantics = value.get("storage_semantics")
            if semantics == "reusable-input-handoff" or (
                semantics is None and len(consumers) > 1
            ):
                legacy.append(str(key))
            elif semantics != "compact-run-output":
                ambiguous.append(str(key))
    reasons: list[str] = []
    if ambiguous or activation not in {"absent", "disabled", "enabled"}:
        state = "unknown"
        reasons.append("incomplete_or_malformed_topology:" + ",".join(sorted(ambiguous)))
    elif bool(sources) != bool(references):
        state = "unknown"
        reasons.append("partial_durable_topology")
    elif sources and legacy:
        state = "mixed"
        reasons.append("durable_and_legacy_transports_coexist")
    elif sources:
        state = "durable"
        reasons.append("durable_sources_and_references_declared")
    elif legacy:
        state = "legacy"
        reasons.append("bulk_lane_inputs_remain_run_scoped")
    elif activation in {"absent", "disabled"}:
        state = "available_not_adopted"
        reasons.append("storage_capability_is_not_adoption")
    elif activation == "enabled":
        state = "compact_run_evidence"
        reasons.append("enabled_contract_has_only_compact_run_outputs")
    else:
        state = "unknown"
        reasons.append("topology_unprovable")
    return StorageTopology(
        state, activation, sources, references, tuple(sorted(legacy)), tuple(reasons)
    )


def migration_plan(
    graph: Mapping[str, Any], contract: Mapping[str, Any] | None, *,
    graph_digest: str, contract_digest: str | None,
) -> dict[str, Any]:
    """Compile exact graph-bound actions; never infer reusable object boundaries."""

    topology = classify_storage_topology(graph, contract)
    actions = []
    for artifact_id in topology.legacy_candidates:
        artifact = graph["artifacts"][artifact_id]
        actions.append({
            "action": "declare_durable_input_boundary",
            "artifact_id": artifact_id,
            "artifact_path": artifact["path"],
            "producers": list(_edges(graph, artifact_id, "produces")),
            "consumers": list(_edges(graph, artifact_id, "consumes")),
            "proposed_source_id": f"{artifact_id}-durable-source",
            "proposed_reference_id": f"{artifact_id}-durable-reference",
            "requires_reviewed_object_declaration": True,
        })
    if topology.state == "unknown":
        disposition = "blocked_unknown_topology"
    elif actions:
        disposition = "review_required"
    else:
        disposition = "no_transition"
    payload = {
        "schema_version": "1.0",
        "kind": "governance.evidence-storage-migration-plan.v1",
        "graph_sha256": graph_digest,
        "storage_contract_sha256": contract_digest,
        "topology": topology.as_dict(),
        "disposition": disposition,
        "actions": actions,
        "truth_semantics_changed": False,
        "provider_mutation_authorized": False,
        "cleanup_authorized": False,
        "storage_accounting": {
            "provider_observation": "required",
            "dimensions": [
                "actions_artifact_bytes_per_run",
                "durable_unique_input_bytes",
                "run_output_bytes",
                "authenticated_duplicate_bytes",
                "upload_bytes",
                "download_bytes",
            ],
            "authority_effect": "none",
        },
    }
    payload["plan_sha256"] = hashlib.sha256(
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    return payload


def compile_migration_plan(repo_root: Path) -> dict[str, Any]:
    """Compile from the canonical composed graph, including registered extensions."""

    from .ci_graph_contracts import validate_ci_graph

    root = repo_root.resolve()
    compiled = validate_ci_graph(root)
    graph = compiled.graph
    contract = compiled.evidence_storage
    contract_path = root / "governance/evidence-storage.yml"
    return migration_plan(
        graph,
        contract,
        graph_digest=hashlib.sha256(
            (json.dumps(graph, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest(),
        contract_digest=(
            hashlib.sha256(contract_path.read_bytes()).hexdigest()
            if contract is not None else None
        ),
    )
