"""Deterministic authority and duplication report for one compiled CI graph."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from .ci_graph_contracts import CompiledCIGraph, validate_ci_graph
from .ci_graph_import import inventory_github_workflows
from .ci_graph_render import check_ci_graph
from .ci_graph_timeouts import gate_timeout_contract
from .ci_graph_yaml import load_yaml_path
from .evidence_gate_contracts import expected_evidence_kinds


def _tracked(repo_root: Path, patterns: tuple[str, ...]) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--", *patterns],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return sorted(line for line in result.stdout.splitlines() if line) if result.returncode == 0 else []


def _repository_state(repo_root: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return {"available": False, "committed_clean": False}
    entries = sorted(value.decode("utf-8") for value in result.stdout.split(b"\0") if value)
    return {
        "available": True,
        "committed_clean": not entries,
        "status_entries": entries,
        "status_sha256": hashlib.sha256(result.stdout).hexdigest(),
    }


def _make_targets(repo_root: Path) -> list[dict[str, Any]]:
    targets: dict[str, set[str]] = {}
    for name in ("GNUmakefile", "Makefile", "makefile", "Makefile.fragment"):
        path = repo_root / name
        if not path.is_file() or path.is_symlink():
            continue
        for match in re.finditer(
            r"(?m)^([A-Za-z0-9][A-Za-z0-9_.-]*):(?:\s|$)",
            path.read_text(encoding="utf-8"),
        ):
            targets.setdefault(match.group(1), set()).add(name)
    return [
        {"target": target, "sources": sorted(sources)}
        for target, sources in sorted(targets.items())
    ]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _test_manifest_inventory(repo_root: Path) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(repo_root).as_posix(),
            "sha256": _digest(path),
            "node_count": len(
                [line for line in path.read_text(encoding="utf-8").splitlines() if line]
            ),
        }
        for path in sorted((repo_root / "governance/test-manifests").glob("*.txt"))
        if path.is_file() and not path.is_symlink()
    ]


def _gate_inventory(repo_root: Path) -> list[dict[str, Any]]:
    registry = load_yaml_path(repo_root / "governance/gate-contracts.yml")
    profile = load_yaml_path(repo_root / "governance-profile.yml")
    gates = registry["gates"]
    evidence_kinds = expected_evidence_kinds(repo_root)
    applicable = {
        str(value["target"]): {
            "profile_id": str(gate_id),
            "status": str(value["status"]),
            "command_policy": str(value["command_policy"]),
        }
        for gate_id, value in profile["release_gate_profile"]["gates"].items()
    }
    return [
        {
            "id": gate_id,
            **applicable.get(gate_id, {"status": "undeclared"}),
            "invocation": value["invocation"],
            "timeout_seconds": value["invocation"].get(
                "timeout_seconds",
                registry.get("execution_policy", {}).get("default_timeout_seconds", 1800),
            ),
            "evidence_kind": evidence_kinds.get(
                gate_id, value.get("evidence", {}).get("kind", "unspecified")
            ),
            "negative_control_ids": [
                control["id"] for control in value["negative_controls"]
            ],
            "negative_controls": value["negative_controls"],
            "evidence": value.get("evidence", {}),
        }
        for gate_id, value in sorted(gates.items())
    ]


def _schema_inventory(repo_root: Path, pattern: str) -> list[dict[str, str]]:
    return [
        {"path": path.relative_to(repo_root).as_posix(), "sha256": _digest(path)}
        for path in sorted(repo_root.glob(pattern))
        if path.is_file() and not path.is_symlink()
    ]


def _optional_yaml(repo_root: Path, relative: str) -> dict[str, Any]:
    path = repo_root / relative
    return load_yaml_path(path) if path.is_file() and not path.is_symlink() else {}


def _event(event: dict[str, Any]) -> dict[str, Any]:
    return {key: event[key] for key in sorted(event)}


def _effective_graph(compiled: CompiledCIGraph) -> list[dict[str, Any]]:
    graph = compiled.graph
    result = []
    for workflow in compiled.workflows:
        jobs = []
        for job in workflow["jobs"]:
            resource = graph["resource_classes"][job["resource_class"]]
            jobs.append(
                {
                    "id": job["id"],
                    "display_name": job["display_name"],
                    "semantic_role": job["semantic_role"],
                    "needs": list(job["needs"]),
                    "condition": job["condition"],
                    "timeout_minutes": job["timeout_minutes"],
                    "resource_class": job["resource_class"],
                    "runner": resource["runner"],
                    "trust": job["trust"],
                    "permissions": dict(sorted(job["permissions"].items())),
                    "matrix": job.get("strategy", {}).get("matrix", job.get("matrix", {})),
                    "checkout": job["checkout"],
                    "components": list(job["components"]),
                    "environment": dict(sorted(job["environment"].items())),
                    "outputs": dict(sorted(job["outputs"].items())),
                    "controller_requirement": job["controller_requirement"],
                    "executor": job["executor"],
                    "produces": list(job["produces"]),
                    "consumes": list(job["consumes"]),
                    "required": job["required"],
                }
            )
        result.append(
            {
                "id": workflow["id"],
                "path": workflow["path"],
                "display_name": workflow["display_name"],
                "role": workflow["role"],
                "events": [_event(value) for value in workflow["events"]],
                "permissions": dict(sorted(workflow["permissions"].items())),
                "environment": dict(sorted(workflow["environment"].items())),
                "concurrency": workflow.get("concurrency"),
                "jobs": jobs,
            }
        )
    return result


def _gate_consumers(compiled: CompiledCIGraph) -> list[str]:
    return sorted(
        f"{workflow['id']}/{job['id']}"
        for workflow in compiled.workflows
        for job in workflow["jobs"]
        if job["executor"]["kind"] in {"gate_group", "gate_shard", "terminal_truth", "truth"}
    )


def _artifact_consumers(compiled: CompiledCIGraph) -> list[str]:
    return sorted(
        f"{workflow['id']}/{job['id']}:{direction}:{artifact}"
        for workflow in compiled.workflows
        for job in workflow["jobs"]
        for direction in ("produces", "consumes")
        for artifact in job[direction]
    )


def _authority_map(compiled: CompiledCIGraph) -> list[dict[str, Any]]:
    workflow_paths = sorted(item["path"] for item in compiled.workflows)
    gate_consumers = _gate_consumers(compiled)
    artifact_consumers = _artifact_consumers(compiled)
    return [
        {
            "fact": "workflow_topology",
            "source": "governance/ci-graph.yml plus registered ci-extensions",
            "consumers": workflow_paths,
            "synchronization": "deterministically rendered",
            "drift_detection": "bcf ci graph render --check",
            "change_failure": "cycles, missing edges, unreachable artifact fan-in, or hand edits fail before execution",
        },
        {
            "fact": "gate_commands_and_required_inventory",
            "source": "governance/gate-contracts.yml and governance-profile.yml",
            "consumers": gate_consumers + ["Makefile.fragment", "governance truth"],
            "synchronization": "derived by profile, manifest, graph, and evidence helpers",
            "drift_detection": "governance validation plus exact test-manifest and graph validation",
            "change_failure": "missing, duplicate, skipped, malformed, or unsuccessful evidence fails closed",
        },
        {
            "fact": "artifact_and_receipt_contracts",
            "source": "governance/ci-graph.yml, schemas/evidence-receipt.schema.json, and evidence-session.json",
            "consumers": artifact_consumers + ["governance truth"],
            "synchronization": "rendered artifact actions and exact run-attempt receipt admission",
            "drift_detection": "graph compilation, generated-byte parity, session binding, and receipt admission",
            "change_failure": "undeclared, duplicated, malformed, wrong-subject, replayed, or mixed evidence invalidates truth",
        },
        {
            "fact": "workflow_identity_and_expected_jobs",
            "source": "compiled workflow bytes and governance/ci-authority.yml",
            "consumers": ["trusted admission", "finalizers", "status publishers", "release authority"],
            "synchronization": "bcf ci pin-authority compiles workflow blobs, matrices, and expected jobs",
            "drift_detection": "workflow authority and self-controller validation",
            "change_failure": "renamed, missing, extra, failed, cancelled, or stale jobs revoke authority",
        },
        {
            "fact": "runner_permissions_conditions_and_dispatch",
            "source": "governance/ci-graph.yml plus registered extensions",
            "consumers": workflow_paths,
            "synchronization": "deterministically rendered",
            "drift_detection": "graph trust checks, event simulation, diagnostics, and byte parity",
            "change_failure": "missing mapping, unsafe authority, undeclared input, or hosted waiter blocks compilation",
        },
        {
            "fact": "test_populations",
            "source": "governance/test-manifests/*.txt collected from gate selectors",
            "consumers": ["gate receipts", "preflight", "governance truth"],
            "synchronization": "bcf test-manifest collect/check",
            "drift_detection": "exact node-manifest comparison",
            "change_failure": "missing, extra, skipped, or duplicated nodes invalidate evidence",
        },
        {
            "fact": "gate_and_outer_job_timeouts",
            "source": "governance/gate-contracts.yml execution_policy and ci-graph job timeout_minutes",
            "consumers": gate_consumers,
            "synchronization": "evidence runtime consumes the gate timeout; graph compiler compares outer headroom",
            "drift_detection": "bcf ci graph validate",
            "change_failure": "an outer evidence deadline shorter than one inner gate deadline plus headroom fails compilation",
        },
        {
            "fact": "automation_dependency_versions_and_changelog",
            "source": "authenticated exact base/head manifest bytes selected by governance/automation-producers.yml",
            "consumers": ["trusted automation reconciler", "CHANGELOG.md"],
            "synchronization": "typed manifest decoders derive dependency, previous version, and new version",
            "drift_detection": "automation registry validation and changelog projection controls",
            "change_failure": "unsupported, ambiguous, prose-derived, or versionless changes are rejected before write authority",
        },
    ]


def audit_ci_graph(repo_root: Path) -> dict[str, Any]:
    """Return the complete reproducible local authority report without mutating state."""

    root = repo_root.resolve()
    compiled = validate_ci_graph(root)
    inventory = inventory_github_workflows(root)
    render = check_ci_graph(root)
    default_timeout, overrides = gate_timeout_contract(root)
    test_manifests = _test_manifest_inventory(root)
    gate_inventory = _gate_inventory(root)
    dependency_paths = _tracked(
        root,
        (
            ":(glob)**/pyproject.toml",
            ":(glob)**/requirements*.txt",
            ":(glob)**/*.lock",
            ":(glob)**/package*.json",
            ":(glob)**/Dockerfile*",
            ".github/dependabot.yml",
        ),
    )
    protection = _optional_yaml(root, "governance/github-protection.yml")
    authority = _optional_yaml(root, "governance/ci-authority.yml")
    dependabot = _optional_yaml(root, ".github/dependabot.yml")
    expected_job_sets = sum(
        1
        for value in authority.get("workflow_registry", {}).values()
        if isinstance(value, dict) and "expected_jobs" in value
    )
    workflows = _effective_graph(compiled)
    jobs = [job for workflow in workflows for job in workflow["jobs"]]
    repository_workflows = inventory["workflows"]
    repository_jobs = [
        job for workflow in repository_workflows for job in workflow["jobs"]
    ]
    generated_paths = {workflow["path"] for workflow in workflows}
    report = {
        "schema_version": "1.0",
        "status": "pass" if render.status == "clean" else "fail",
        "subject": inventory["subject"],
        "repository_state": _repository_state(root),
        "canonical_graph": {
            "path": "governance/ci-graph.yml",
            "sha256": compiled.graph_sha256,
            "extensions": dict(compiled.extension_sha256),
            "locked_inputs": dict(compiled.input_sha256),
            "generated_parity": render.status,
        },
        "inventory": {
            "workflow_count": len(repository_workflows),
            "job_count": len(repository_jobs),
            "compiled_workflow_count": len(workflows),
            "compiled_job_count": len(jobs),
            "semantic_role_count": len({job["semantic_role"] for job in jobs}),
            "repository_workflows": repository_workflows,
            "unmanaged_workflow_paths": sorted(
                workflow["path"]
                for workflow in repository_workflows
                if workflow["path"] not in generated_paths
            ),
            "artifact_count": len(compiled.graph["artifacts"]),
            "gate_count": len(gate_inventory),
            "gates": gate_inventory,
            "test_manifests": test_manifests,
            "make_targets": _make_targets(root),
            "dependency_surfaces": dependency_paths,
            "dependabot_update_rules": dependabot.get("updates", []),
            "artifacts": dict(sorted(compiled.graph["artifacts"].items())),
            "commands": dict(sorted(compiled.graph["commands"].items())),
            "conditions": dict(sorted(compiled.graph["conditions"].items())),
            "step_components": dict(
                sorted(compiled.graph["step_components"].items())
            ),
            "resource_classes": dict(
                sorted(compiled.graph["resource_classes"].items())
            ),
            "graph_policy": compiled.graph["policy"],
            "receipt_schemas": _schema_inventory(root, "schemas/*receipt*.schema.json"),
            "truth_claim_dependencies": load_yaml_path(
                root / "governance/evidence-policy.yml"
            )["claim_dependencies"],
            "required_status_checks": protection.get("ruleset", {}).get(
                "required_status_checks", []
            ),
            "compiled_expected_job_sets": expected_job_sets,
        },
        "timeout_contract": {
            "default_gate_seconds": default_timeout,
            "per_gate_seconds": dict(sorted(overrides.items())),
            "minimum_outer_headroom_seconds": compiled.graph["policy"].get(
                "minimum_gate_timeout_headroom_seconds", 60
            ),
        },
        "authority_map": _authority_map(compiled),
        "effective_graph": workflows,
        "mechanical_findings": [],
        "remaining_manual_authority": [
            {
                "fact": "provider_runner_availability_permissions_secrets_and_ruleset_state",
                "owner": "repository owner and GitHub provider",
                "justification": "external provider state cannot be inferred from repository bytes; inspect it before dispatch or mutation",
            },
            {
                "fact": "risk_intent_and_graph_policy_changes",
                "owner": "explicit human authority",
                "justification": "mechanics validate and render declared intent but do not choose risk appetite",
            },
        ],
    }
    report["report_sha256"] = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return report
