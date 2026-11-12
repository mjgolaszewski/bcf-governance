"""Deterministic authority and duplication report for one compiled CI graph."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .ci_graph_contracts import CompiledCIGraph, validate_ci_graph
from .ci_graph_import import inventory_github_workflows
from .ci_graph_render import check_ci_graph
from .ci_graph_routing import routing_audit
from .ci_graph_timeouts import INTERPRETER_PROBE_TIMEOUT_SECONDS, gate_deadline_contract, gate_cleanup_timeout_seconds
from .ci_graph_yaml import load_yaml_path
from .evidence_gate_contracts import expected_evidence_kinds
from .semantic_source_paths import _source_git


def _tracked(repo_root: Path, patterns: tuple[str, ...]) -> list[str]:
    result = _source_git(repo_root, "ls-files", "-z", "--", *patterns)
    return sorted(line for line in result.stdout.decode("utf-8").split("\0") if line) if result.returncode == 0 else []


def _source_history_snapshot(repo_root: Path) -> dict[str, Any]:
    """Observe registered Git identities; source bytes and clone coverage are separate."""
    identity = _source_git(repo_root, "rev-parse", "HEAD", "HEAD^{tree}")
    common = _source_git(repo_root, "rev-parse", "--git-common-dir")
    branch = _source_git(repo_root, "symbolic-ref", "-q", "HEAD")
    worktrees = _source_git(repo_root, "worktree", "list", "--porcelain", "-z")
    refs = _source_git(repo_root, "for-each-ref", "--format=%(refname)%00%(objectname)%00%(tree)", "refs/heads/")
    if any(row.returncode for row in (identity, common, worktrees, refs)) or branch.returncode not in (0, 1):
        raise ValueError("registered source-history discovery failed")
    subject = identity.stdout.decode("ascii").splitlines()
    if len(subject) != 2 or any(re.fullmatch(r"[a-f0-9]{40}", value) is None for value in subject):
        raise ValueError("registered source-history subject is not exact")
    common_path = (repo_root / common.stdout.decode("utf-8").rstrip("\n")).resolve()
    subject_branch = branch.stdout.decode("utf-8").rstrip("\n") if branch.returncode == 0 else None
    branches = []
    for raw in refs.stdout.splitlines():
        fields = raw.decode("utf-8").split("\0")
        if len(fields) != 3 or not fields[0].startswith("refs/heads/") or any(
            re.fullmatch(r"[a-f0-9]{40}", value) is None for value in fields[1:]
        ):
            raise ValueError("registered branch inventory is malformed")
        ancestry = _source_git(repo_root, "merge-base", "--is-ancestor", fields[1], subject[0])
        if ancestry.returncode not in (0, 1):
            raise ValueError("registered branch ancestry is unavailable")
        branches.append(dict(ref=fields[0], commit_sha=fields[1], tree_sha=fields[2],
                             ancestor_of_subject=ancestry.returncode == 0))
    roots = []
    if worktrees.stdout and not worktrees.stdout.endswith(b"\0\0"):
        raise ValueError("registered worktree inventory is malformed")
    for block in worktrees.stdout.split(b"\0\0"):
        if not block:
            continue
        values = {}
        for raw in block.split(b"\0"):
            key, _, value = raw.partition(b" ")
            name = key.decode("ascii")
            if name not in {"worktree", "HEAD", "branch", "bare", "detached", "locked", "prunable"} or name in values:
                raise ValueError("registered worktree metadata is ambiguous")
            values[name] = value.decode("utf-8")
        if not values.get("worktree"):
            raise ValueError("registered worktree path is absent")
        if "bare" not in values and (
                ("branch" in values) == ("detached" in values)
                or re.fullmatch(r"[a-f0-9]{40}", values.get("HEAD", "")) is None):
            raise ValueError("registered worktree branch metadata is contradictory")
        path = Path(values["worktree"])
        if not path.is_absolute():
            raise ValueError("registered worktree path is not absolute")
        row = dict(path=str(path), head_sha=values.get("HEAD"), branch_ref=values.get("branch"),
                   locked=values.get("locked"), prunable=values.get("prunable"), available=False)
        roots.append(row)
        if "bare" in values or not path.is_dir():
            row["unresolved"] = "bare_or_missing_registered_checkout"
            continue
        observed = _source_git(path, "rev-parse", "HEAD", "HEAD^{tree}")
        peer_common = _source_git(path, "rev-parse", "--git-common-dir")
        peer_branch = _source_git(path, "symbolic-ref", "-q", "HEAD")
        status = _source_git(path, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        untracked = _source_git(path, "ls-files", "-z", "--others", "--exclude-standard", "--")
        if any(value.returncode for value in (observed, peer_common, status, untracked)) or peer_branch.returncode not in (0, 1):
            row["unresolved"] = "registered_checkout_read_unavailable"
            continue
        peer_identity = observed.stdout.decode("ascii").splitlines()
        peer_ref = peer_branch.stdout.decode("utf-8").rstrip("\n") if peer_branch.returncode == 0 else None
        if (len(peer_identity) != 2 or peer_identity[0] != values.get("HEAD")
                or peer_ref != values.get("branch")
                or (path / peer_common.stdout.decode("utf-8").rstrip("\n")).resolve() != common_path):
            row["unresolved"] = "registered_checkout_identity_mismatch"
            continue
        if any(re.fullmatch(r"[a-f0-9]{40}", value) is None for value in peer_identity):
            raise ValueError("registered checkout subject is not exact")
        row.update(available=True, tree_sha=peer_identity[1],
                   status_entries=sorted(value.decode("utf-8") for value in status.stdout.split(b"\0") if value),
                   untracked_paths=sorted(value.decode("utf-8") for value in untracked.stdout.split(b"\0") if value))
    if not roots or len({row["path"] for row in roots}) != len(roots):
        raise ValueError("registered worktree population is empty or duplicated")
    if not any(Path(row["path"]).resolve() == repo_root.resolve() and row["head_sha"] == subject[0]
               and row["branch_ref"] == subject_branch for row in roots):
        raise ValueError("active source subject is absent from registered worktrees")
    if subject_branch is not None and not any(row["ref"] == subject_branch and row["commit_sha"] == subject[0]
                                              for row in branches):
        raise ValueError("active source branch contradicts branch inventory")
    equal_trees: dict[str, set[str]] = {}
    for row in branches:
        equal_trees.setdefault(row["tree_sha"], set()).add(row["commit_sha"])
    return dict(subject=dict(commit_sha=subject[0], tree_sha=subject[1], branch_ref=subject_branch),
                worktrees=sorted(roots, key=lambda value: value["path"]),
                branches=sorted(branches, key=lambda value: value["ref"]),
                same_tree_distinct_commits=[dict(tree_sha=tree, commits=sorted(commits))
                    for tree, commits in sorted(equal_trees.items()) if len(commits) > 1])


def _repository_state(repo_root: Path) -> dict[str, Any]:
    result = _source_git(repo_root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if result.returncode:
        return {"available": False, "committed_clean": False}
    entries = sorted(value.decode("utf-8") for value in result.stdout.split(b"\0") if value)
    state = {
        "available": True,
        "committed_clean": not entries,
        "status_entries": entries,
        "status_sha256": hashlib.sha256(result.stdout).hexdigest(),
    }
    history = dict(schema_version="1.0", authority=False, execution_qualified=False,
                   scope="registered_git_worktrees_and_local_branch_tips", full_workspace_inventory=False,
                   independent_clone_discovery="unresolved", source_byte_custody="unresolved",
                   retirement_authorized=False, available=False, identity_observation_stable=False)
    try:
        captured = _source_history_snapshot(repo_root)
        consuming = _source_history_snapshot(repo_root)
        current_status = _source_git(repo_root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        stable = captured == consuming and current_status.returncode == 0 and current_status.stdout == result.stdout
        history.update(captured, identity_observation_stable=stable,
                       available=stable and all(row["available"] for row in captured["worktrees"]))
        if not stable:
            history["unresolved"] = "registered_source_identity_moved_during_capture"
        if current_status.returncode or current_status.stdout != result.stdout:
            state.update(available=False, committed_clean=False)
    except (OSError, ValueError, UnicodeError) as exc:
        history["unresolved"] = type(exc).__name__ + ": " + str(exc)
    state["source_history"] = history
    return state


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
            "cleanup_timeout_seconds": gate_cleanup_timeout_seconds(registry.get("execution_policy", {})),
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
                    **routing_audit(resource),
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
    default_timeout, overrides, cleanup_timeout = gate_deadline_contract(root)
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
        "schema_version": "1.1",
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
            "cleanup_timeout_seconds": cleanup_timeout,
            "interpreter_probe_seconds": INTERPRETER_PROBE_TIMEOUT_SECONDS,
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
