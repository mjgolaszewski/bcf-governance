"""Portable planner-derived evidence shard execution."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_timeouts import gate_deadline_contract, gate_sequence_deadline_ms, LEGACY_HEADROOM_SECONDS, validate_gate_job_timeouts
from .ci_github_api import GitHubAPI
from .ci_github_errors import GitHubAPIError
from .ci_graph_execution import (
    declared_workflow_context,
    local_gate_job_environments,
    resolve_local_job_environment,
)
from .evidence_sessions import load_session, select_session
from .evidence_session_schema import is_planned_session
from .evidence_test_adapters import captured_receipt_succeeded
from .governance_evidence import capture_gate
from .test_splinter_proofs import materialize_prior_provider_proofs
from .semantic_yaml import load_unique_mapping_text


SHARD_DISPLAY_NAMES = tuple(f"Evidence shard {index}" for index in range(4))


def _mapping(path: Path, repo_root: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(repo_root)} must contain an object")
    return value


def required_gate_targets(repo_root: Path) -> list[str]:
    """Resolve required targets from profile applicability and executable ownership."""

    profile = _mapping(repo_root / "governance-profile.yml", repo_root)
    contracts = _mapping(repo_root / "governance/gate-contracts.yml", repo_root)
    catalog = contracts.get("gate_catalog")
    executable = contracts.get("gates")
    configured = profile.get("release_gate_profile", {}).get("gates")
    if not all(isinstance(value, dict) for value in (catalog, executable, configured)):
        raise ValueError("gate profile and contracts must contain mappings")
    targets = sorted(
        str(value["target"])
        for value in configured.values()
        if isinstance(value, dict) and value.get("status") == "required"
    )
    if len(targets) != len(set(targets)):
        raise ValueError("required gate targets must be unique")
    catalog_targets = {
        str(value.get("target")) for value in catalog.values() if isinstance(value, dict)
    }
    if any(target not in executable or target not in catalog_targets for target in targets):
        raise ValueError("every required target needs one executable catalog owner")
    return targets


def local_gate_execution_environments(
    repo_root: Path,
    graph: dict[str, Any],
    producers: tuple[str, ...],
) -> dict[str, dict[str, str]]:
    """Bind local gates to graph jobs or the closed profile-v1 direct lane."""

    profile = _mapping(repo_root / "governance-profile.yml", repo_root)
    allowed_unmapped: frozenset[str] = frozenset()
    if str(profile.get("profile_contract_version", "1.0")) == "1.0":
        ci_profile = profile.get("ci_profile")
        required_push_jobs = (
            ci_profile.get("required_push_jobs")
            if isinstance(ci_profile, dict)
            else None
        )
        if (
            not isinstance(required_push_jobs, list)
            or not all(isinstance(value, str) and value for value in required_push_jobs)
            or len(required_push_jobs) != len(set(required_push_jobs))
        ):
            raise ValueError(
                "profile-v1 local execution requires exact unique required_push_jobs"
            )
        required = set(required_gate_targets(repo_root))
        invalid = sorted(set(required_push_jobs) - required)
        if invalid:
            raise ValueError(
                "profile-v1 required_push_jobs are not required executable gates: "
                + ", ".join(invalid)
            )
        allowed_unmapped = frozenset(required_push_jobs)
    return local_gate_job_environments(
        graph, producers, allowed_unmapped=allowed_unmapped
    )


def partition_required_gates(
    repo_root: Path,
    *,
    shard_index: int,
    shard_count: int,
    planned_targets: list[str] | None = None,
    execution_dag: dict[str, Any] | None = None,
) -> list[str]:
    if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard index must be within the positive shard count")
    if execution_dag is not None:
        nodes = execution_dag.get("nodes")
        edges = execution_dag.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise ValueError("planned execution DAG must contain nodes and edges")
        assignments: dict[str, int] = {}
        node_ids: set[str] = set()
        expected_edges: list[dict[str, str]] = []
        for node in nodes:
            if not isinstance(node, dict):
                raise ValueError("planned execution DAG node must be an object")
            producer = node.get("producer")
            assigned = node.get("assigned_shard")
            if (
                not isinstance(producer, str)
                or not producer
                or isinstance(assigned, bool)
                or not isinstance(assigned, int)
                or assigned < 0
                or assigned >= shard_count
                or producer in assignments
                or not isinstance(node.get("id"), str)
                or node["id"] in node_ids
                or not isinstance(node.get("depends_on"), list)
            ):
                raise ValueError("planned shard assignment is incomplete or ambiguous")
            assignments[producer] = assigned
            node_ids.add(node["id"])
        by_id = {str(node["id"]): node for node in nodes}
        dependents: dict[str, list[str]] = {node_id: [] for node_id in by_id}
        indegree: dict[str, int] = {}
        for node in nodes:
            indegree[node["id"]] = len(node["depends_on"])
            for dependency in node["depends_on"]:
                if (
                    not isinstance(dependency, str)
                    or dependency not in by_id
                    or by_id[dependency]["assigned_shard"] != node["assigned_shard"]
                ):
                    raise ValueError("planned execution dependency is not ordered on one shard")
                dependents[dependency].append(node["id"])
                expected_edges.append({"from": dependency, "to": node["id"]})
        observed_edges = [
            (edge.get("from"), edge.get("to")) if isinstance(edge, dict) else (None, None)
            for edge in edges
        ]
        canonical_edges = [(edge["from"], edge["to"]) for edge in expected_edges]
        if len(observed_edges) != len(set(observed_edges)) or set(observed_edges) != set(canonical_edges):
            raise ValueError("planned execution DAG edges differ from node dependencies")
        ready = sorted(node_id for node_id, count in indegree.items() if count == 0)
        ordered: list[str] = []
        while ready:
            node_id = ready.pop(0)
            ordered.append(node_id)
            for dependent in sorted(dependents[node_id]):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    ready.append(dependent)
                    ready.sort()
        if len(ordered) != len(nodes):
            raise ValueError("planned execution dependencies contain a cycle")
        targets = planned_targets or []
        if set(assignments) != set(targets):
            raise ValueError("planned shard assignment differs from gate inventory")
        return [
            str(by_id[node_id]["producer"])
            for node_id in ordered
            if by_id[node_id]["assigned_shard"] == shard_index
        ]
    targets = planned_targets if planned_targets is not None else required_gate_targets(repo_root)
    return [gate for index, gate in enumerate(targets) if index % shard_count == shard_index]


def workflow_shard_matrix() -> dict[str, list[Any]]:
    return {
        "shard": list(range(len(SHARD_DISPLAY_NAMES))),
        "include": [
            {"shard": index, "display_name": display_name}
            for index, display_name in enumerate(SHARD_DISPLAY_NAMES)
        ],
    }


def planned_gate_targets(
    repo_root: Path,
    *,
    planned_targets: list[str] | None,
    execution_dag: dict[str, Any] | None,
) -> list[str]:
    """Return every planned producer once in canonical local execution order."""

    if execution_dag is None:
        return planned_targets if planned_targets is not None else required_gate_targets(repo_root)
    nodes = execution_dag.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        if nodes == [] and planned_targets == [] and execution_dag.get("edges") == []:
            return []
        raise ValueError("planned execution DAG must contain its gate inventory")
    assignments = [
        node.get("assigned_shard") if isinstance(node, dict) else None for node in nodes
    ]
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in assignments):
        raise ValueError("planned shard assignment is incomplete or ambiguous")
    shard_count = max(assignments) + 1
    return [
        gate
        for shard_index in sorted(set(assignments))
        for gate in partition_required_gates(
            repo_root,
            shard_index=shard_index,
            shard_count=shard_count,
            planned_targets=planned_targets,
            execution_dag=execution_dag,
        )
    ]


def validate_planned_shard_deadlines(
    repo_root: Path, graph: dict[str, Any], planned_targets: list[str],
    execution_dag: dict[str, Any] | None, *, shard_count: int | None = None,
    workflow_id: str | None = None,
) -> None:
    """Bind every actual assignment to its existing executor before work."""
    try:
        workflows = [workflow for workflow in graph["workflows"]
                     if workflow["id"] == workflow_id] if workflow_id is not None else [
                         workflow for workflow in graph["workflows"]
                         if any(event.get("type") == "pull_request" for event in workflow["events"])]
        if workflow_id is not None and len(workflows) != 1:
            raise ValueError("planned shard workflow context is missing or ambiguous")
        if shard_count is not None and (type(shard_count) is not int or shard_count < 1):
            raise ValueError("runtime shard count is invalid")
        if len(set(planned_targets)) != len(planned_targets) or any(
            not isinstance(gate, str) or not gate for gate in planned_targets
        ):
            raise ValueError("planned shard inventory is ambiguous")
        if not planned_targets:
            partition_required_gates(repo_root, shard_index=0, shard_count=1,
                                     planned_targets=[], execution_dag=execution_dag)
            return
        jobs = [job for workflow in workflows
                for job in workflow["jobs"]
                if job["executor"]["kind"] in {"gate_group", "gate_shard"}]
        owners = {gate: [index for index, job in enumerate(jobs)
                         if gate in job["executor"]["gates"]] for gate in planned_targets}
        if any(len(values) > 1 for values in owners.values()):
            raise ValueError("planned shard inventory lacks one exact executor owner")
        missing = [gate for gate, values in owners.items() if not values]
        if missing and workflow_id is not None:
            raise ValueError("planned shard inventory lacks its bound workflow owner")
        if missing:
            local_gate_execution_environments(repo_root, graph, tuple(missing))
        selected = {values[0] for values in owners.values() if values}
        shards = [jobs[index] for index in selected if jobs[index]["executor"]["kind"] == "gate_shard"]
        if not shards:
            partition_required_gates(repo_root, shard_index=0, shard_count=len(SHARD_DISPLAY_NAMES),
                                     planned_targets=planned_targets, execution_dag=execution_dag)
            return  # Fixed groups already contain their full declared populations.
        if missing or len(selected) != 1:
            raise ValueError("planned shard inventory crosses unfiltered executor jobs")
        default, overrides, cleanup = gate_deadline_contract(repo_root)
        headroom = graph["policy"].get("minimum_gate_timeout_headroom_seconds", LEGACY_HEADROOM_SECONDS)
        if type(headroom) is not int or headroom < 1:
            raise ValueError("planned shard headroom is invalid")
        for job in shards:
            count = job["executor"].get("shard_count")
            if type(count) is not int or count < 1 or (shard_count is not None and shard_count != count):
                raise ValueError("planned shard count contradicts its executor")
            for index in range(count):
                gates = partition_required_gates(repo_root, shard_index=index, shard_count=count,
                    planned_targets=planned_targets, execution_dag=execution_dag)
                if not gates:
                    continue
                required = gate_sequence_deadline_ms(
                    [overrides.get(gate, default) for gate in gates], cleanup=cleanup, headroom=headroom,
                ) // 1000
                available = job["timeout_minutes"] * 60
                if available < required:
                    raise ValueError(f"planned shard {job['id']}/{index} timeout {available}s cannot contain "
                                     f"{required}s composed gate bounds")
    except (TypeError, KeyError, ValueError, OSError) as exc:
        raise CIGraphError(str(exc)) from exc


def _physical_deadline_graph(graph: dict[str, Any], workflow_id: str) -> dict[str, Any]:
    """Constrain declared budgets by exact provider-owned defining source bytes."""
    environment = os.environ
    repository = environment.get('BCF_JOB_WORKFLOW_REPOSITORY', '')
    path = environment.get('BCF_JOB_WORKFLOW_FILE_PATH', '')
    sha = environment.get('BCF_JOB_WORKFLOW_SHA', '')
    if not repository or not path or not sha:
        raise CIGraphError('physical workflow deadline requires defining source coordinates')
    try:
        source = GitHubAPI(token=environment.get('GITHUB_TOKEN', ''),
            api_url=environment.get('GITHUB_API_URL', 'https://api.github.com')).content(
                repository, path, ref=sha)
        raw = source.content
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if source.path != path or source.blob_oid != blob:
            raise ValueError('physical workflow source path or blob does not match')
        document = load_unique_mapping_text(raw.decode('utf-8'))
        physical_jobs = document.get('jobs')
        if not isinstance(physical_jobs, dict):
            raise ValueError('physical workflow lacks job definitions')
        bounded = copy.deepcopy(graph)
        workflow = next(value for value in bounded['workflows'] if value['id'] == workflow_id)
        for job in workflow['jobs']:
            if job['executor']['kind'] not in {'gate_shard', 'gate_group'}:
                continue
            physical = physical_jobs.get(job['id'])
            timeout = physical.get('timeout-minutes') if isinstance(physical, dict) else None
            if type(timeout) is not int or not 1 <= timeout <= 360:
                raise ValueError('physical workflow job deadline is missing or not a bounded literal')
            job['timeout_minutes'] = min(job['timeout_minutes'], timeout)
        return bounded
    except (GitHubAPIError, ValueError, TypeError, KeyError, UnicodeError, StopIteration) as exc:
        raise CIGraphError(f'physical workflow deadline is not authenticated: {exc}') from exc


def admit_planned_shard_deadlines(
    repo_root: Path, plan: dict[str, Any], *, shard_count: int | None = None,
) -> None:
    """Keep graph-absent local legacy scope; require modern graph authority."""
    path = repo_root / "governance/ci-graph.yml"
    if not path.exists() and not path.is_symlink():
        profile_path = repo_root / "governance-profile.yml"
        profile = _mapping(profile_path, repo_root) if profile_path.exists() else {}
        if str(profile.get("profile_contract_version", "1.0")) != "1.0":
            raise CIGraphError("planned shard deadline admission requires the CI graph")
        return
    dag = plan.get("execution_dag")
    targets = plan.get("expected_gate_inventory")
    if targets is None and isinstance(dag, dict) and isinstance(dag.get("nodes"), list):
        targets = [node.get("producer") if isinstance(node, dict) else None for node in dag["nodes"]]
    if not isinstance(targets, list):
        raise CIGraphError("planned shard deadline inventory is missing")
    graph = validate_ci_graph(repo_root).graph
    workflow_id = declared_workflow_context(graph, os.environ)
    validate_planned_shard_deadlines(repo_root, graph, targets, dag,
                                    shard_count=shard_count, workflow_id=workflow_id)
    if workflow_id is not None:
        physical = _physical_deadline_graph(graph, workflow_id)
        validate_gate_job_timeouts(repo_root, {**physical, 'workflows': [
            workflow for workflow in physical['workflows'] if workflow['id'] == workflow_id]})
        validate_planned_shard_deadlines(repo_root, physical, targets, dag,
                                        shard_count=shard_count, workflow_id=workflow_id)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--shard-count", type=int)
    parser.add_argument("--all-planned", action="store_true")
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--session-manifest", type=Path)
    parser.add_argument("--session-root", type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    explicit = args.output_root is not None or args.session_manifest is not None
    if explicit == (args.session_root is not None):
        raise SystemExit("provide both --output-root/--session-manifest or only --session-root")
    if explicit:
        if args.output_root is None or args.session_manifest is None:
            raise SystemExit("explicit evidence session requires both paths")
        output_root = args.output_root
        session_manifest = args.session_manifest
        session = load_session(session_manifest) if session_manifest.is_file() else None
    else:
        session = select_session(args.session_root)
        session_manifest = session.manifest_path
        output_root = session.root
    planned = (
        [str(value) for value in session.payload.get("expected_gate_inventory", [])]
        if session is not None and is_planned_session(session.payload)
        else None
    )
    execution_dag = (
        session.payload.get("execution_dag")
        if session is not None and is_planned_session(session.payload)
        else None
    )
    if args.all_planned:
        if args.shard_index is not None or args.shard_count is not None:
            raise SystemExit("--all-planned cannot be combined with shard coordinates")
        gates = planned_gate_targets(
            repo_root, planned_targets=planned, execution_dag=execution_dag
        )
        graph_environments = local_gate_execution_environments(
            repo_root, validate_ci_graph(repo_root).graph, tuple(gates)
        )
    else:
        if args.shard_index is None or args.shard_count is None:
            raise SystemExit("provide shard coordinates or --all-planned")
        gates = partition_required_gates(
            repo_root,
            shard_index=args.shard_index,
            shard_count=args.shard_count,
            planned_targets=planned,
            execution_dag=execution_dag,
        )
    admit_planned_shard_deadlines(repo_root, {
        "expected_gate_inventory": planned if planned is not None else required_gate_targets(repo_root),
        "execution_dag": execution_dag,
    }, shard_count=args.shard_count)
    prior_temp: tempfile.TemporaryDirectory[str] | None = None
    try:
        if not args.all_planned and "test" in gates and os.environ.get("GITHUB_ACTIONS") == "true":
            prior_temp = tempfile.TemporaryDirectory(prefix="bcf-prior-splinter-proofs-")
            prior_root = Path(prior_temp.name)
            report = materialize_prior_provider_proofs(
                GitHubAPI(
                    token=os.environ.get("GITHUB_TOKEN", ""),
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                ),
                prior_root,
                repository=os.environ.get("GITHUB_REPOSITORY", ""),
                repository_id=os.environ.get("GITHUB_REPOSITORY_ID", ""),
                head_sha=os.environ.get("GITHUB_SHA", ""),
                run_id=os.environ.get("GITHUB_RUN_ID", ""),
                current_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")),
                job=os.environ.get("GITHUB_JOB", ""),
                shard=int(args.shard_index),
            )
            (prior_root / "provider.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            os.environ["BCF_PRIOR_SPLINTER_PROOF_ROOT"] = str(prior_root)
            os.environ["BCF_EVIDENCE_SHARD"] = str(args.shard_index)
        for gate in gates:
            if args.all_planned:
                receipt = capture_gate(
                    repo_root,
                    gate,
                    output_root / gate,
                    python_executable=sys.executable,
                    session_manifest=session_manifest,
                    job_environment=resolve_local_job_environment(
                        graph_environments[gate], repo_root
                    ),
                )
                if not captured_receipt_succeeded(receipt):
                    raise SystemExit(1)
                continue
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/governance_evidence.py",
                    "--repo-root",
                    ".",
                    "run",
                    "--gate",
                    gate,
                    "--output",
                    str(output_root / gate),
                    "--python",
                    sys.executable,
                    "--session-manifest",
                    str(session_manifest),
                ],
                cwd=repo_root,
                check=False,
            )
            if result.returncode:
                raise SystemExit(result.returncode)
    finally:
        if prior_temp is not None:
            prior_temp.cleanup()


if __name__ == "__main__":
    main()
