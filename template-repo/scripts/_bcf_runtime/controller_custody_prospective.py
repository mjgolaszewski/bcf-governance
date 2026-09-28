"""Executable prospective proof for controller-custody producer/consumer contracts."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Mapping, Sequence

from .ci_github_identity import GitHubControllerError
from .ci_graph_contracts import validate_ci_graph
from .ci_graph_post_merge import post_merge_evaluation
from .self_workflow_contracts import validate_self_workflow_contracts
from .controller_custody import compile_controller_custody


_BASE_ROUTED_JOBS = {
    ("exact-main-finalizer", "finalize"): (
        "project-custody-controller-route", "exact-main-finalize-effective"
    ),
    ("exact-main-publisher", "publish"): (
        "project-finalizer-controller-route", "exact-main-publish-effective"
    ),
}


def _workflow(graph: Mapping[str, Any], workflow_id: str) -> Mapping[str, Any]:
    matches = [item for item in graph["workflows"] if item.get("id") == workflow_id]
    if len(matches) != 1:
        raise GitHubControllerError(
            f"controller custody workflow {workflow_id} is not unique"
        )
    return matches[0]


def _job(
    graph: Mapping[str, Any], workflow_id: str, job_id: str
) -> Mapping[str, Any]:
    workflow = _workflow(graph, workflow_id)
    matches = [item for item in workflow["jobs"] if item.get("id") == job_id]
    if len(matches) != 1:
        raise GitHubControllerError(
            f"controller custody job {workflow_id}/{job_id} is not unique"
        )
    return matches[0]


def _components(job: Mapping[str, Any]) -> tuple[str, ...]:
    executor = job.get("executor")
    values = executor.get("components") if isinstance(executor, Mapping) else None
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise GitHubControllerError("controller custody consumer lacks component sequence")
    return tuple(values)


def _ordered(values: Sequence[str], first: str, second: str) -> bool:
    return first in values and second in values and values.index(first) < values.index(second)


def _custody(commit: str) -> dict[str, Any]:
    return compile_controller_custody(
        {
            "source": "source_policy",
            "subject": {"commit_sha": "1" * 40, "tree_sha": "2" * 40},
            "transition_ids": [],
            "pin": {
                "BCF_BOOTSTRAP_ARTIFACT_ID": "20",
                "BCF_BOOTSTRAP_ARTIFACT_NAME": f"bcf-trusted-control-{commit}-1",
                "BCF_BOOTSTRAP_ARTIFACT_DIGEST": "sha256:" + "3" * 64,
                "BCF_BOOTSTRAP_RUN_ID": "10",
                "BCF_BOOTSTRAP_RUN_ATTEMPT": "1",
                "BCF_BOOTSTRAP_COMMIT_SHA": commit,
                "BCF_BOOTSTRAP_TREE_SHA": "2" * 40,
                "BCF_BOOTSTRAP_REPOSITORY_ID": "1207503211",
                "BCF_BOOTSTRAP_WHEEL_SHA256": "4" * 64,
            },
        },
        repository="owner/repository",
    )


def _route(
    argv: Sequence[str], *, python_executable: Path, payload: Mapping[str, Any],
    expected_commit: str,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="bcf-controller-route-") as temporary:
        root = Path(temporary)
        source = root / "producer.json"
        output = root / "github-output"
        source.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        command = [
            str(python_executable) if value == "{python}" else value for value in argv
        ]
        result = subprocess.run(
            command,
            cwd=root,
            env={
                "BCF_CONTROLLER_ROUTE_FILE": str(source),
                "GITHUB_OUTPUT": str(output),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and output.read_text(encoding="utf-8") != (
            f"controller_commit_sha={expected_commit}\n"
        ):
            raise GitHubControllerError("controller route projected a different identity")
        return result


def validate_controller_custody_chain(
    graph: Mapping[str, Any], *, python_executable: Path
) -> dict[str, Any]:
    """Execute every producer shape and verify every privileged consumer route."""

    trusted_controller = graph.get("trusted_controller")
    if not isinstance(trusted_controller, Mapping) or trusted_controller.get("kind") == "executable":
        return {
            "status": "not_adopted",
            "producer_shapes": [],
            "privileged_consumers": [],
            "negative_permutations": 0,
        }
    workflow_ids = {str(value.get("id")) for value in graph["workflows"]}
    rotation_id = "controller-rotation"
    if rotation_id not in workflow_ids:
        raise GitHubControllerError("controller rotation workflow is unavailable")
    if "automation-reconcile" in workflow_ids:
        automation = _workflow(graph, "automation-reconcile")
        if (
            automation.get("events")
            != [{
                "type": "workflow_run",
                "workflows": ["bcf/automation-admission"],
                "types": ["completed"],
            }]
            or [job.get("id") for job in automation.get("jobs", [])]
            != ["reconcile"]
        ):
            raise GitHubControllerError(
                "automation reconciliation and controller rotation are not trigger-isolated"
            )
    rotation_contract = _workflow(graph, rotation_id)
    if rotation_contract.get("events") != [{
        "type": "workflow_run",
        "workflows": ["bcf/exact-main-admission"],
        "types": ["completed"],
    }]:
        raise GitHubControllerError(
            "controller rotation trigger is not exact-main isolated"
        )
    routed_jobs = {
        **_BASE_ROUTED_JOBS,
        ("exact-main-publisher", "rotation-callback"): (
            "project-rotation-outcome-route", "dispatch-routine-certification"
        ),
        (rotation_id, "authorize"): (
            "project-custody-controller-route", "authorize-routine-transition"
        ),
    }
    for (workflow_id, job_id), (route, consumer) in routed_jobs.items():
        job = _job(graph, workflow_id, job_id)
        components = _components(job)
        if not _ordered(components, route, consumer):
            raise GitHubControllerError(
                f"controller custody route does not precede {workflow_id}/{job_id}"
            )
        if job.get("trust") != "trusted":
            raise GitHubControllerError("controller custody consumer is not trusted")

    exact_admit = _job(graph, "exact-main", "admit")
    if exact_admit.get("needs") != ["trusted-controller-build"]:
        raise GitHubControllerError("exact-main admission target is not builder-routed")
    controller_builder = _job(graph, "exact-main", "trusted-controller-build")
    custody_components = _components(controller_builder)
    if not _ordered(
        custody_components, "project-controller-custody", "upload-controller-custody"
    ) or "controller-custody" not in controller_builder.get("produces", []):
        raise GitHubControllerError("exact-main route-custody producer is not closed")
    finalizer = _job(graph, "exact-main-finalizer", "finalize")
    finalizer_components = _components(finalizer)
    if (
        not _ordered(
            finalizer_components,
            "download-trigger-controller-custody",
            "upload-finalizer-controller-custody",
        )
        or finalizer.get("produces")
        != ["exact-main-certification", "finalizer-controller-custody"]
        or finalizer.get("consumes") != ["controller-custody"]
    ):
        raise GitHubControllerError(
            "finalizer controller-custody pass-through contract is not closed"
        )
    publisher = _job(graph, "exact-main-publisher", "publish")
    publisher_components = _components(publisher)
    if (
        not _ordered(
            publisher_components,
            "download-finalizer-controller-custody",
            "project-finalizer-controller-route",
        )
        or publisher.get("consumes")
        != ["exact-main-certification", "finalizer-controller-custody"]
    ):
        raise GitHubControllerError(
            "publisher controller-custody pass-through contract is not closed"
        )
    components = graph.get("step_components")
    upload = components.get("upload-finalizer-controller-custody", {})
    download = components.get("download-finalizer-controller-custody", {})
    if (
        upload.get("with")
        != {
            "name": (
                "bcf-finalizer-controller-custody-${{ github.run_id }}-"
                "${{ github.run_attempt }}"
            ),
            "path": "${{ runner.temp }}/bcf-controller-custody",
            "if-no-files-found": "error",
            "retention-days": 30,
        }
        or download.get("with")
        != {
            "name": (
                "bcf-finalizer-controller-custody-"
                "${{ github.event.workflow_run.id }}-"
                "${{ github.event.workflow_run.run_attempt }}"
            ),
            "github-token": "${{ github.token }}",
            "repository": "${{ github.repository }}",
            "run-id": "${{ github.event.workflow_run.id }}",
            "path": "${{ runner.temp }}/bcf-controller-custody",
        }
    ):
        raise GitHubControllerError(
            "finalizer controller-custody transport is not attempt-exact"
        )
    exact_commands = graph["commands"]
    privileged_commands = [
        "exact-main-finalize-effective",
        "exact-main-publish-effective",
        "authorize-routine-transition",
        "dispatch-routine-certification",
    ]
    if {"release-authority", "release-publisher"} <= workflow_ids:
        privileged_commands.extend((
            "resolve-release-inputs", "authorize-release",
            "resolve-release-publication", "publish-release",
        ))
    for command_id in privileged_commands:
        command = exact_commands.get(command_id)
        environment = command.get("environment") if isinstance(command, Mapping) else None
        if not isinstance(environment, Mapping) or (
            environment.get("BCF_CONTROLLER_EXECUTION_REQUIRED") != "true"
        ):
            raise GitHubControllerError(
                f"privileged controller command {command_id} lacks execution binding"
            )

    rotation = _workflow(graph, rotation_id)
    outcome = _job(graph, rotation_id, "outcome")
    if (
        outcome.get("condition") != "always"
        or outcome.get("needs") != ["authorize", "activate"]
        or outcome.get("produces") != ["controller-rotation-outcome"]
        or set(outcome.get("consumes", []))
        != {
            "controller-transition-decision",
            "controller-transition-active-callback-source",
        }
    ):
        raise GitHubControllerError("rotation outcome producer contract is not closed")
    if len([job for job in rotation["jobs"] if job.get("id") == "outcome"]) != 1:
        raise GitHubControllerError("rotation outcome producer is ambiguous")

    release_workflows = workflow_ids.intersection(
        {"release-authority", "release-publisher"}
    )
    if release_workflows and release_workflows != {
        "release-authority", "release-publisher"
    }:
        raise GitHubControllerError("release custody consumer topology is partial")
    for workflow_id in sorted(release_workflows):
        route = _job(graph, workflow_id, "controller-route")
        consumer_id = "authorize" if workflow_id == "release-authority" else "publish"
        consumer = _job(graph, workflow_id, consumer_id)
        if (
            route.get("trust") != "candidate"
            or route.get("controller_requirement") is not None
            or "controller-route" not in consumer.get("needs", [])
            or consumer.get("trust") != "trusted"
        ):
            raise GitHubControllerError(
                f"{workflow_id} route observation can confer authority"
            )

    pr_workflows = workflow_ids.intersection({"pr-finalizer", "pr-status-publisher"})
    if pr_workflows and pr_workflows != {"pr-finalizer", "pr-status-publisher"}:
        raise GitHubControllerError("PR authority consumer topology is partial")
    for workflow_id in sorted(pr_workflows):
        job_id = "finalize" if workflow_id == "pr-finalizer" else "publish"
        if any("controller-route" in value for value in _components(
            _job(graph, workflow_id, job_id)
        )):
            raise GitHubControllerError("PR authority was coupled to exact-main custody")

    route_command = exact_commands.get("project-controller-route")
    argv = route_command.get("argv") if isinstance(route_command, Mapping) else None
    if not isinstance(argv, list) or argv[:2] != ["{python}", "-c"]:
        raise GitHubControllerError("controller route bootstrap is not canonical")

    commit = "a" * 40
    custody = _custody(commit)
    payloads = {
        "admission_custody": custody,
        "certification": custody,
        "legacy_noncertifying_finalizer": custody,
        "no_transition": {"controller_custody": custody},
        "active_transition": {"artifact": {"commit_sha": commit}},
        "release_receipt": {"observations": {"controller_custody": custody}},
    }
    for name, payload in payloads.items():
        result = _route(
            argv, python_executable=python_executable, payload=payload,
            expected_commit=commit,
        )
        if result.returncode != 0:
            raise GitHubControllerError(
                f"controller route rejected producer contract {name}: {result.stderr.strip()}"
            )
    for payload in (
        {},
        {
            "controller": {"commit_sha": commit},
            "authority": {"controller_commit_sha": "b" * 40},
        },
        {"controller": {"commit_sha": "malformed"}},
    ):
        if _route(
            argv, python_executable=python_executable, payload=payload,
            expected_commit=commit,
        ).returncode == 0:
            raise GitHubControllerError("controller route accepted an invalid permutation")
    return {
        "status": "proved",
        "producer_shapes": sorted(payloads),
        "privileged_consumers": sorted(
            f"{workflow}/{job}" for workflow, job in routed_jobs
        ) + [
            f"{workflow}/{'authorize' if workflow == 'release-authority' else 'publish'}"
            for workflow in sorted(release_workflows)
        ],
        "negative_permutations": 3,
    }


def validate_controller_custody_graph(
    repo_root: Path, *, python_executable: Path
) -> tuple[Any, dict[str, Any]]:
    """Compile the graph once and prove its custody chain before other work."""

    graph = validate_ci_graph(repo_root).graph
    proof = validate_controller_custody_chain(
        graph, python_executable=python_executable
    )
    return post_merge_evaluation(graph), proof


def validate_controller_contracts_preflight(
    repo_root: Path, *, python_executable: Path
) -> int:
    """Own the complete cheap self-workflow and custody contract boundary."""

    if not (repo_root / "governance/self-governance-policy.yml").is_file():
        return 0
    validate_controller_custody_graph(
        repo_root, python_executable=python_executable
    )
    return validate_self_workflow_contracts(repo_root)
