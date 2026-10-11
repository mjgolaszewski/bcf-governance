"""Mechanical producer/consumer edge closure for the canonical CI graph."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ci_graph_dag import ancestors, job_graph
from .ci_graph_errors import CIGraphError


@dataclass(frozen=True)
class EdgeContract:
    producer: str
    consumer: str
    reachable: bool
    mechanism: str | None
    exclusion_reason: str | None
    artifacts: tuple[str, ...]
    subject_binding: str | None
    custody: str | None
    applicability: str | None
    permissions: tuple[tuple[str, str], ...]
    lifecycle: str | None
    authority: str | None
    failure_semantics: str | None


def _node(workflow: dict[str, Any], job: dict[str, Any]) -> str:
    return f"{workflow['id']}:{job['id']}"


def _workflow_run_sources(
    workflows: list[dict[str, Any]], consumer: dict[str, Any]
) -> set[str]:
    names = {
        name
        for event in consumer["events"]
        if event["type"] == "workflow_run"
        for name in event.get("workflows", [])
    }
    return {
        workflow["id"]
        for workflow in workflows
        if workflow["display_name"] in names
    }


def _reusable_target(
    workflows: list[dict[str, Any]], job: dict[str, Any]
) -> str | None:
    executor = job["executor"]
    if executor["kind"] != "reusable_workflow":
        return None
    path = executor["path"]
    matches = [workflow["id"] for workflow in workflows if workflow["path"] == path]
    if len(matches) != 1:
        raise CIGraphError(
            f"reusable workflow edge for job {job['id']} does not resolve exactly once"
        )
    return matches[0]


def _reachable_contract(
    *,
    producer_workflow: dict[str, Any],
    producer_job: dict[str, Any],
    consumer_workflow: dict[str, Any],
    consumer_job: dict[str, Any],
    mechanism: str,
    artifacts: tuple[str, ...],
) -> EdgeContract:
    if mechanism == "workflow_run":
        subject_binding = "workflow-run-head-sha"
        custody = "provider-workflow-run"
    elif mechanism == "reusable_workflow":
        subject_binding = "caller-subject"
        custody = "provider-reusable-call"
    else:
        subject_binding = "workflow-run-subject"
        custody = "run-attempt-artifact" if artifacts else "dependency-result"
    authority = (
        "trusted-consumer"
        if consumer_job["trust"] == "trusted"
        else "candidate-consumer"
    )
    return EdgeContract(
        producer=_node(producer_workflow, producer_job),
        consumer=_node(consumer_workflow, consumer_job),
        reachable=True,
        mechanism=mechanism,
        exclusion_reason=None,
        artifacts=artifacts,
        subject_binding=subject_binding,
        custody=custody,
        applicability=str(consumer_job["condition"]),
        permissions=tuple(sorted(consumer_job["permissions"].items())),
        lifecycle=str(consumer_workflow["events"]),
        authority=authority,
        failure_semantics=(
            "consumer-condition-and-required-result"
            if consumer_job["required"]
            else "consumer-condition-only"
        ),
    )


def compile_edge_contracts(graph: dict[str, Any]) -> tuple[EdgeContract, ...]:
    """Close every ordered producer/consumer pair or explain its exclusion."""

    workflows = graph["workflows"]
    workflow_run_sources = {
        workflow["id"]: _workflow_run_sources(workflows, workflow)
        for workflow in workflows
    }
    dependencies: dict[str, dict[str, set[str]]] = {}
    for workflow in workflows:
        by_id, direct = job_graph(workflow)
        dependencies[workflow["id"]] = {
            job_id: ancestors(job_id, direct) for job_id in by_id
        }
    reusable_targets = {
        _node(workflow, job): _reusable_target(workflows, job)
        for workflow in workflows
        for job in workflow["jobs"]
    }

    def reusable_bridge(
        producer_workflow: dict[str, Any],
        producer_job: dict[str, Any],
        consumer_workflow: dict[str, Any],
        artifacts: tuple[str, ...],
    ) -> bool:
        if not artifacts:
            return False
        for caller_workflow in workflows:
            for caller_job in caller_workflow["jobs"]:
                if reusable_targets[_node(caller_workflow, caller_job)] != consumer_workflow["id"]:
                    continue
                if caller_workflow["id"] != producer_workflow["id"]:
                    continue
                if producer_job["id"] not in dependencies[caller_workflow["id"]][caller_job["id"]]:
                    continue
                if set(artifacts).issubset(set(caller_job["consumes"])):
                    return True
        return False
    contracts: list[EdgeContract] = []
    for producer_workflow in workflows:
        for producer_job in producer_workflow["jobs"]:
            for consumer_workflow in workflows:
                for consumer_job in consumer_workflow["jobs"]:
                    if producer_job is consumer_job:
                        continue
                    mechanism: str | None = None
                    if producer_workflow["id"] == consumer_workflow["id"]:
                        if producer_job["id"] in dependencies[consumer_workflow["id"]][consumer_job["id"]]:
                            mechanism = "job_dependency"
                    elif producer_workflow["id"] in workflow_run_sources[consumer_workflow["id"]]:
                        mechanism = "workflow_run"
                    elif reusable_targets[_node(consumer_workflow, consumer_job)] == producer_workflow["id"]:
                        mechanism = "reusable_workflow"
                    produced = set(producer_job["produces"])
                    artifacts = tuple(sorted(produced & set(consumer_job["consumes"])))
                    if mechanism is None and reusable_bridge(
                        producer_workflow,
                        producer_job,
                        consumer_workflow,
                        artifacts,
                    ):
                        mechanism = "reusable_artifact_bridge"
                    if mechanism is not None:
                        contracts.append(
                            _reachable_contract(
                                producer_workflow=producer_workflow,
                                producer_job=producer_job,
                                consumer_workflow=consumer_workflow,
                                consumer_job=consumer_job,
                                mechanism=mechanism,
                                artifacts=artifacts,
                            )
                        )
                        continue
                    if artifacts:
                        raise CIGraphError(
                            f"CI graph edge {_node(producer_workflow, producer_job)} -> "
                            f"{_node(consumer_workflow, consumer_job)} transports artifacts "
                            "without a structural path"
                        )
                    reason = (
                        "reverse_dependency"
                        if consumer_workflow["id"] == producer_workflow["id"]
                        and consumer_job["id"] in dependencies[producer_workflow["id"]][producer_job["id"]]
                        else "profile_lane_disconnected"
                        if producer_workflow["role"] != consumer_workflow["role"]
                        else "no_dependency_or_event_path"
                    )
                    contracts.append(
                        EdgeContract(
                            producer=_node(producer_workflow, producer_job),
                            consumer=_node(consumer_workflow, consumer_job),
                            reachable=False,
                            mechanism=None,
                            exclusion_reason=reason,
                            artifacts=(),
                            subject_binding=None,
                            custody=None,
                            applicability=None,
                            permissions=(),
                            lifecycle=None,
                            authority=None,
                            failure_semantics=None,
                        )
                    )
    for contract in contracts:
        populated = (
            contract.mechanism,
            contract.subject_binding,
            contract.custody,
            contract.applicability,
            contract.lifecycle,
            contract.authority,
            contract.failure_semantics,
        )
        if contract.reachable and any(value is None for value in populated):
            raise CIGraphError(
                f"reachable CI graph edge {contract.producer} -> {contract.consumer} is incomplete"
            )
        if not contract.reachable and contract.exclusion_reason is None:
            raise CIGraphError(
                f"unreachable CI graph edge {contract.producer} -> {contract.consumer} lacks an exclusion"
            )
    return tuple(contracts)
