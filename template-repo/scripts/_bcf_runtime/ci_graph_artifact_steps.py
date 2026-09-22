"""Mechanically render exact run/attempt artifact custody steps."""

from __future__ import annotations

from typing import Any

from .ci_github_actions import action_pin
from .ci_graph_contracts import CompiledCIGraph
from .ci_graph_reusable_artifacts import reusable_artifact_binding


def artifact_producer(
    compiled: CompiledCIGraph, artifact: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    for workflow in compiled.workflows:
        for job in workflow["jobs"]:
            if artifact in job["produces"]:
                return workflow, job
    raise AssertionError(f"artifact {artifact} has no producer")


def artifact_runtime_path(
    compiled: CompiledCIGraph, job: dict[str, Any], artifact: str,
) -> str:
    if job["trust"] == "trusted" and job["checkout"] is False:
        return f"${{{{ runner.temp }}}}/bcf-{artifact}"
    return str(compiled.graph["artifacts"][artifact]["path"])


def download_steps(
    compiled: CompiledCIGraph, workflow: dict[str, Any], job: dict[str, Any],
    artifacts: list[str] | None = None,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for artifact in job["consumes"] if artifacts is None else artifacts:
        if job["executor"]["kind"] == "durable_publish":
            continue
        producer_workflow, _ = artifact_producer(compiled, artifact)
        cross_workflow = producer_workflow["id"] != workflow["id"]
        reusable_binding = (
            reusable_artifact_binding(compiled.graph, workflow, artifact)
            if cross_workflow else None
        )
        workflow_run = cross_workflow and reusable_binding is None
        run_id = (
            "${{ github.event.workflow_run.id }}"
            if workflow_run else "${{ github.run_id }}"
        )
        run_attempt = (
            "${{ github.event.workflow_run.run_attempt }}"
            if workflow_run else "${{ github.run_attempt }}"
        )
        with_values: dict[str, Any] = {
            "name": f"bcf-{artifact}-{run_id}-{run_attempt}",
            "path": artifact_runtime_path(compiled, job, artifact),
        }
        if workflow_run:
            with_values.update({
                "github-token": "${{ github.token }}",
                "repository": "${{ github.repository }}",
                "run-id": run_id,
            })
        step: dict[str, Any] = {
            "name": f"Download exact {artifact} evidence",
            "uses": action_pin("download-artifact"),
            "with": with_values,
        }
        if reusable_binding is not None:
            step["if"] = f"${{{{ inputs.{reusable_binding[0]} == true }}}}"
        if (
            job["executor"]["kind"] == "authority"
            and job["executor"]["operation"] == "publish"
        ):
            step["continue-on-error"] = True
        steps.append(step)
    return steps
