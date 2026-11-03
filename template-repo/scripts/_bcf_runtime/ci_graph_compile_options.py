"""Compiler-owned defaults and total validated CI rendering options."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ci_graph_reusable_artifacts import project_reusable_workflow_permissions


@dataclass(frozen=True)
class CIComponentRenderOptions:
    action_uses: str | None
    condition_style: str


@dataclass(frozen=True)
class CIJobRenderOptions:
    omit_name: bool
    singleton_needs: bool
    emit_permissions: bool
    deferred_environment: bool


def _apply_canonical_defaults(graph: dict[str, Any]) -> None:
    """Apply optional contract defaults once, before any downstream consumer."""
    graph["policy"].setdefault("reserved_status_contexts", [])
    for resource in graph["resource_classes"].values():
        resource.setdefault("python_version", "3.12")
    for command in graph["commands"].values():
        command.setdefault("required_environment", [])
    for component in graph["step_components"].values():
        kind = component["kind"]
        if kind != "directory_setup":
            component.setdefault("condition", None)
        if kind not in {"controller_install", "directory_setup"}:
            component.setdefault("id", None)
        if kind == "command":
            component.setdefault("restores_private_artifacts", [])
    for workflow in graph["workflows"]:
        workflow.setdefault("environment", {})
        for job in workflow["jobs"]:
            job.setdefault("environment", {})
            job.setdefault("outputs", {})
            job.setdefault("controller_requirement", None)
            executor = job["executor"]
            if executor["kind"] == "reusable_workflow":
                executor.setdefault("inputs", {})
    project_reusable_workflow_permissions(graph)


def _compile_render_options(
    graph: dict[str, Any],
) -> tuple[dict[str, str], dict[str, CIComponentRenderOptions], dict[tuple[str, str], CIJobRenderOptions]]:
    # Optional authored declarations remain schema-valid and unchanged. The
    # compiler alone resolves their total rendering representation after all
    # ingress validation, so renderers never select an omitted-field fallback.
    from .ci_github_actions import action_pin

    command_render_modes = {
        command_id: command.get("render_mode", "argv")
        for command_id, command in graph["commands"].items()
    }
    component_render_options = {
        component_id: CIComponentRenderOptions(
            action_uses=(
                action_pin(component["action"], component.get("source_pin"))
                if component["kind"] == "action" else None
            ),
            condition_style=component.get("condition_style", "expression"),
        )
        for component_id, component in graph["step_components"].items()
    }
    job_render_options = {
        (workflow["id"], job["id"]): CIJobRenderOptions(
            omit_name=job.get("omit_name", False),
            singleton_needs=job.get("needs_style") == "singleton-scalar",
            emit_permissions=job.get("permissions_style") not in {
                "inherit-workflow", "inherit-callee-bound"
            },
            deferred_environment=(
                job.get("required_environment_position") == "after-repo-preparation"
            ),
        )
        for workflow in graph["workflows"] for job in workflow["jobs"]
    }
    return command_render_modes, component_render_options, job_render_options


