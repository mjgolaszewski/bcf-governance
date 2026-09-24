"""Mechanical execution-input invariants for compiled CI graph jobs."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .ci_graph_errors import CIGraphError


_EXPLICIT_EXECUTORS = {"component_sequence", "gate_shard", "terminal_truth"}
_REPOSITORY_PREFIXES = ("./", ".artifacts/", ".github/", "governance/", "scripts/")
_ENV_REFERENCE = "${{ env.%s }}"
_RUN_AND_DONE_FORBIDDEN = frozenset(
    {"sleep", "poll", "watch", "wait", "while", "until", "wait-for-runner", "lease-runner"}
)
_SELECTED_PYTHON_EXECUTABLES = frozenset(
    {"{python}", "{controller}", "{ephemeral_controller}"}
)
_INPUT_REFERENCE = re.compile(r"inputs\.([A-Za-z_][A-Za-z0-9_-]*)")
_LITERAL_INPUT_FALLBACK = re.compile(
    r"inputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\|\|\s*(['\"])(.*?)\2"
)


@dataclass(frozen=True)
class ExactMainEvaluation:
    """Canonical post-merge truth intent projected by the exact-main graph."""

    mode: str
    target: str | None

    def as_dict(self) -> dict[str, str | None]:
        return {"mode": self.mode, "target": self.target}


def exact_main_evaluation(
    workflows: tuple[dict[str, Any], ...],
) -> ExactMainEvaluation:
    """Resolve one exact admission/governance evaluation contract."""

    selected = [item for item in workflows if item["id"] == "exact-main"]
    if len(selected) != 1:
        raise CIGraphError("canonical graph must contain one exact-main workflow")
    jobs = {str(item["id"]): item for item in selected[0]["jobs"]}
    try:
        admit = jobs["admit"]["executor"]
        governance = jobs["governance"]["executor"]
        mode = str(admit["evaluation_mode"])
        target = admit["evaluation_target"] if "evaluation_target" in admit else None
        inputs = governance["inputs"]
    except (KeyError, TypeError) as exc:
        raise CIGraphError("exact-main evaluation intent is incomplete") from exc
    if mode not in {"workitem", "closure"}:
        raise CIGraphError("exact-main evaluation intent is not terminally typed")
    input_mode = inputs["evaluation_mode"] if "evaluation_mode" in inputs else None
    input_target = inputs["evaluation_target"] if "evaluation_target" in inputs else None
    if input_mode != mode or input_target != target:
        raise CIGraphError("exact-main admission and governance evaluation intents differ")
    if mode == "workitem" and not isinstance(target, str):
        raise CIGraphError("bounded exact-main target is missing")
    if mode == "closure" and target is not None:
        raise CIGraphError("phase closure cannot carry a workitem target")
    return ExactMainEvaluation(mode, target)


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(item for nested in value.values() for item in _strings(nested))
    if isinstance(value, list):
        return tuple(item for nested in value for item in _strings(nested))
    return ()


def _command_ids(
    graph: dict[str, Any], executor: dict[str, Any]
) -> tuple[str, ...]:
    if executor["kind"] in _EXPLICIT_EXECUTORS:
        return tuple(
            graph["step_components"][component_id]["command"]
            for component_id in executor["components"]
            if graph["step_components"][component_id]["kind"] == "command"
        )
    if executor["kind"] in {"command", "truth"}:
        return (executor["command"],)
    return ()


def _requires_selected_python(command: dict[str, Any]) -> bool:
    """Return whether a governed executable depends on the selected Python runtime."""

    return bool(_SELECTED_PYTHON_EXECUTABLES.intersection(command["argv"]))


def job_required_environment(
    graph: dict[str, Any],
    workflow: dict[str, Any],
    job: dict[str, Any],
    executor: dict[str, Any],
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Derive each job's required environment once and reject missing/conflicting bindings."""

    inherited = {**workflow.get("environment", {}), **job.get("environment", {})}
    component_bindings: dict[str, list[str]] = {}
    if executor["kind"] in _EXPLICIT_EXECUTORS:
        for component_id in executor["components"]:
            component = graph["step_components"][component_id]
            if component["kind"] != "command":
                continue
            for name, value in component.get("environment", {}).items():
                component_bindings.setdefault(name, []).append(value)
    bindings: dict[str, str] = {}
    issues: list[str] = []
    for command_id in _command_ids(graph, executor):
        command = graph["commands"][command_id]
        for name in command.get("required_environment", []):
            candidates = [
                *component_bindings.get(name, ()),
                *([command["environment"][name]] if name in command["environment"] else []),
                *([inherited[name]] if name in inherited else []),
            ]
            usable = [
                value
                for value in candidates
                if isinstance(value, str)
                and value
                and value != _ENV_REFERENCE % name
            ]
            step_outputs = [value for value in usable if "${{ steps." in value]
            if step_outputs:
                issues.append(
                    f"CI graph job {job['id']} cannot preflight required environment {name} from a future step output"
                )
                continue
            distinct = list(dict.fromkeys(usable))
            if not distinct:
                issues.append(
                    f"CI graph job {job['id']} is missing required environment binding {name}"
                )
            elif len(distinct) > 1:
                issues.append(
                    f"CI graph job {job['id']} has conflicting required environment binding {name}"
                )
            else:
                bindings[name] = distinct[0]
    return bindings, tuple(issues)


def job_execution_issues(
    graph: dict[str, Any],
    job: dict[str, Any],
    executor: dict[str, Any],
    workflow: dict[str, Any] | None = None,
) -> tuple[str, ...]:
    """Return deterministic interpreter and trusted-input contract violations."""

    issues: list[str] = []
    if executor.get("protection_inspection"):
        if (
            executor.get("kind") not in {"authority", "component_sequence"}
            or (
                executor.get("kind") == "authority"
                and executor.get("operation") != "admit-with-prior-evidence"
            )
            or job.get("protected_environment") != "bcf-trusted-protection-inspection"
            or job.get("trust") != "trusted"
            or job.get("checkout") is not False
        ):
            issues.append(
                "protection inspection requires the protected trusted exact-main admission job"
            )
        if executor.get("kind") == "component_sequence" and not {
            "protection-inspector-token",
            "prior-evidence-effective",
        }.issubset(set(executor.get("components", []))):
            issues.append("protection inspection component sequence is incomplete")
    if workflow is not None:
        _, environment_issues = job_required_environment(
            graph, workflow, job, executor
        )
        issues.extend(environment_issues)
    if executor["kind"] in _EXPLICIT_EXECUTORS:
        python_ready = False
        for component_id in executor["components"]:
            component = graph["step_components"][component_id]
            if component["kind"] == "action" and component["action"] == "setup-python":
                python_ready = True
                continue
            if (
                component["kind"] == "command"
                and _requires_selected_python(
                    graph["commands"][component["command"]]
                )
                and not python_ready
            ):
                issues.append(
                    f"CI graph job {job['id']} must provision selected Python before governed commands"
                )
    elif executor["kind"] in {"command", "truth"}:
        command = graph["commands"][executor["command"]]
        if _requires_selected_python(command) and "python" not in job["components"]:
            issues.append(
                f"CI graph job {job['id']} must provision selected Python before governed commands"
            )
    elif (
        executor["kind"] in {"authority", "durable_publish"}
        and "python" not in job["components"]
    ):
        issues.append(
            f"CI graph job {job['id']} must provision selected Python before governed commands"
        )
    if job["trust"] == "trusted" and job["checkout"] is False:
        execution_inputs: list[Any] = [job.get("environment", {})]
        execution_inputs.extend(
            graph["commands"][command_id]
            for command_id in _command_ids(graph, executor)
        )
        if executor["kind"] in _EXPLICIT_EXECUTORS:
            execution_inputs.extend(
                graph["step_components"][component_id]
                for component_id in executor["components"]
            )
        relative = sorted(
            {
                value
                for payload in execution_inputs
                for value in _strings(payload)
                if value.startswith(_REPOSITORY_PREFIXES)
            }
        )
        if relative:
            issues.append(
                f"trusted no-checkout job {job['id']} references repository-relative inputs {relative}"
            )
    return tuple(issues)


def workflow_input_issues(
    graph: dict[str, Any], workflow: dict[str, Any]
) -> tuple[str, ...]:
    """Reject raw workflow inputs that disappear under a workflow's direct events."""

    direct_events = sorted(
        event["type"]
        for event in workflow["events"]
        if event["type"] not in {"workflow_call", "workflow_dispatch"}
    )
    if not direct_events:
        return ()
    declared_inputs = {
        str(name): contract
        for event in workflow["events"]
        if event["type"] == "workflow_call"
        for name, contract in event.get("inputs", {}).items()
    }
    issues: list[str] = []
    for job in workflow["jobs"]:
        surfaces: list[tuple[str, Any]] = [("job outputs", job.get("outputs", {}))]
        for command_id in _command_ids(graph, job["executor"]):
            surfaces.append((f"command {command_id}", graph["commands"][command_id]))
        executor = job["executor"]
        if executor["kind"] in _EXPLICIT_EXECUTORS:
            for component_id in executor["components"]:
                component = graph["step_components"][component_id]
                if component["kind"] == "action":
                    surfaces.append((f"action {component_id}", component))
        if executor["kind"] == "reusable_workflow":
            surfaces.append(("reusable-workflow inputs", executor["inputs"]))
        for surface, payload in surfaces:
            for value in _strings(payload):
                references = set(_INPUT_REFERENCE.findall(value))
                if references and "||" not in value:
                    issues.append(
                        f"direct-event workflow {workflow['id']} {surface} "
                        f"must provide an input fallback for {direct_events}"
                    )
                    continue
                fallbacks = {
                    name: literal
                    for name, _, literal in _LITERAL_INPUT_FALLBACK.findall(value)
                }
                for name in sorted(references):
                    contract = declared_inputs.get(name)
                    expected = contract.get("default") if isinstance(contract, dict) else None
                    expected_literal = (
                        str(expected).lower()
                        if isinstance(expected, bool)
                        else "" if expected is None else str(expected)
                    )
                    if fallbacks.get(name) != expected_literal:
                        issues.append(
                            f"direct-event workflow {workflow['id']} {surface} input {name} "
                            "fallback must equal its declared workflow_call default"
                        )
    return tuple(sorted(set(issues)))


def hosted_command_issues(graph: dict[str, Any]) -> tuple[str, ...]:
    """Reject hosted coordination and incomplete run-and-done policy."""
    configured = {
        str(value).lower() for value in graph["policy"]["forbidden_hosted_tokens"]
    }
    if graph["policy"].get("hosted_orchestration") == "run_and_done":
        missing = sorted(_RUN_AND_DONE_FORBIDDEN - configured)
        if missing:
            return (f"run-and-done hosted policy is missing tokens {missing}",)
    issues: list[str] = []
    for workflow in graph["workflows"]:
        issues.extend(workflow_input_issues(graph, workflow))
        for job in workflow["jobs"]:
            resource = graph["resource_classes"][job["resource_class"]]
            if not resource["hosted"]:
                continue
            for command_id in _command_ids(graph, job["executor"]):
                normalized = " ".join(graph["commands"][command_id]["argv"]).lower()
                for token in configured:
                    if re.search(
                        rf"(?:^|[^a-z0-9]){re.escape(token)}(?:$|[^a-z0-9])",
                        normalized,
                    ):
                        issues.append(
                            f"hosted waiter token {token!r} is prohibited in job {job['id']}"
                        )
    return tuple(issues)
