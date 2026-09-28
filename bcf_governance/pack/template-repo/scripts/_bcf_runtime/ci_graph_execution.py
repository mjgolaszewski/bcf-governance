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
_EFFECTIVE_CONTROLLER = (
    "${{ runner.tool_cache }}/bcf-governance/"
    "${{ steps.effective-controller.outputs.BCF_BOOTSTRAP_COMMIT_SHA }}/bin/bcf"
)
_ROUTED_RELEASE_CONTROLLER = (
    "${{ runner.tool_cache }}/bcf-governance/"
    "${{ needs.controller-route.outputs.target_commit }}/bin/bcf"
)
_EFFECTIVE_RELEASE_OPERATIONS = frozenset(
    {"resolve", "authorize", "resolve-publication", "publish"}
)
_TRIGGER_RELEASE_OPERATIONS = frozenset({"runtime", "verify-evidence", "collect"})
_INPUT_REFERENCE = re.compile(r"inputs\.([A-Za-z_][A-Za-z0-9_-]*)")
_LITERAL_INPUT_FALLBACK = re.compile(
    r"inputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\|\|\s*(['\"])(.*?)\2"
)
_DIRECT_POST_MERGE_MODE = re.compile(
    r"^\$\{\{ inputs\.evaluation_mode \|\| "
    r"\(github\.event_name == 'push' && '(pr|workitem|closure)' \|\| 'pr'\) \}\}$"
)
_DIRECT_POST_MERGE_TARGET = re.compile(
    r"^\$\{\{ inputs\.evaluation_target \|\| "
    r"\(github\.event_name == 'push' && '([^']+)' \|\| ''\) \}\}$"
)


def direct_post_merge_mode(mode: str) -> str:
    """Render one event-safe direct-push evaluation intent."""

    if mode not in {"pr", "workitem", "closure"}:
        raise CIGraphError("direct post-merge evaluation intent is invalid")
    return (
        "${{ inputs.evaluation_mode || "
        f"(github.event_name == 'push' && '{mode}' || 'pr') }}}}"
    )


def parse_direct_post_merge_mode(value: object) -> str | None:
    """Decode only the canonical event-safe direct-push intent expression."""

    match = _DIRECT_POST_MERGE_MODE.fullmatch(str(value))
    return match.group(1) if match else None


def direct_post_merge_target(target: str) -> str:
    """Render one event-safe exact direct-push workitem target."""

    if not target or "'" in target:
        raise CIGraphError("direct post-merge evaluation target is invalid")
    return (
        "${{ inputs.evaluation_target || "
        f"(github.event_name == 'push' && '{target}' || '') }}}}"
    )


def parse_direct_post_merge_target(value: object) -> str | None:
    """Decode only the canonical event-safe direct-push target expression."""

    match = _DIRECT_POST_MERGE_TARGET.fullmatch(str(value))
    return match.group(1) if match else None


DIRECT_POST_MERGE_MODE = direct_post_merge_mode("closure")


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
    def role(name: str) -> dict[str, Any]:
        jobs = [
            item for item in selected[0]["jobs"]
            if item.get("semantic_role") == name
        ]
        if len(jobs) != 1:
            raise CIGraphError(f"exact-main semantic role {name} is not unique")
        return jobs[0]

    try:
        admit = role("exact-main-admission")["executor"]
        governance = role("exact-main-governance-producer")["executor"]
        mode = str(admit["evaluation_mode"])
        target = admit["evaluation_target"] if "evaluation_target" in admit else None
        inputs = governance["inputs"]
    except (KeyError, TypeError) as exc:
        raise CIGraphError("exact-main evaluation intent is incomplete") from exc
    if mode not in {"pr", "workitem", "closure"}:
        raise CIGraphError("exact-main evaluation intent is not typed")
    input_mode = inputs["evaluation_mode"] if "evaluation_mode" in inputs else None
    input_target = inputs["evaluation_target"] if "evaluation_target" in inputs else None
    if input_mode != mode or input_target != target:
        raise CIGraphError("exact-main admission and governance evaluation intents differ")
    if mode == "workitem" and not isinstance(target, str):
        raise CIGraphError("bounded exact-main target is missing")
    if mode in {"pr", "closure"} and target is not None:
        raise CIGraphError("unbounded evaluation cannot carry a workitem target")
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


def controller_command_ids(
    graph: dict[str, Any], executor: dict[str, Any]
) -> tuple[str, ...]:
    """Derive every fixed, transported, or ephemeral trusted-controller command."""

    selected: list[str] = []
    route_tokens = (
        "needs.trusted-controller-build.outputs.target_commit",
        "steps.controller-route.outputs.controller_commit_sha",
        "needs.controller-route.outputs.target_commit",
    )
    for command_id in _command_ids(graph, executor):
        argv = graph["commands"][command_id]["argv"]
        if "{controller}" in argv or any(
            isinstance(value, str)
            and "runner.tool_cache" in value
            and any(token in value for token in route_tokens)
            for value in argv
        ):
            selected.append(command_id)
    return tuple(selected)


def _argument(argv: list[str], flag: str) -> str | None:
    try:
        value = argv[argv.index(flag) + 1]
    except (ValueError, IndexError):
        return None
    return value if isinstance(value, str) else None


def _requires_selected_python(command: dict[str, Any]) -> bool:
    """Return whether a governed executable depends on the selected Python runtime."""

    return bool(_SELECTED_PYTHON_EXECUTABLES.intersection(command["argv"]))


def job_requires_full_history(
    graph: dict[str, Any], executor: dict[str, Any]
) -> bool:
    """Derive whether a job consumes an exact pull-request base commit."""

    return any(
        "BCF_PR_BASE_SHA" in graph["commands"][command_id].get("environment", {})
        or "BCF_PR_BASE_SHA"
        in graph["commands"][command_id].get("required_environment", [])
        for command_id in _command_ids(graph, executor)
    )


def _release_controller_issues(
    graph: dict[str, Any], job: dict[str, Any], executor: dict[str, Any]
) -> tuple[str, ...]:
    """Bind each privileged release operation to its canonical controller custody."""

    if executor["kind"] not in _EXPLICIT_EXECUTORS:
        return ()
    components = executor["components"]
    installed = [
        index
        for index, component_id in enumerate(components)
        if graph["step_components"][component_id]["kind"] == "controller_install"
    ]
    issues: list[str] = []
    for index, component_id in enumerate(components):
        component = graph["step_components"][component_id]
        if component["kind"] != "command":
            continue
        argv = graph["commands"][component["command"]]["argv"]
        if len(argv) < 4 or argv[1:3] != ["ci-github", "release"]:
            continue
        operation = argv[3]
        if operation in _EFFECTIVE_RELEASE_OPERATIONS:
            fixed_route = argv[0] == _EFFECTIVE_CONTROLLER and (
                "resolve-effective-controller" in components[:index]
            )
            transported_route = (
                argv[0] == _ROUTED_RELEASE_CONTROLLER
                and "controller-route" in job.get("needs", [])
            )
            if not (fixed_route or transported_route) or (
                job.get("controller_requirement") != "current"
            ):
                issues.append(
                    f"release {operation} must require the current controller and invoke its provider-effective identity"
                )
        elif operation in _TRIGGER_RELEASE_OPERATIONS and (
            argv[0] != "{ephemeral_controller}"
            or not any(install_index < index for install_index in installed)
        ):
            issues.append(
                f"release {operation} must invoke its previously installed exact triggering controller"
            )
    return tuple(issues)


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
    if job_requires_full_history(graph, executor):
        explicit_checkouts = [
            graph["step_components"][component_id]
            for component_id in executor.get("components", [])
            if graph["step_components"][component_id].get("kind") == "action"
            and graph["step_components"][component_id].get("action") == "checkout"
        ]
        if not job.get("checkout") and not explicit_checkouts:
            issues.append(
                f"CI graph job {job['id']} consumes an exact PR base without checkout"
            )
        elif explicit_checkouts and any(
            component.get("with", {}).get("fetch-depth") != 0
            for component in explicit_checkouts
        ):
            issues.append(
                f"CI graph job {job['id']} consumes an exact PR base without full-history checkout"
            )
    if executor.get("kind") in _EXPLICIT_EXECUTORS and job.get("checkout"):
        if any(
            graph["step_components"][component_id].get("kind") == "action"
            and graph["step_components"][component_id].get("action") == "checkout"
            for component_id in executor["components"]
        ):
            issues.append(
                f"CI graph job {job['id']} has duplicate implicit and explicit checkout ownership"
            )
    issues.extend(_release_controller_issues(graph, job, executor))
    if (
        workflow is not None
        and workflow.get("role") == "exact-main"
        and job.get("semantic_role") == "exact-main-admission"
        and executor.get("kind") == "component_sequence"
        and "evaluation_mode" in executor
    ):
        commands = [
            graph["commands"][
                graph["step_components"][component_id]["command"]
            ]["argv"]
            for component_id in executor["components"]
            if graph["step_components"][component_id]["kind"] == "command"
        ]
        admissions = [
            argv for argv in commands
            if "ci-github" in argv and "exact-main" in argv and "admit" in argv
        ]
        if len(admissions) != 1:
            issues.append("exact-main admission requires one canonical admission command")
        else:
            argv = admissions[0]
            mode = _argument(argv, "--evaluation-mode")
            target = _argument(argv, "--evaluation-target")
            if (
                mode != executor.get("evaluation_mode")
                or target != executor.get("evaluation_target")
            ):
                issues.append(
                    "exact-main admission command and executor evaluation intents differ"
                )
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
                    actual_fallback = (
                        "pr"
                        if name == "evaluation_mode"
                        and parse_direct_post_merge_mode(value) is not None
                        else ""
                        if name == "evaluation_target"
                        and parse_direct_post_merge_target(value) is not None
                        else fallbacks.get(name)
                    )
                    if actual_fallback != expected_literal:
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
