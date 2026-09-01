"""Load, compose, and mechanically validate the BCF CI graph."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .ci_graph_yaml import GraphYAMLError, load_yaml_path
from .ci_graph_values import CIGraphValueError, resolve_graph_values


GRAPH_PATH = Path("governance/ci-graph.yml")
EXTENSION_ROOT = Path("governance/ci-extensions")
GRAPH_SCHEMA_PATH = Path("schemas/ci-graph.schema.json")
EXTENSION_SCHEMA_PATH = Path("schemas/ci-graph-extension.schema.json")


class CIGraphError(ValueError):
    """Raised when graph bytes do not define one safe executable topology."""


@dataclass(frozen=True)
class CompiledCIGraph:
    graph: dict[str, Any]
    workflows: tuple[dict[str, Any], ...]
    commands: dict[str, dict[str, Any]]
    graph_sha256: str
    extension_sha256: tuple[tuple[str, str], ...]
    input_sha256: tuple[tuple[str, str], ...]
    trusted_controller: str
    trusted_controller_check: str
    trusted_controller_current: bool


def _schema(repo_root: Path, relative: Path) -> dict[str, Any]:
    path = repo_root / relative
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CIGraphError(f"cannot load graph schema {relative}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CIGraphError(f"graph schema {relative} must be an object")
    return payload


def _validate_schema(payload: dict[str, Any], schema: dict[str, Any], source: str) -> None:
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path))
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise CIGraphError(f"{source} schema violation at {location}: {error.message}")


def _extension_files(repo_root: Path) -> set[str]:
    root = repo_root / EXTENSION_ROOT
    if not root.exists():
        return set()
    if not root.is_dir() or root.is_symlink():
        raise CIGraphError("governance/ci-extensions must be a nonsymlink directory")
    result: set[str] = set()
    for path in sorted(root.iterdir()):
        if path.is_symlink():
            raise CIGraphError(f"CI graph extension is a symlink: {path.relative_to(repo_root)}")
        if path.is_file() and path.suffix in {".yml", ".yaml"}:
            result.add(path.relative_to(repo_root).as_posix())
        elif path.is_file():
            raise CIGraphError(f"unsupported file in CI graph extension root: {path.name}")
        elif path.is_dir():
            raise CIGraphError(f"nested CI graph extension directory is not allowed: {path.name}")
    return result


def _load_extensions(
    repo_root: Path, graph: dict[str, Any]
) -> tuple[list[dict[str, Any]], tuple[tuple[str, str], ...]]:
    references = graph["extensions"]
    registered_paths = [str(item["path"]) for item in references]
    if len(set(registered_paths)) != len(registered_paths):
        raise CIGraphError("CI graph extension paths must be unique")
    registered_ids = [str(item["id"]) for item in references]
    if len(set(registered_ids)) != len(registered_ids):
        raise CIGraphError("CI graph extension IDs must be unique")
    actual_paths = _extension_files(repo_root)
    if set(registered_paths) != actual_paths:
        unregistered = sorted(actual_paths - set(registered_paths))
        missing = sorted(set(registered_paths) - actual_paths)
        raise CIGraphError(
            f"CI graph extension inventory mismatch: unregistered={unregistered}, missing={missing}"
        )
    schema = _schema(repo_root, EXTENSION_SCHEMA_PATH)
    payloads: list[dict[str, Any]] = []
    digests: list[tuple[str, str]] = []
    control_ids: set[str] = set()
    for reference in references:
        relative = str(reference["path"])
        path = repo_root / relative
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest != reference["sha256"]:
            raise CIGraphError(f"CI graph extension digest mismatch: {relative}")
        try:
            payload = load_yaml_path(path)
        except GraphYAMLError as exc:
            raise CIGraphError(str(exc)) from exc
        _validate_schema(payload, schema, relative)
        if payload["extension"]["id"] != reference["id"]:
            raise CIGraphError(f"CI graph extension ID mismatch: {relative}")
        if payload["document"]["path"] != relative:
            raise CIGraphError(f"CI graph extension document path mismatch: {relative}")
        if payload["extension"]["attachment_point"] not in graph["extension_points"]:
            raise CIGraphError(f"CI graph extension uses undeclared attachment point: {relative}")
        if not payload["workflows"] and not payload["jobs"]:
            raise CIGraphError(f"CI graph extension has no workflow or job contribution: {relative}")
        for category, values in payload["extension"]["required_controls"].items():
            for control_id in values:
                if control_id in control_ids:
                    raise CIGraphError(
                        f"CI graph extension control has multiple owners: {control_id}"
                    )
                control_ids.add(control_id)
        payloads.append(payload)
        digests.append((relative, digest))
    return payloads, tuple(digests)


def _truth_job(workflow: dict[str, Any]) -> dict[str, Any] | None:
    values = [
        job
        for job in workflow["jobs"]
        if job["executor"]["kind"] in {"truth", "terminal_truth"}
    ]
    if len(values) > 1:
        raise CIGraphError(f"workflow {workflow['id']} has multiple terminal truth jobs")
    return values[0] if values else None


def _compose(graph: dict[str, Any], extensions: list[dict[str, Any]]) -> dict[str, Any]:
    composed = copy.deepcopy(graph)
    workflows = {item["id"]: item for item in composed["workflows"]}
    for extension in extensions:
        contributed_workflow_ids = {
            str(workflow.get("id"))
            for workflow in extension["workflows"]
            if isinstance(workflow, dict) and workflow.get("id")
        }
        contributed_workflow_ids.update(
            str(job.get("workflow"))
            for job in extension["jobs"]
            if isinstance(job, dict) and job.get("workflow")
        )
        for artifact_id, artifact in extension["artifacts"].items():
            if artifact_id in composed["artifacts"]:
                raise CIGraphError(f"CI graph artifact has multiple contract owners: {artifact_id}")
            composed["artifacts"][artifact_id] = artifact
        for condition_id, condition in extension["conditions"].items():
            if condition_id in composed["conditions"]:
                raise CIGraphError(
                    f"CI graph condition has multiple owners: {condition_id}"
                )
            composed["conditions"][condition_id] = condition
        for command_id, command in extension["commands"].items():
            if command_id in composed["commands"]:
                raise CIGraphError(f"CI graph command has multiple owners: {command_id}")
            composed["commands"][command_id] = command
        for component_id, component in extension["step_components"].items():
            if component_id in composed["step_components"]:
                raise CIGraphError(
                    f"CI graph step component has multiple owners: {component_id}"
                )
            composed["step_components"][component_id] = component
        for workflow in extension["workflows"]:
            workflow_id = workflow.get("id") if isinstance(workflow, dict) else None
            if workflow_id in workflows:
                raise CIGraphError(f"CI graph workflow has multiple owners: {workflow_id}")
            composed["workflows"].append(workflow)
            if isinstance(workflow_id, str):
                workflows[workflow_id] = workflow
        point = extension["extension"]["attachment_point"]
        for attached in extension["jobs"]:
            if not isinstance(attached, dict) or not isinstance(attached.get("workflow"), str):
                raise CIGraphError("CI graph extension job must declare one workflow")
            workflow_id = attached["workflow"]
            if workflow_id not in workflows:
                raise CIGraphError(f"CI graph extension targets unknown workflow: {workflow_id}")
            job = {key: value for key, value in attached.items() if key != "workflow"}
            jobs = workflows[workflow_id]["jobs"]
            truth = _truth_job(workflows[workflow_id])
            if point in {"evidence-lane", "before-truth"} and truth is not None:
                index = jobs.index(truth)
                jobs.insert(index, job)
                if job["id"] not in truth["needs"]:
                    truth["needs"].append(job["id"])
                for artifact in job["produces"]:
                    if artifact not in truth["consumes"]:
                        truth["consumes"].append(artifact)
            elif point == "preflight":
                jobs.insert(0, job)
            else:
                jobs.append(job)
        contributed_events = {
            event["type"]
            for workflow_id in contributed_workflow_ids
            if workflow_id in workflows
            for event in workflows[workflow_id]["events"]
        }
        applicability = set(extension["extension"]["applicability"])
        if applicability != contributed_events:
            raise CIGraphError(
                f"CI graph extension {extension['extension']['id']} applicability does not "
                "match its contributed workflow events"
            )
    return composed


def _apply_canonical_defaults(graph: dict[str, Any]) -> None:
    """Apply optional contract defaults once, before any downstream consumer."""

    for resource in graph["resource_classes"].values():
        resource.setdefault("python_version", "3.12")
    for command in graph["commands"].values():
        command.setdefault("required_environment", [])
    for component in graph["step_components"].values():
        if component["kind"] not in {"controller_install", "directory_setup"}:
            component.setdefault("id", None)
            component.setdefault("condition", None)
        if component["kind"] == "command":
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


def _validate_step_components(graph: dict[str, Any]) -> None:
    artifacts = set(graph["artifacts"])
    commands = set(graph["commands"])
    conditions = set(graph["conditions"])
    for component_id, component in graph["step_components"].items():
        if component["kind"] in {"controller_install", "directory_setup"}:
            continue
        condition = component["condition"]
        if condition is not None and condition not in conditions:
            raise CIGraphError(
                f"CI graph step component {component_id} references unknown condition"
            )
        if component["kind"] == "command" and component["command"] not in commands:
            raise CIGraphError(
                f"CI graph step component {component_id} references unknown command"
            )
        restored = set(component.get("restores_private_artifacts", []))
        missing_restored = sorted(restored - artifacts)
        if missing_restored:
            raise CIGraphError(
                f"CI graph step component {component_id} restores undeclared artifacts {missing_restored}"
            )
        for direction in ("produces", "consumes"):
            missing = sorted(set(component[direction]) - artifacts)
            if missing:
                raise CIGraphError(
                    f"CI graph step component {component_id} {direction} undeclared artifacts {missing}"
                )


def _private_artifacts(graph: dict[str, Any]) -> set[str]:
    """Derive artifacts carrying a private evidence-session custody boundary."""

    session_paths = {
        artifact["path"]
        for artifact in graph["artifacts"].values()
        if artifact["kind"] == "session"
    }
    return {
        artifact_id
        for artifact_id, artifact in graph["artifacts"].items()
        if artifact["kind"] == "session" or artifact["path"] in session_paths
    }


def _validate_private_transport(
    graph: dict[str, Any], job: dict[str, Any], executor: dict[str, Any]
) -> None:
    protected = set(job["consumes"]) & _private_artifacts(graph)
    if not protected:
        return
    if executor["kind"] not in {"component_sequence", "gate_shard", "terminal_truth"}:
        if "restore-private-modes" not in job["components"]:
            raise CIGraphError(
                f"CI graph job {job['id']} must restore private artifact modes before execution"
            )
        return
    components = executor["components"]
    protected_downloads = [
        index
        for index, component_id in enumerate(components)
        if graph["step_components"][component_id]["kind"] == "action"
        and graph["step_components"][component_id]["action"] == "download-artifact"
        and set(graph["step_components"][component_id]["consumes"]) & protected
    ]
    downloaded = {
        artifact
        for index in protected_downloads
        for artifact in graph["step_components"][components[index]]["consumes"]
        if artifact in protected
    }
    restores = [
        index
        for index, component_id in enumerate(components)
        if graph["step_components"][component_id].get("restores_private_artifacts")
    ]
    downloads_are_contiguous = bool(protected_downloads) and protected_downloads == list(
        range(min(protected_downloads), max(protected_downloads) + 1)
    )
    if (
        downloaded != protected
        or not downloads_are_contiguous
        or len(restores) != 1
        or restores[0] != max(protected_downloads, default=-2) + 1
    ):
        raise CIGraphError(
            f"CI graph job {job['id']} must restore private artifact modes immediately after exact transport"
        )
    restore = graph["step_components"][components[restores[0]]]
    if set(restore["restores_private_artifacts"]) != protected:
        raise CIGraphError(
            f"CI graph job {job['id']} private mode restoration must bind every transported artifact"
        )
    download_conditions = {
        graph["step_components"][components[index]]["condition"]
        for index in protected_downloads
    }
    if len(download_conditions) != 1 or restore["condition"] not in download_conditions:
        raise CIGraphError(
            f"CI graph job {job['id']} private mode restoration condition must match its transport"
        )
    download_roots = {
        str(graph["step_components"][components[index]]["with"].get("path", ""))
        for index in protected_downloads
    }
    argv = graph["commands"][restore["command"]]["argv"]
    declared_roots = {
        argv[index + 1]
        for index, value in enumerate(argv[:-1])
        if value == "--root"
    }
    if download_roots != declared_roots:
        raise CIGraphError(
            f"CI graph job {job['id']} private mode restoration root must match artifact custody"
        )


def _condition_needs(graph: dict[str, Any], condition: str | None) -> set[str]:
    if condition is None or condition in {"success", "always", "failure", "cancelled"}:
        return set()
    return set(re.findall(r"\bneeds\.([A-Za-z0-9._-]+)\.", graph["conditions"][condition]))


def _validate_condition_scope(
    graph: dict[str, Any], job: dict[str, Any], component_ids: list[str]
) -> None:
    available = set(job["needs"])
    references = _condition_needs(graph, job["condition"])
    for component_id in component_ids:
        references.update(
            _condition_needs(
                graph, graph["step_components"][component_id].get("condition")
            )
        )
    missing = sorted(references - available)
    if missing:
        raise CIGraphError(
            f"CI graph job {job['id']} condition references unavailable needs {missing}"
        )


def _validate_selected_python(
    graph: dict[str, Any], job: dict[str, Any], executor: dict[str, Any]
) -> None:
    """Require setup-python to mechanically own every selected-Python binding."""

    if executor["kind"] in {"component_sequence", "gate_shard", "terminal_truth"}:
        python_ready = False
        for component_id in executor["components"]:
            component = graph["step_components"][component_id]
            if component["kind"] == "action" and component["action"] == "setup-python":
                python_ready = True
                continue
            if (
                component["kind"] == "command"
                and "{python}" in graph["commands"][component["command"]]["argv"]
                and not python_ready
            ):
                raise CIGraphError(
                    f"CI graph job {job['id']} must provision selected Python before governed commands"
                )
        return
    if executor["kind"] in {"command", "truth"}:
        command = graph["commands"][executor["command"]]
        if "{python}" in command["argv"] and "python" not in job["components"]:
            raise CIGraphError(
                f"CI graph job {job['id']} must provision selected Python before governed commands"
            )


def _job_graph(workflow: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
    jobs = workflow["jobs"]
    by_id: dict[str, dict[str, Any]] = {}
    dependencies: dict[str, set[str]] = {}
    for job in jobs:
        job_id = job["id"]
        if job_id in by_id:
            raise CIGraphError(f"workflow {workflow['id']} duplicates job ID {job_id}")
        by_id[job_id] = job
        dependencies[job_id] = set(job["needs"])
    for job_id, needs in dependencies.items():
        missing = sorted(needs - set(by_id))
        if missing:
            raise CIGraphError(f"workflow {workflow['id']} job {job_id} needs missing jobs {missing}")
    return by_id, dependencies


def _ancestors(job_id: str, dependencies: dict[str, set[str]]) -> set[str]:
    visited: set[str] = set()
    active: set[str] = set()

    def visit(current: str) -> None:
        if current in active:
            raise CIGraphError(f"CI graph cycle includes job {current}")
        if current in visited:
            return
        active.add(current)
        for dependency in dependencies[current]:
            visit(dependency)
        active.remove(current)
        visited.add(current)

    visit(job_id)
    visited.remove(job_id)
    return visited


def _validate_workflows(graph: dict[str, Any]) -> None:
    workflows = graph["workflows"]
    workflow_ids = [item["id"] for item in workflows]
    paths = [item["path"] for item in workflows]
    if len(set(workflow_ids)) != len(workflow_ids) or len(set(paths)) != len(paths):
        raise CIGraphError("CI graph workflow IDs and paths must each be unique")
    push_workflows = [
        item for item in workflows if any(event["type"] == "push" for event in item["events"])
    ]
    if len(push_workflows) != 1 or push_workflows[0]["role"] != "exact-main":
        raise CIGraphError("CI graph must have one exact-main push authority")
    semantic_roles: set[str] = set()
    artifact_producers: dict[str, tuple[str, str]] = {}
    graph_resources = graph["resource_classes"]
    workflows_by_id = {item["id"]: item for item in workflows}
    for workflow in workflows:
        for job in workflow["jobs"]:
            for artifact in job["produces"]:
                if artifact not in graph["artifacts"]:
                    raise CIGraphError(f"CI graph job {job['id']} produces undeclared artifact {artifact}")
                if artifact in artifact_producers:
                    raise CIGraphError(f"CI graph artifact has multiple producers: {artifact}")
                artifact_producers[artifact] = (workflow["id"], job["id"])
    for workflow in workflows:
        workflow_gate_owners: set[str] = set()
        if workflow["role"] == "scheduled" and any(
            event["type"] in {"pull_request", "push"} for event in workflow["events"]
        ):
            raise CIGraphError("scheduled controls cannot be required by PR or push events")
        by_id, dependencies = _job_graph(workflow)
        ancestor_map = {job_id: _ancestors(job_id, dependencies) for job_id in by_id}
        for job in workflow["jobs"]:
            role = job["semantic_role"]
            if role in semantic_roles:
                raise CIGraphError(f"CI graph semantic role has multiple owners: {role}")
            semantic_roles.add(role)
            resource_id = job["resource_class"]
            if resource_id not in graph_resources:
                raise CIGraphError(f"CI graph job {job['id']} has unknown resource class {resource_id}")
            resource = graph_resources[resource_id]
            if resource["trust"] != job["trust"]:
                raise CIGraphError(f"CI graph job {job['id']} trust conflicts with its resource class")
            if job["trust"] == "trusted" and (job["checkout"] or "checkout" in job["components"]):
                raise CIGraphError(f"trusted CI graph job {job['id']} may not check out candidate code")
            if job["trust"] == "candidate" and any(
                value == "write" and key in {"actions", "checks", "contents", "packages", "pull-requests", "statuses"}
                for key, value in job["permissions"].items()
            ):
                raise CIGraphError(f"candidate CI graph job {job['id']} has privileged write authority")
            executor = job["executor"]
            condition = job["condition"]
            if condition not in {"success", "always", "failure", "cancelled"} and condition not in graph["conditions"]:
                raise CIGraphError(
                    f"CI graph job {job['id']} references unknown condition {condition}"
                )
            if executor["kind"] == "authority" and job["trust"] != "trusted":
                raise CIGraphError(f"authority job {job['id']} is not trusted")
            if executor["kind"] in {"command", "truth", "terminal_truth"} and executor["command"] not in graph["commands"]:
                raise CIGraphError(f"CI graph job {job['id']} references unknown command")
            if executor["kind"] in {"gate_group", "gate_shard"}:
                for gate in executor["gates"]:
                    if gate in workflow_gate_owners:
                        raise CIGraphError(
                            f"CI graph gate {gate} has multiple owners in workflow {workflow['id']}"
                        )
                    workflow_gate_owners.add(gate)
            if executor["kind"] in {"component_sequence", "gate_shard", "terminal_truth"}:
                missing_components = sorted(
                    set(executor["components"]) - set(graph["step_components"])
                )
                if missing_components:
                    raise CIGraphError(
                        f"CI graph job {job['id']} references unknown step components {missing_components}"
                    )
                _validate_condition_scope(graph, job, executor["components"])
                _validate_private_transport(graph, job, executor)
                _validate_selected_python(graph, job, executor)
                component_produces = {
                    artifact
                    for component_id in executor["components"]
                    for artifact in graph["step_components"][component_id]["produces"]
                }
                component_consumes = {
                    artifact
                    for component_id in executor["components"]
                    for artifact in graph["step_components"][component_id]["consumes"]
                }
                if component_produces != set(job["produces"]):
                    raise CIGraphError(
                        f"CI graph job {job['id']} component-produced artifacts do not match its contract"
                    )
                if component_consumes != set(job["consumes"]):
                    raise CIGraphError(
                        f"CI graph job {job['id']} component-consumed artifacts do not match its contract"
                    )
                controller_commands = [
                    graph["step_components"][component_id]["command"]
                    for component_id in executor["components"]
                    if graph["step_components"][component_id]["kind"] == "command"
                    and "{controller}"
                    in graph["commands"][
                        graph["step_components"][component_id]["command"]
                    ]["argv"]
                ]
                if controller_commands and job["trust"] != "trusted":
                    raise CIGraphError(
                        f"candidate CI graph job {job['id']} may not invoke the trusted controller"
                    )
                release_controller_commands = [
                    command_id
                    for command_id in controller_commands
                    if graph["commands"][command_id]["argv"][:3]
                    == ["{controller}", "ci-github", "release"]
                ]
                if release_controller_commands and job["controller_requirement"] != "current":
                    raise CIGraphError(
                        f"release controller job {job['id']} must require the current controller"
                    )
                if job["controller_requirement"] == "current" and not controller_commands:
                    raise CIGraphError(
                        f"CI graph job {job['id']} requires the current controller without invoking it"
                    )
                ephemeral_commands = [
                    graph["step_components"][component_id]["command"]
                    for component_id in executor["components"]
                    if graph["step_components"][component_id]["kind"] == "command"
                    and "{ephemeral_controller}"
                    in graph["commands"][
                        graph["step_components"][component_id]["command"]
                    ]["argv"]
                ]
                installs_ephemeral = any(
                    graph["step_components"][component_id]["kind"]
                    == "controller_install"
                    for component_id in executor["components"]
                )
                if ephemeral_commands and not installs_ephemeral:
                    raise CIGraphError(
                        f"CI graph job {job['id']} invokes an unprovisioned ephemeral controller"
                    )
                if executor["kind"] == "terminal_truth":
                    component_commands = {
                        graph["step_components"][component_id]["command"]
                        for component_id in executor["components"]
                        if graph["step_components"][component_id]["kind"] == "command"
                    }
                    if executor["command"] not in component_commands:
                        raise CIGraphError(
                            f"terminal truth job {job['id']} does not execute its canonical truth command"
                        )
                if executor["kind"] == "gate_shard":
                    strategy = job.get("strategy")
                    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
                    shard_values = (
                        matrix.get(executor["shard_key"])
                        if isinstance(matrix, dict)
                        else None
                    )
                    if shard_values != list(range(executor["shard_count"])):
                        raise CIGraphError(
                            f"gate shard job {job['id']} matrix does not exactly cover its shards"
                        )
            else:
                _validate_condition_scope(graph, job, [])
                _validate_private_transport(graph, job, executor)
                _validate_selected_python(graph, job, executor)
        for job in workflow["jobs"]:
            for artifact in job["consumes"]:
                if artifact not in graph["artifacts"]:
                    raise CIGraphError(f"CI graph job {job['id']} consumes undeclared artifact {artifact}")
                if artifact not in artifact_producers:
                    raise CIGraphError(f"CI graph job {job['id']} consumes unknown artifact {artifact}")
                producer_workflow, producer_job = artifact_producers[artifact]
                if producer_workflow == workflow["id"]:
                    if producer_job not in ancestor_map[job["id"]]:
                        raise CIGraphError(f"CI graph artifact {artifact} is outside exact dependency fan-in")
                    continue
                producer = workflows_by_id[producer_workflow]
                trigger_names = {
                    name
                    for event in workflow["events"]
                    if event["type"] == "workflow_run"
                    for name in event.get("workflows", [])
                }
                if producer["display_name"] not in trigger_names:
                    raise CIGraphError(f"CI graph artifact {artifact} is outside exact provider fan-in")
        evidence = [
            job
            for job in workflow["jobs"]
            if job["executor"]["kind"] in {"gate_group", "gate_shard"}
        ]
        if evidence:
            truth = _truth_job(workflow)
            if truth is None:
                raise CIGraphError(f"workflow {workflow['id']} has evidence without terminal truth")
            expected = {artifact for job in evidence for artifact in job["produces"]}
            if not expected or not expected.issubset(set(truth["consumes"])):
                raise CIGraphError(f"workflow {workflow['id']} has incomplete evidence fan-in")


def _validate_hosted_commands(graph: dict[str, Any]) -> None:
    forbidden = tuple(value.lower() for value in graph["policy"]["forbidden_hosted_tokens"])
    for workflow in graph["workflows"]:
        for job in workflow["jobs"]:
            resource = graph["resource_classes"][job["resource_class"]]
            if not resource["hosted"]:
                continue
            executor = job["executor"]
            command_ids: list[str] = []
            if executor["kind"] in {"command", "truth", "terminal_truth"}:
                command_ids.append(executor["command"])
            if executor["kind"] in {"component_sequence", "gate_shard", "terminal_truth"}:
                command_ids.extend(
                    graph["step_components"][component]["command"]
                    for component in executor["components"]
                    if graph["step_components"][component]["kind"] == "command"
                )
            for command_id in command_ids:
                argv = graph["commands"][command_id]["argv"]
                normalized = " ".join(argv).lower()
                for token in forbidden:
                    if re.search(rf"(?:^|[^a-z0-9]){re.escape(token)}(?:$|[^a-z0-9])", normalized):
                        raise CIGraphError(
                            f"hosted waiter token {token!r} is prohibited in job {job['id']}"
                        )


def _validate_required_gate_ownership(repo_root: Path, graph: dict[str, Any]) -> None:
    profile_path = repo_root / "governance-profile.yml"
    if not profile_path.is_file() or profile_path.is_symlink():
        return
    try:
        profile = load_yaml_path(profile_path)
    except GraphYAMLError as exc:
        raise CIGraphError(str(exc)) from exc
    profile_contract_version = str(profile.get("profile_contract_version", "1.0"))
    if profile_contract_version != "2.0":
        return
    if str(graph.get("profile_contract_version", "1.0")) != profile_contract_version:
        # Profile promotion and workflow adoption are separate transactions.
        return
    gates = profile.get("release_gate_profile", {}).get("gates", {})
    if not isinstance(gates, dict):
        raise CIGraphError("governance profile has no release gate inventory")
    required = {
        str(value["target"])
        for value in gates.values()
        if isinstance(value, dict)
        and value.get("status") == "required"
        and isinstance(value.get("target"), str)
    }
    pull_request_workflows = [
        workflow
        for workflow in graph["workflows"]
        if any(event["type"] == "pull_request" for event in workflow["events"])
    ]
    if not pull_request_workflows:
        raise CIGraphError("CI graph has no pull-request workflow owning required gates")
    executed = [
        gate
        for workflow in pull_request_workflows
        for job in workflow["jobs"]
        if job["executor"]["kind"] in {"gate_group", "gate_shard"}
        for gate in job["executor"]["gates"]
    ]
    duplicates = sorted({gate for gate in executed if executed.count(gate) > 1})
    missing = sorted(required - set(executed))
    unexpected = sorted(set(executed) - required)
    if duplicates or missing or unexpected:
        raise CIGraphError(
            "pull-request gate ownership must exactly match profile-required targets: "
            f"duplicates={duplicates}, missing={missing}, unexpected={unexpected}"
        )


def _trusted_controller(
    repo_root: Path, graph: dict[str, Any]
) -> tuple[str, str, bool, tuple[tuple[str, str], ...]]:
    contract = graph["trusted_controller"]
    if contract["kind"] == "executable":
        executable = str(contract["executable"])
        return executable, f"command -v -- {executable} >/dev/null", True, ()
    relative = str(contract["policy_path"])
    path = repo_root / relative
    try:
        payload = load_yaml_path(path)
    except GraphYAMLError as exc:
        raise CIGraphError(str(exc)) from exc
    runner_security = payload.get("runner_security")
    if not isinstance(runner_security, dict):
        raise CIGraphError("self-governance policy lacks runner_security")
    pin = runner_security.get("trusted_controller_artifact")
    installation = runner_security.get("trusted_controller_installation")
    if not isinstance(pin, dict) or not isinstance(installation, dict):
        raise CIGraphError("self-governance policy lacks compiled controller custody")
    target = str(pin.get("BCF_BOOTSTRAP_COMMIT_SHA", ""))
    installed = str(installation.get("installed_commit_sha", ""))
    if re.fullmatch(r"[a-f0-9]{40}", target) is None or re.fullmatch(
        r"[a-f0-9]{40}", installed
    ) is None:
        raise CIGraphError("self-governance controller custody is not exact")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    control_root = f'"$RUNNER_TOOL_CACHE"/bcf-governance/{installed}'
    executable = f"{control_root}/bin/bcf"
    check = f"test -d {control_root}\ntest ! -L {control_root}\ntest -x {executable}"
    return executable, check, target == installed, ((relative, digest),)


def validate_ci_graph(
    repo_root: Path, graph_path: Path = GRAPH_PATH
) -> CompiledCIGraph:
    repo_root = repo_root.resolve()
    path = graph_path if graph_path.is_absolute() else repo_root / graph_path
    try:
        graph = load_yaml_path(path)
    except GraphYAMLError as exc:
        raise CIGraphError(str(exc)) from exc
    graph_schema = _schema(repo_root, GRAPH_SCHEMA_PATH)
    _validate_schema(graph, graph_schema, graph_path.as_posix())
    extensions, digests = _load_extensions(repo_root, graph)
    composed = _compose(graph, extensions)
    _apply_canonical_defaults(composed)
    try:
        composed, value_inputs = resolve_graph_values(repo_root, composed)
    except CIGraphValueError as exc:
        raise CIGraphError(str(exc)) from exc
    _validate_schema(composed, graph_schema, "composed CI graph")
    _validate_step_components(composed)
    _validate_workflows(composed)
    _validate_hosted_commands(composed)
    _validate_required_gate_ownership(repo_root, composed)
    controller, controller_check, controller_current, controller_inputs = _trusted_controller(
        repo_root, composed
    )
    inputs = tuple(sorted(set(value_inputs + controller_inputs)))
    graph_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return CompiledCIGraph(
        graph=composed,
        workflows=tuple(composed["workflows"]),
        commands=composed["commands"],
        graph_sha256=graph_digest,
        extension_sha256=digests,
        input_sha256=inputs,
        trusted_controller=controller,
        trusted_controller_check=controller_check,
        trusted_controller_current=controller_current,
    )
