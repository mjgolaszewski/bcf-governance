"""Profile-owned executable gate input contracts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .ci_graph_timeouts import bounded_execution_seconds
from .yaml_mutations import YAMLMutationPathError, mutation_mode


TEST_POLICIES = {
    "automated_tests",
    "contract_tests",
    "architecture_tests",
    "architecture_module_size",
    "architecture_layer_membership",
    "architecture_context_membership",
    "architecture_import_boundaries",
    "architecture_cqrs_side",
    "architecture_router_thinness",
    "architecture_duplication",
}

class ProfileContractError(ValueError):
    """Raised when a profile cannot become operational safely."""

def _safe_relative(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProfileContractError(f"{context} must be a non-empty path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ProfileContractError(f"{context} must stay inside the repository")
    return path.as_posix()

def _validate_oracle(raw: object, *, context: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ProfileContractError(f"{context} must be a mapping")
    kind = raw.get("kind")
    if kind == "test_node_failure":
        node_ids = raw.get("node_ids")
        if not isinstance(node_ids, list) or not node_ids or not all(
            isinstance(value, str) and value for value in node_ids
        ):
            raise ProfileContractError(f"{context}.node_ids must be a non-empty string list")
        return {"kind": kind, "node_ids": list(dict.fromkeys(node_ids))}
    if kind != "diagnostic":
        raise ProfileContractError(f"{context}.kind must be diagnostic or test_node_failure")
    exit_codes = raw.get("exit_codes")
    stream = raw.get("stream")
    pattern = raw.get("regex")
    if (
        not isinstance(exit_codes, list)
        or not exit_codes
        or not all(isinstance(value, int) and 1 <= value <= 125 for value in exit_codes)
        or stream not in {"stdout", "stderr"}
        or not isinstance(pattern, str)
        or not pattern
    ):
        raise ProfileContractError(
            f"{context} diagnostic requires exit_codes 1..125, stdout|stderr, and regex"
        )
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ProfileContractError(f"{context}.regex is invalid: {exc}") from exc
    return {
        "kind": kind,
        "exit_codes": sorted(set(exit_codes)),
        "stream": stream,
        "regex": pattern,
    }

def _validate_control(raw: object, *, context: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
        raise ProfileContractError(f"{context} requires a non-empty id")
    mutation = raw.get("mutation")
    if not isinstance(mutation, dict):
        raise ProfileContractError(f"{context}.mutation must be a mapping")
    path = mutation.get("path")
    if path != "@active_phase_log":
        _safe_relative(path, context=f"{context}.mutation.path")
    try:
        mutation_mode(mutation, suffix=Path(str(path)).suffix)
    except YAMLMutationPathError as exc:
        raise ProfileContractError(f"{context}.mutation {exc}") from exc
    return {
        "id": raw["id"],
        "mutation": dict(mutation),
        "oracle": _validate_oracle(raw.get("oracle"), context=f"{context}.oracle"),
    }

def _validate_gate(target: str, raw: object, *, command_policy: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ProfileContractError(f"gate {target} must be a mapping")
    invocation = raw.get("invocation")
    if not isinstance(invocation, dict):
        raise ProfileContractError(f"gate {target}.invocation must be a mapping")
    argv = invocation.get("argv")
    if not isinstance(argv, list) or not argv or not all(
        isinstance(value, str) and value for value in argv
    ):
        raise ProfileContractError(f"gate {target}.invocation.argv must be a non-empty string list")
    if Path(argv[0]).name.lower() in {"true", "false", "echo", "printf", ":"}:
        raise ProfileContractError(
            f"gate {target}.invocation.argv is a no-op, not executable evidence"
        )
    for index, argument in enumerate(argv):
        path_argument = Path(argument)
        if path_argument.is_absolute() or ".." in path_argument.parts:
            raise ProfileContractError(
                f"gate {target}.invocation.argv[{index}] must not escape the repository"
            )
    interpreter = Path(argv[0]).name.lower()
    if interpreter.startswith(("python", "node", "ruby", "perl")):
        if len(argv) < 2 or argv[1].startswith("-"):
            raise ProfileContractError(
                f"gate {target} must invoke a tracked script, not inline/module interpreter code"
            )
        _safe_relative(argv[1], context=f"gate {target}.invocation.argv[1]")
    cwd = _safe_relative(invocation.get("cwd", "."), context=f"gate {target}.invocation.cwd")
    env = invocation.get("env", {})
    required_env = invocation.get("required_env", [])
    if not isinstance(env, dict) or not all(
        isinstance(key, str) and key and isinstance(value, str) for key, value in env.items()
    ):
        raise ProfileContractError(f"gate {target}.invocation.env must contain string values")
    if not isinstance(required_env, list) or not all(
        isinstance(value, str) and value for value in required_env
    ):
        raise ProfileContractError(f"gate {target}.invocation.required_env must be a string list")
    declared_timeout: dict[str, int] = {}
    if "timeout_seconds" in invocation:
        try:
            declared_timeout["timeout_seconds"] = bounded_execution_seconds(
                invocation["timeout_seconds"], field=f"gate {target}.invocation.timeout_seconds"
            )
        except CIGraphError as exc:
            raise ProfileContractError(str(exc)) from exc
    controls = raw.get("negative_controls")
    if not isinstance(controls, list) or not controls:
        raise ProfileContractError(f"gate {target} requires at least one negative control")
    evidence = raw.get("evidence", {})
    if not isinstance(evidence, dict):
        raise ProfileContractError(f"gate {target}.evidence must be a mapping")
    evidence = dict(evidence)
    output_requirements = evidence.get("output_requirements", [])
    if not isinstance(output_requirements, list):
        raise ProfileContractError(f"gate {target}.evidence.output_requirements must be a list")
    normalized_outputs: list[dict[str, Any]] = []
    for index, output in enumerate(output_requirements):
        if not isinstance(output, dict) or not isinstance(output.get("media_type"), str):
            raise ProfileContractError(
                f"gate {target}.evidence.output_requirements[{index}] is invalid"
            )
        normalized_outputs.append(
            {
                "path": _safe_relative(
                    output.get("path"),
                    context=f"gate {target}.evidence.output_requirements[{index}].path",
                ),
                "media_type": output["media_type"],
                "authority": "non_authoritative_until_captured",
            }
        )
    if normalized_outputs:
        evidence["output_requirements"] = normalized_outputs
    validated_controls = [
        _validate_control(value, context=f"gate {target}.negative_controls[{index}]")
        for index, value in enumerate(controls)
    ]
    if command_policy in TEST_POLICIES:
        test_contract = evidence.get("test_contract")
        if not isinstance(test_contract, dict):
            raise ProfileContractError(f"gate {target} requires evidence.test_contract")
        junit_xml = _safe_relative(
            test_contract.get("junit_xml"),
            context=f"gate {target}.evidence.test_contract.junit_xml",
        )
        thresholds: dict[str, int] = {}
        for key, default in (("min_collected", 1), ("min_executed", 1), ("max_skipped", 0)):
            value = test_contract.get(key, default)
            if not isinstance(value, int) or value < 0:
                raise ProfileContractError(
                    f"gate {target}.evidence.test_contract.{key} must be a non-negative integer"
                )
            thresholds[key] = value
        if thresholds["min_executed"] < 1:
            raise ProfileContractError(f"gate {target} must execute at least one required test")
        if any(control["oracle"]["kind"] != "test_node_failure" for control in validated_controls):
            raise ProfileContractError(
                f"test gate {target} controls must use named test_node_failure oracles"
            )
        evidence = {
            **evidence,
            "test_contract": {
                **test_contract,
                **thresholds,
                "junit_xml": junit_xml,
                "artifact_binding": "non_authoritative_until_captured",
            },
        }
    return {
        "invocation": {
            "argv": argv,
            "cwd": cwd,
            "env": dict(sorted(env.items())),
            "required_env": sorted(set(required_env)),
            **declared_timeout,
        },
        "evidence": evidence,
        "negative_controls": validated_controls,
    }
