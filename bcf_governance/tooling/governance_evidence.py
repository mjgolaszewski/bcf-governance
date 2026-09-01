"""Capture and attest portable governance evidence bundles."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .evidence_attestation import attest_bundle, bundle_digest
from .evidence_execution import (
    EvidenceError,
    _command,
    _execution_cwd,
    _execution_env,
    _run,
    _runtime_command,
    _selected_python,
)
from .evidence_gate_contracts import (
    _gate_contract,
    _load_yaml,
    expected_evidence_kinds,
    expected_invocations,
)
from .evidence_sessions import allocate_session, bind_session, local_producer_identity
from .evidence_sessions import receipt_workflow_identity
from .evidence_test_adapters import (
    recompute_test_artifact_observations,
    test_observations as _test_observations,
)
from .negative_control_execution import negative_control_command


RECEIPT_SUFFIX = ".evidence.json"


def _git(repo_root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise EvidenceError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_output_artifacts(
    output_dir: Path, gate_id: str, result: subprocess.CompletedProcess[str]
) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    for suffix, value in (("stdout", result.stdout), ("stderr", result.stderr)):
        path = output_dir / f"{gate_id}.{suffix}.txt"
        path.write_text(value, encoding="utf-8")
        artifacts.append(
            {
                "path": path.name,
                "media_type": "text/plain",
                "sha256": _sha256(path),
            }
        )
    return artifacts


def _tracked_mutation_path(worktree: Path, relative_path: object) -> Path | None:
    if not isinstance(relative_path, str) or not relative_path:
        return None
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    lexical = worktree / relative
    if lexical.is_symlink() or not lexical.is_file():
        return None
    resolved = lexical.resolve()
    if not resolved.is_relative_to(worktree.resolve()):
        return None
    tracked = _git(worktree, "ls-files", "--error-unmatch", relative.as_posix(), check=False)
    if tracked != relative.as_posix():
        return None
    return resolved


def _apply_negative_control(worktree: Path, control: dict[str, Any]) -> tuple[bool, str | None]:
    mutation = control.get("mutation")
    if not isinstance(mutation, dict):
        return False, None
    relative_path = mutation.get("path")
    if relative_path == "@active_phase_log":
        ledger = yaml.safe_load(
            (worktree / "plans/phase-ledger.yml").read_text(encoding="utf-8")
        )
        active = ledger.get("active_phase") if isinstance(ledger, dict) else None
        relative_path = active.get("log") if isinstance(active, dict) else None
    path = _tracked_mutation_path(worktree, relative_path)
    if path is None:
        return False, None
    tracked_relative = path.relative_to(worktree.resolve()).as_posix()
    yaml_path = mutation.get("yaml_path")
    if isinstance(relative_path, str) and isinstance(yaml_path, str) and "value" in mutation:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        current: Any = payload
        tokens = yaml_path.split(".")
        try:
            for token in tokens[:-1]:
                current = current[int(token)] if isinstance(current, list) else current[token]
            last = tokens[-1]
            previous = current[int(last)] if isinstance(current, list) else current.get(last)
            if isinstance(current, list):
                current[int(last)] = mutation["value"]
            else:
                current[last] = mutation["value"]
        except (KeyError, IndexError, TypeError, ValueError):
            return False, None
        if previous == mutation["value"]:
            return False, None
        path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        return True, tracked_relative
    search = mutation.get("search")
    replace = mutation.get("replace")
    replace_base64 = mutation.get("replace_base64")
    if not isinstance(relative_path, str) or not isinstance(search, str):
        return False, None
    if isinstance(replace_base64, str):
        try:
            replace = base64.b64decode(replace_base64, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False, None
    if not isinstance(replace, str):
        return False, None
    source = path.read_text(encoding="utf-8")
    if str(search) not in source:
        return False, None
    path.write_text(source.replace(search, replace, 1), encoding="utf-8")
    return True, tracked_relative


def _unexpected_worktree_changes(worktree: Path, allowed_tracked: set[str]) -> list[str]:
    modified = {
        value
        for value in _git(worktree, "diff", "--name-only", "HEAD").splitlines()
        if value
    }
    staged = {
        value
        for value in _git(worktree, "diff", "--cached", "--name-only", "HEAD").splitlines()
        if value
    }
    untracked = {
        value
        for value in _git(worktree, "ls-files", "--others", "--exclude-standard").splitlines()
        if value
    }
    return sorted((modified | staged) - allowed_tracked | untracked)


def _junit_failed_nodes(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    root = ET.parse(path).getroot()
    failed: set[str] = set()
    for case in root.iter("testcase"):
        if case.find("failure") is None and case.find("error") is None:
            continue
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "")
        failed.add(f"{classname}::{name}" if classname else name)
    return failed


def _oracle_observation(
    worktree: Path,
    contract: dict[str, Any],
    control: dict[str, Any],
    observed: subprocess.CompletedProcess[str] | None,
) -> dict[str, Any]:
    oracle = control.get("oracle")
    if not isinstance(oracle, dict) or observed is None:
        return {"satisfied": False, "reason": "oracle_or_execution_missing"}
    if observed.returncode in {126, 127} or observed.returncode < 0 or observed.returncode >= 128:
        return {"satisfied": False, "reason": "infrastructure_failure"}
    if oracle.get("kind") == "diagnostic":
        exit_codes = oracle.get("exit_codes", [])
        stream = oracle.get("stream")
        pattern = oracle.get("regex")
        value = observed.stdout if stream == "stdout" else observed.stderr
        matched = (
            isinstance(exit_codes, list)
            and observed.returncode in exit_codes
            and isinstance(pattern, str)
            and re.search(pattern, value) is not None
        )
        return {
            "satisfied": matched,
            "kind": "diagnostic",
            "exit_code_matched": observed.returncode in exit_codes if isinstance(exit_codes, list) else False,
            "diagnostic_matched": bool(isinstance(pattern, str) and re.search(pattern, value)),
        }
    if oracle.get("kind") == "test_node_failure":
        test_contract = contract.get("test_contract")
        junit_value = test_contract.get("junit_xml") if isinstance(test_contract, dict) else None
        failed_nodes = (
            _junit_failed_nodes(worktree / junit_value)
            if isinstance(junit_value, str)
            else set()
        )
        expected = {str(value) for value in oracle.get("node_ids", [])}
        return {
            "satisfied": bool(expected) and expected.issubset(failed_nodes),
            "kind": "test_node_failure",
            "failed_node_ids": sorted(failed_nodes),
        }
    return {"satisfied": False, "reason": "unknown_oracle"}


def _negative_control_results(
    repo_root: Path,
    contract: dict[str, Any],
    command: list[str],
    output_dir: Path,
    baseline_observations: dict[str, Any],
    python_executable: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    controls = contract.get("negative_controls")
    if not isinstance(controls, list):
        return [], []
    results: list[dict[str, Any]] = []
    artifacts: list[dict[str, str]] = []
    for index, raw_control in enumerate(controls, start=1):
        control = raw_control if isinstance(raw_control, dict) else {}
        control_id = str(control.get("id", f"control-{index}"))
        with tempfile.TemporaryDirectory(prefix="bcf-evidence-") as temp_name:
            worktree = Path(temp_name) / "repo"
            _git(repo_root, "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD")
            try:
                applied, mutation_path = _apply_negative_control(worktree, control)
                env, _ = _execution_env(worktree, contract, python_executable)
                observed = (
                    _run(negative_control_command(command, contract, control, python_executable, worktree), cwd=_execution_cwd(worktree, contract), env=env)
                    if applied
                    else None
                )
                oracle_observation = _oracle_observation(
                    worktree, contract, control, observed
                )
                oracle = control.get("oracle")
                baseline_nodes = {
                    str(value)
                    for value in baseline_observations.get("test_node_ids", [])
                    if isinstance(value, str)
                }
                required_baseline_nodes = {
                    str(value)
                    for value in oracle.get("node_ids", [])
                    if isinstance(oracle, dict) and isinstance(value, str)
                }
                baseline_nodes_passed = (
                    oracle.get("kind") != "test_node_failure"
                    if isinstance(oracle, dict)
                    else False
                ) or (
                    bool(required_baseline_nodes)
                    and required_baseline_nodes.issubset(baseline_nodes)
                )
                if not baseline_nodes_passed:
                    oracle_observation = {
                        **oracle_observation,
                        "satisfied": False,
                        "reason": "baseline_test_nodes_not_passing",
                    }
                unexpected_changes = _unexpected_worktree_changes(
                    worktree,
                    {mutation_path} if mutation_path is not None else set(),
                )
                if unexpected_changes:
                    oracle_observation = {
                        **oracle_observation,
                        "satisfied": False,
                        "reason": "unexpected_worktree_changes",
                    }
                artifact_names: dict[str, str] = {}
                for stream in ("stdout", "stderr"):
                    path = output_dir / f"{contract['target']}.{control_id}.{stream}.txt"
                    path.write_text(
                        getattr(observed, stream) if observed is not None else "",
                        encoding="utf-8",
                    )
                    artifact = {
                        "path": path.name,
                        "media_type": "text/plain",
                        "sha256": _sha256(path),
                    }
                    artifacts.append(artifact)
                    artifact_names[stream] = path.name
                test_contract = contract.get("test_contract")
                junit_value = (
                    test_contract.get("junit_xml")
                    if isinstance(test_contract, dict)
                    else None
                )
                if isinstance(junit_value, str) and (worktree / junit_value).is_file():
                    junit_path = output_dir / f"{contract['target']}.{control_id}.junit.xml"
                    shutil.copy2(worktree / junit_value, junit_path)
                    artifacts.append(
                        {
                            "path": junit_path.name,
                            "media_type": "application/junit+xml",
                            "sha256": _sha256(junit_path),
                        }
                    )
                    artifact_names["junit"] = junit_path.name
                results.append(
                    {
                        "id": control_id,
                        "mutation_applied": applied,
                        "oracle": control.get("oracle"),
                        "oracle_observation": oracle_observation,
                        "baseline_test_nodes_passed": baseline_nodes_passed,
                        "unexpected_worktree_changes": unexpected_changes,
                        "observed_exit_code": observed.returncode if observed is not None else None,
                        "raw_artifacts": artifact_names,
                    }
                )
            finally:
                _git(repo_root, "worktree", "remove", "--force", str(worktree), check=False)
    return results, artifacts


def _environment_observations(
    contract: dict[str, Any], runtime_env: dict[str, str]
) -> list[dict[str, Any]]:
    assertions = contract.get("environment_assertions")
    if not isinstance(assertions, list):
        return []
    observed: list[dict[str, Any]] = []
    for raw in assertions:
        assertion = raw if isinstance(raw, dict) else {}
        name = assertion.get("name")
        if not isinstance(name, str) or not name:
            continue
        value = runtime_env.get(name)
        observed.append(
            {
                "name": name,
                "operator": str(assertion.get("operator", "equals")),
                "expected": assertion.get("value"),
                "actual": value,
                "satisfied": value == str(assertion.get("value")),
            }
        )
    return observed


def _required_output_observations(
    repo_root: Path, contract: dict[str, Any], output_dir: Path
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    requirements = contract.get("output_requirements")
    if not isinstance(requirements, list):
        return [], []
    observations: list[dict[str, Any]] = []
    artifacts: list[dict[str, str]] = []
    for index, raw in enumerate(requirements, start=1):
        requirement = raw if isinstance(raw, dict) else {}
        relative = requirement.get("path")
        media_type = requirement.get("media_type")
        safe = (
            isinstance(relative, str)
            and not Path(relative).is_absolute()
            and ".." not in Path(relative).parts
        )
        source = repo_root / str(relative) if safe else None
        satisfied = bool(source is not None and source.is_file())
        observation = {
            "path": relative,
            "media_type": media_type,
            "satisfied": satisfied,
        }
        if satisfied and source is not None:
            destination = output_dir / f"required-{index}-{source.name}"
            shutil.copy2(source, destination)
            artifact = {
                "path": destination.name,
                "media_type": str(media_type),
                "sha256": _sha256(destination),
            }
            artifacts.append(artifact)
            observation["artifact_path"] = destination.name
            observation["artifact_sha256"] = artifact["sha256"]
        observations.append(observation)
    return observations, artifacts


def _capture_preflight(repo_root: Path, output_dir: Path) -> dict[str, Any]:
    status = _git(
        repo_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=no",
    )
    if status:
        raise EvidenceError(
            "exact-tree evidence requires no staged, unstaged, or non-ignored untracked files:\n"
            + status
        )
    root = repo_root.resolve()
    resolved_output = output_dir.resolve()
    if resolved_output == root:
        raise EvidenceError("evidence output cannot be the governed repository root")
    if resolved_output.is_relative_to(root):
        relative = resolved_output.relative_to(root).as_posix()
        ignored = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", relative],
            cwd=repo_root,
            check=False,
        )
        if ignored.returncode != 0:
            raise EvidenceError("in-repository evidence output must be ignored by Git")
    for line in _git(repo_root, "ls-files", "-s").splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) != 4 or fields[0] != "120000":
            continue
        relative = Path(fields[3])
        link = repo_root / relative
        target = Path(os.readlink(link))
        resolved = target if target.is_absolute() else (link.parent / target).resolve()
        if target.is_absolute() or not resolved.is_relative_to(root):
            raise EvidenceError(f"tracked symlink escapes governed tree: {relative.as_posix()}")
    return {
        "tracked_clean": True,
        "untracked_clean": True,
        "status_porcelain_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
    }


def capture_gate(
    repo_root: Path,
    gate_id: str,
    output_dir: Path,
    *,
    python_executable: str | Path | None = None,
    session_manifest: Path | None = None,
) -> Path:
    repo_root = repo_root.resolve()
    caller_state = _capture_preflight(repo_root, output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    contract = _gate_contract(repo_root, gate_id)
    target = str(contract["target"])
    profile_payload = _load_yaml(repo_root / "governance-profile.yml")
    contract_version = str(profile_payload.get("profile_contract_version", "1.0"))
    session, session_artifact = bind_session(
        repo_root,
        target,
        output_dir,
        session_manifest,
        required=contract_version == "2.0",
    )
    workflow_identity = receipt_workflow_identity(session, target)
    command = _command(contract)
    selected_python = _selected_python(python_executable)
    runtime_command = _runtime_command(command, selected_python)
    head = _git(repo_root, "rev-parse", "HEAD")
    tree = _git(repo_root, "rev-parse", "HEAD^{tree}")
    started = datetime.now(UTC)
    with tempfile.TemporaryDirectory(prefix="bcf-evidence-positive-") as temp_name:
        worktree = Path(temp_name) / "repo"
        _git(repo_root, "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD")
        try:
            env, environment_metadata = _execution_env(
                worktree, contract, selected_python
            )
            result = _run(
                runtime_command, cwd=_execution_cwd(worktree, contract), env=env
            )
            artifacts = _write_output_artifacts(output_dir, target, result)
            if session_artifact is not None:
                artifacts.append(session_artifact)
            observations: dict[str, Any] = {
                "exit_code": result.returncode,
                "execution_environment": environment_metadata,
                "environment_assertions": _environment_observations(contract, env),
            }
            if session is not None:
                observations["evidence_session"] = {
                    "session_id": session.payload["session_id"],
                    "manifest_sha256": session.digest,
                }
            output_observations, output_artifacts = _required_output_observations(
                worktree, contract, output_dir
            )
            observations["output_requirements"] = output_observations
            artifacts.extend(output_artifacts)
            if contract["evidence_kind"] == "test_suite":
                test_observations, test_artifacts = _test_observations(
                    worktree, contract, result, output_dir
                )
                observations.update(test_observations)
                artifacts.extend(test_artifacts)
            post_status = _git(
                worktree,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=no",
            )
            observations["execution_tree_clean"] = not bool(post_status)
            observations["execution_tree_status_sha256"] = hashlib.sha256(
                post_status.encode("utf-8")
            ).hexdigest()
        finally:
            _git(repo_root, "worktree", "remove", "--force", str(worktree), check=False)
    probes: list[dict[str, Any]] = []
    if result.returncode == 0 and observations["execution_tree_clean"]:
        probes, probe_artifacts = _negative_control_results(
            repo_root,
            contract,
            runtime_command,
            output_dir,
            observations,
            selected_python,
        )
        artifacts.extend(probe_artifacts)
    completed = datetime.now(UTC)
    session_kind = session.payload["producer"]["kind"] if session else None
    default_producer_kind = (
        "workflow"
        if session_kind == "workflow"
        or (session is None and os.environ.get("GITHUB_ACTIONS") == "true")
        else "service"
    )
    producer_kind = os.environ.get(
        "BCF_EVIDENCE_PRODUCER_KIND", default_producer_kind
    )
    if producer_kind not in {"human", "model", "service", "workflow"}:
        raise EvidenceError("BCF_EVIDENCE_PRODUCER_KIND must be human, model, service, or workflow")
    receipt = {
        "schema_version": "2.0",
        "kind": contract["evidence_kind"],
        "evidence_id": f"{target}-{head[:12]}",
        "gate_id": target,
        "producer": {
            "kind": producer_kind,
            "id": os.environ.get("BCF_EVIDENCE_PRODUCER_ID")
            or os.environ.get("GITHUB_ACTOR")
            or os.environ.get("USER")
            or "bcf-evidence",
        },
        "invocation": {
            "argv": command,
            "cwd": contract["invocation"].get("cwd", "."),
            "environment": observations["execution_environment"],
            "workflow": workflow_identity,
        },
        "subject": {
            "commit_sha": head,
            "tree_sha": tree,
            "binding": "exact_tree",
            **caller_state,
            "execution_tree_sha": tree,
        },
        "artifacts": artifacts,
        "observations": observations,
        "behavioral_probes": probes,
        "result": (
            "passed"
            if result.returncode == 0
            and observations["execution_tree_clean"]
            and all(
                value.get("satisfied") is True
                for value in observations.get("environment_assertions", [])
                if isinstance(value, dict)
            )
            and all(
                value.get("satisfied") is True
                for value in observations.get("output_requirements", [])
                if isinstance(value, dict)
            )
            and probes
            and all(probe.get("oracle_observation", {}).get("satisfied") is True for probe in probes)
            else "failed"
        ),
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "timestamp": completed.isoformat().replace("+00:00", "Z"),
    }
    if isinstance(contract.get("freshness_limit_seconds"), int):
        receipt["freshness_limit_seconds"] = contract["freshness_limit_seconds"]
    receipt_path = output_dir / f"{target}{RECEIPT_SUFFIX}"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt_path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Capture or attest governance evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    subparsers = parser.add_subparsers(dest="operation", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--gate", required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--python", type=Path)
    run_parser.add_argument("--session-manifest", type=Path)
    session_parser = subparsers.add_parser("session")
    session_parser.add_argument("--artifact-root", type=Path, required=True)
    session_parser.add_argument("--expected-gate", action="append", default=[])
    session_parser.add_argument("--expected-producer", action="append", default=[])
    session_parser.add_argument("--local-producer-id")
    attest_parser = subparsers.add_parser("attest")
    attest_parser.add_argument("--bundle-dir", type=Path, required=True)
    attest_parser.add_argument("--private-key", type=Path, required=True)
    attest_parser.add_argument("--key-id", required=True)
    attest_parser.add_argument("--actor-id", required=True)
    attest_parser.add_argument(
        "--actor-kind", choices=("human", "model", "service", "workflow"), default="service"
    )
    attest_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "run":
            path = capture_gate(
                args.repo_root,
                args.gate,
                args.output,
                python_executable=args.python,
                session_manifest=args.session_manifest,
            )
        elif args.operation == "session":
            expected_gates = args.expected_gate or sorted(
                expected_evidence_kinds(args.repo_root.resolve())
            )
            session = allocate_session(
                args.repo_root.resolve(),
                args.artifact_root,
                expected_gates,
                expected_producers=args.expected_producer or None,
                producer_identity=(
                    local_producer_identity(
                        args.repo_root.resolve(), args.local_producer_id
                    )
                    if args.local_producer_id
                    else None
                ),
            )
            path = session.manifest_path
        else:
            path = attest_bundle(
                args.repo_root.resolve(),
                args.bundle_dir.resolve(),
                args.private_key.resolve(),
                args.key_id,
                args.actor_id,
                args.output.resolve(),
                args.actor_kind,
            )
    except (ValueError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=os.sys.stderr)
        raise SystemExit(1)
    print(path)
    if args.operation == "run":
        receipt = json.loads(path.read_text(encoding="utf-8"))
        observations = receipt.get("observations", {})
        probes = receipt.get("behavioral_probes", [])
        invalid_probe = not probes or any(
            not isinstance(probe, dict)
            or probe.get("mutation_applied") is not True
            or probe.get("oracle_observation", {}).get("satisfied") is not True
            for probe in probes
        )
        if receipt.get("result") != "passed" or observations.get("exit_code") != 0 or invalid_probe:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
