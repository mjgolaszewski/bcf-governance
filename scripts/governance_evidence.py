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


RECEIPT_SUFFIX = ".evidence.json"
DSSE_PAYLOAD_TYPE = "application/vnd.bcf.evidence-bundle.v1+json"
TEST_POLICIES = {"automated_tests", "contract_tests", "architecture_tests"}
TEST_POLICIES.update(
    {
        "architecture_module_size",
        "architecture_layer_membership",
        "architecture_context_membership",
        "architecture_import_boundaries",
        "architecture_cqrs_side",
        "architecture_router_thinness",
        "architecture_duplication",
    }
)


class EvidenceError(ValueError):
    """Raised when evidence cannot be captured safely."""


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise EvidenceError(f"missing required path {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvidenceError(f"{path} must deserialize to a mapping")
    return payload


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


def bundle_digest(bundle_dir: Path, *, exclude_names: set[str] | None = None) -> str:
    excluded = exclude_names or set()
    digest = hashlib.sha256()
    for path in sorted(bundle_dir.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        relative = path.relative_to(bundle_dir).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    return (
        b"DSSEv1 "
        + str(len(payload_type.encode("utf-8"))).encode("ascii")
        + b" "
        + payload_type.encode("utf-8")
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _profile_gate(repo_root: Path, gate_id: str) -> tuple[str, dict[str, Any]]:
    profile = _load_yaml(repo_root / "governance-profile.yml")
    release_profile = profile.get("release_gate_profile")
    gates = release_profile.get("gates") if isinstance(release_profile, dict) else None
    if not isinstance(gates, dict):
        raise EvidenceError("governance-profile.yml must define release_gate_profile.gates")
    for configured_id, value in gates.items():
        if not isinstance(value, dict):
            continue
        target = value.get("target")
        if gate_id in {configured_id, target}:
            if not isinstance(target, str) or not target:
                raise EvidenceError(f"gate {configured_id} has no target")
            return str(configured_id), value
    raise EvidenceError(f"unknown governance gate {gate_id!r}")


def _evidence_policy(repo_root: Path) -> dict[str, Any]:
    return _load_yaml(repo_root / "governance/evidence-policy.yml")


def _gate_contract(repo_root: Path, gate_id: str) -> dict[str, Any]:
    configured_id, gate = _profile_gate(repo_root, gate_id)
    policy = _evidence_policy(repo_root)
    overrides = policy.get("gate_overrides")
    override: dict[str, Any] = {}
    if isinstance(overrides, dict):
        candidate = overrides.get(gate.get("target"), overrides.get(configured_id, {}))
        if isinstance(candidate, dict):
            override = candidate
    command_policy = str(gate.get("command_policy", ""))
    default_kind = (
        "test_suite"
        if command_policy in TEST_POLICIES
        else "security_review"
        if command_policy == "security_review"
        else "runtime_health"
        if command_policy == "runtime_smoke"
        else "gate"
    )
    kind = str(override.get("evidence_kind") or default_kind)
    return {
        "id": configured_id,
        "target": str(gate["target"]),
        "status": str(gate.get("status", "required")),
        "command_policy": command_policy,
        "evidence_kind": kind,
        "negative_controls": override.get("negative_controls", []),
        "test_contract": override.get("test_contract", {}),
        "environment_assertions": override.get("environment_assertions", []),
        "output_requirements": override.get("output_requirements", []),
        "freshness_limit_seconds": override.get("freshness_limit_seconds"),
    }


def expected_evidence_kinds(repo_root: Path) -> dict[str, str]:
    """Return the policy-derived evidence kind for each configured gate target."""
    profile = _load_yaml(repo_root / "governance-profile.yml")
    release_profile = profile.get("release_gate_profile")
    gates = release_profile.get("gates") if isinstance(release_profile, dict) else {}
    if not isinstance(gates, dict):
        return {}
    return {
        str(gate["target"]): str(_gate_contract(repo_root, str(gate["target"]))["evidence_kind"])
        for gate in gates.values()
        if isinstance(gate, dict) and isinstance(gate.get("target"), str)
    }


def _command(contract: dict[str, Any]) -> list[str]:
    return ["make", str(contract["target"])]


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)


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


def _pytest_counts(text: str) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "xfailed": 0, "xpassed": 0}
    for name in counts:
        matches = re.findall(rf"(\d+)\s+{name}", text, flags=re.IGNORECASE)
        if matches:
            counts[name] = int(matches[-1])
    collected_matches = re.findall(r"collected\s+(\d+)\s+items?", text, flags=re.IGNORECASE)
    terminal_total = sum(counts.values())
    counts["collected"] = int(collected_matches[-1]) if collected_matches else terminal_total
    counts["executed"] = counts["passed"] + counts["failed"] + counts["errors"] + counts["xfailed"] + counts["xpassed"]
    return counts


def _junit_observations(path: Path) -> tuple[dict[str, int], list[str]]:
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    node_ids: list[str] = []
    skipped = failed = errors = 0
    for case in cases:
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "")
        node_ids.append(f"{classname}::{name}" if classname else name)
        skipped += int(case.find("skipped") is not None)
        failed += int(case.find("failure") is not None)
        errors += int(case.find("error") is not None)
    collected = len(cases)
    executed = collected - skipped
    return (
        {
            "collected": collected,
            "executed": executed,
            "passed": executed - failed - errors,
            "failed": failed,
            "errors": errors,
            "skipped": skipped,
            "xfailed": 0,
            "xpassed": 0,
        },
        sorted(node_ids),
    )


def recompute_test_artifact_observations(
    receipt_path: Path, receipt: dict[str, Any]
) -> tuple[dict[str, int], list[str] | None]:
    """Reparse raw test artifacts instead of trusting normalized receipt counts."""
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list):
        return _pytest_counts(""), None
    text_parts: list[str] = []
    for raw in artifacts:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            continue
        relative = Path(raw["path"])
        if relative.is_absolute() or ".." in relative.parts:
            continue
        path = receipt_path.parent / relative
        if not path.is_file():
            continue
        media_type = str(raw.get("media_type", ""))
        if "junit" in media_type or path.name.endswith(".junit.xml"):
            try:
                return _junit_observations(path)
            except (ET.ParseError, OSError, ValueError):
                return _pytest_counts(""), []
        if path.name.endswith((".stdout.txt", ".stderr.txt")):
            try:
                text_parts.append(path.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                continue
    return _pytest_counts("\n".join(text_parts)), None


def _test_observations(
    repo_root: Path,
    contract: dict[str, Any],
    result: subprocess.CompletedProcess[str],
    output_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    test_contract = contract.get("test_contract")
    test_contract = test_contract if isinstance(test_contract, dict) else {}
    thresholds = {
        "min_collected": int(test_contract.get("min_collected", 1)),
        "min_executed": int(test_contract.get("min_executed", 1)),
        "max_skipped": int(test_contract.get("max_skipped", 0)),
    }
    node_ids: list[str] = []
    artifacts: list[dict[str, str]] = []
    junit_path_value = test_contract.get("junit_xml")
    if isinstance(junit_path_value, str) and junit_path_value:
        source = repo_root / junit_path_value
        if not source.exists():
            counts = _pytest_counts(result.stdout + "\n" + result.stderr)
        else:
            counts, node_ids = _junit_observations(source)
            destination = output_dir / f"{contract['target']}.junit.xml"
            shutil.copy2(source, destination)
            artifacts.append(
                {"path": destination.name, "media_type": "application/junit+xml", "sha256": _sha256(destination)}
            )
    else:
        counts = _pytest_counts(result.stdout + "\n" + result.stderr)
    manifest_value = test_contract.get("expected_node_manifest")
    expected_nodes: list[str] = []
    if isinstance(manifest_value, str) and manifest_value:
        manifest_path = repo_root / manifest_value
        if manifest_path.exists():
            expected_nodes = sorted(
                line.strip()
                for line in manifest_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
    return (
        {
            "test_counts": counts,
            "test_thresholds": thresholds,
            "test_node_ids": node_ids,
            "expected_test_node_ids": expected_nodes,
            "expected_nodes_mode": str(test_contract.get("expected_nodes_mode", "contains")),
        },
        artifacts,
    )


def _apply_negative_control(worktree: Path, control: dict[str, Any]) -> bool:
    mutation = control.get("mutation")
    if not isinstance(mutation, dict):
        return False
    relative_path = mutation.get("path")
    if relative_path == "@active_phase_log":
        ledger = yaml.safe_load(
            (worktree / "plans/phase-ledger.yml").read_text(encoding="utf-8")
        )
        active = ledger.get("active_phase") if isinstance(ledger, dict) else None
        relative_path = active.get("log") if isinstance(active, dict) else None
    yaml_path = mutation.get("yaml_path")
    if isinstance(relative_path, str) and isinstance(yaml_path, str) and "value" in mutation:
        path = worktree / relative_path
        if not path.exists():
            return False
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
            return False
        if previous == mutation["value"]:
            return False
        path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        return True
    search = mutation.get("search")
    replace = mutation.get("replace")
    replace_base64 = mutation.get("replace_base64")
    if not isinstance(relative_path, str) or not isinstance(search, str):
        return False
    if isinstance(replace_base64, str):
        try:
            replace = base64.b64decode(replace_base64, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
    if not isinstance(replace, str):
        return False
    path = worktree / str(relative_path)
    if not path.exists():
        return False
    source = path.read_text(encoding="utf-8")
    if str(search) not in source:
        return False
    path.write_text(source.replace(search, replace, 1), encoding="utf-8")
    return True


def _negative_control_results(
    repo_root: Path, contract: dict[str, Any], command: list[str]
) -> list[dict[str, Any]]:
    controls = contract.get("negative_controls")
    if not isinstance(controls, list):
        return []
    results: list[dict[str, Any]] = []
    for index, raw_control in enumerate(controls, start=1):
        control = raw_control if isinstance(raw_control, dict) else {}
        control_id = str(control.get("id", f"control-{index}"))
        with tempfile.TemporaryDirectory(prefix="bcf-evidence-") as temp_name:
            worktree = Path(temp_name) / "repo"
            _git(repo_root, "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD")
            try:
                applied = _apply_negative_control(worktree, control)
                observed = _run(command, cwd=worktree) if applied else None
                results.append(
                    {
                        "id": control_id,
                        "mutation_applied": applied,
                        "expected_exit": "nonzero",
                        "observed_exit_code": observed.returncode if observed is not None else None,
                        "stdout_sha256": hashlib.sha256(
                            (observed.stdout if observed is not None else "").encode("utf-8")
                        ).hexdigest(),
                        "stderr_sha256": hashlib.sha256(
                            (observed.stderr if observed is not None else "").encode("utf-8")
                        ).hexdigest(),
                    }
                )
            finally:
                _git(repo_root, "worktree", "remove", "--force", str(worktree), check=False)
    return results


def _environment_observations(contract: dict[str, Any]) -> list[dict[str, Any]]:
    assertions = contract.get("environment_assertions")
    if not isinstance(assertions, list):
        return []
    observed: list[dict[str, Any]] = []
    for raw in assertions:
        assertion = raw if isinstance(raw, dict) else {}
        name = assertion.get("name")
        if not isinstance(name, str) or not name:
            continue
        value = os.environ.get(name)
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


def capture_gate(repo_root: Path, gate_id: str, output_dir: Path) -> Path:
    repo_root = repo_root.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    contract = _gate_contract(repo_root, gate_id)
    target = str(contract["target"])
    command = _command(contract)
    head = _git(repo_root, "rev-parse", "HEAD")
    tree = _git(repo_root, "rev-parse", "HEAD^{tree}")
    tracked_clean = not bool(_git(repo_root, "status", "--porcelain", "--untracked-files=no"))
    started = datetime.now(UTC)
    result = _run(command, cwd=repo_root)
    completed = datetime.now(UTC)
    artifacts = _write_output_artifacts(output_dir, target, result)
    observations: dict[str, Any] = {
        "exit_code": result.returncode,
        "environment_assertions": _environment_observations(contract),
    }
    output_observations, output_artifacts = _required_output_observations(
        repo_root, contract, output_dir
    )
    observations["output_requirements"] = output_observations
    artifacts.extend(output_artifacts)
    if contract["evidence_kind"] == "test_suite":
        test_observations, test_artifacts = _test_observations(
            repo_root, contract, result, output_dir
        )
        observations.update(test_observations)
        artifacts.extend(test_artifacts)
    probes = _negative_control_results(repo_root, contract, command)
    producer_kind = os.environ.get(
        "BCF_EVIDENCE_PRODUCER_KIND",
        "workflow" if os.environ.get("GITHUB_ACTIONS") == "true" else "service",
    )
    if producer_kind not in {"human", "model", "service", "workflow"}:
        raise EvidenceError("BCF_EVIDENCE_PRODUCER_KIND must be human, model, service, or workflow")
    receipt = {
        "schema_version": "1.0",
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
            "workflow": {
                "provider": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local",
                "path": os.environ.get("GITHUB_WORKFLOW_REF", "local"),
                "job": os.environ.get("GITHUB_JOB", "local"),
                "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
                "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
                "matrix": {"gate": target},
            },
        },
        "subject": {
            "commit_sha": head,
            "tree_sha": tree,
            "binding": "exact_tree",
            "tracked_clean": tracked_clean,
        },
        "artifacts": artifacts,
        "observations": observations,
        "behavioral_probes": probes,
        "result": "passed" if result.returncode == 0 else "failed",
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "timestamp": completed.isoformat().replace("+00:00", "Z"),
    }
    if isinstance(contract.get("freshness_limit_seconds"), int):
        receipt["freshness_limit_seconds"] = contract["freshness_limit_seconds"]
    receipt_path = output_dir / f"{target}{RECEIPT_SUFFIX}"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt_path


def attest_bundle(
    repo_root: Path,
    bundle_dir: Path,
    private_key: Path,
    key_id: str,
    actor_id: str,
    output: Path,
    actor_kind: str = "service",
) -> Path:
    if actor_kind not in {"human", "model", "service", "workflow"}:
        raise EvidenceError("attestation actor kind must be human, model, service, or workflow")
    statement = {
        "bundle_sha256": bundle_digest(bundle_dir, exclude_names={output.name}),
        "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
        "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
        "verifier": {"kind": actor_kind, "id": actor_id},
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signed_payload = _dsse_pae(DSSE_PAYLOAD_TYPE, payload)
    with tempfile.NamedTemporaryFile() as payload_file, tempfile.NamedTemporaryFile() as signature_file:
        payload_file.write(signed_payload)
        payload_file.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                payload_file.name,
                "-out",
                signature_file.name,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise EvidenceError(result.stderr.strip() or "unable to sign evidence bundle")
        signature = Path(signature_file.name).read_bytes()
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Capture or attest governance evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    subparsers = parser.add_subparsers(dest="operation", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--gate", required=True)
    run_parser.add_argument("--output", type=Path, required=True)
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
            path = capture_gate(args.repo_root, args.gate, args.output)
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
    except EvidenceError as exc:
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
            or not isinstance(probe.get("observed_exit_code"), int)
            or probe["observed_exit_code"] == 0
            for probe in probes
        )
        if observations.get("exit_code") != 0 or invalid_probe:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
