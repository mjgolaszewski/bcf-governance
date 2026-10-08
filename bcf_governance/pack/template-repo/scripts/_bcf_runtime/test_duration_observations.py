"""Mechanically project compact, non-authoritative test duration observations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Iterable
import xml.etree.ElementTree as ET


OBSERVATIONS_PATH = Path("governance/test-duration-observations.json")
MANIFEST_PATH = Path("governance/test-manifests/test.txt")
POLICY_PATH = Path("governance/gate-contracts.yml")


class TestDurationObservationError(ValueError):
    """A duration projection is not mechanically reproducible."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise TestDurationObservationError("test duration Git identity is unavailable")
    return result.stdout.strip()


def _manifest_nodes(repo_root: Path) -> tuple[str, ...]:
    path = repo_root / MANIFEST_PATH
    try:
        nodes = tuple(line for line in path.read_text(encoding="utf-8").splitlines() if line)
    except OSError as exc:
        raise TestDurationObservationError("test node manifest is unavailable") from exc
    if not nodes or tuple(sorted(nodes)) != nodes or len(set(nodes)) != len(nodes):
        raise TestDurationObservationError("test node manifest is not exact and ordered")
    return nodes


def _cache_root(repo_root: Path) -> Path | None:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or not result.stdout.strip():
        return None
    root = Path(result.stdout.strip()).resolve() / "bcf" / "proof-bundles"
    return root if root.is_dir() and not root.is_symlink() else None


def _junit_durations(path: Path) -> dict[str, int]:
    try:
        cases = ET.parse(path).getroot().iter("testcase")
    except (OSError, ET.ParseError) as exc:
        raise TestDurationObservationError("test duration JUnit is unreadable") from exc
    durations: dict[str, int] = {}
    for case in cases:
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "")
        node = f"{classname}::{name}" if classname else name
        try:
            duration = max(1, round(float(case.attrib.get("time", "0")) * 1000))
        except ValueError as exc:
            raise TestDurationObservationError("test duration JUnit contains invalid time") from exc
        if not node or node in durations:
            raise TestDurationObservationError("test duration JUnit node inventory is ambiguous")
        durations[node] = duration
    return durations


def _is_ancestor(repo_root: Path, commit: str) -> bool:
    if len(commit) != 40:
        return False
    return subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", commit, "HEAD"],
        capture_output=True,
        check=False,
    ).returncode == 0


def _candidate_sources(
    repo_root: Path, nodes: tuple[str, ...], policy_sha256: str
) -> dict[str, list[tuple[str, dict[str, int], str, str, tuple[str, ...]]]]:
    root = _cache_root(repo_root)
    sources: dict[str, list[tuple[str, dict[str, int], str, str, tuple[str, ...]]]] = {}
    current_nodes = set(nodes)
    if root is None:
        return sources
    for bundle in sorted(path for path in root.iterdir() if path.is_dir() and not path.is_symlink()):
        proof = bundle / "proof-bundle.json"
        partition = bundle / "evidence/test/test.partition.json"
        junit = bundle / "evidence/test/test.junit.xml"
        evidence = bundle / "evidence/test/test.evidence.json"
        try:
            proof_payload = json.loads(proof.read_text(encoding="utf-8"))
            partition_payload = json.loads(partition.read_text(encoding="utf-8"))
            evidence_payload = json.loads(evidence.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        identity = partition_payload.get("identity")
        if not isinstance(identity, dict):
            continue
        raw_inventory = partition_payload.get("node_inventory")
        if not isinstance(raw_inventory, list) or any(
            not isinstance(node, str) or not node for node in raw_inventory
        ):
            continue
        source_nodes = tuple(raw_inventory)
        commit = identity.get("subject_commit")
        tree = identity.get("subject_tree")
        if (
            not isinstance(commit, str)
            or not isinstance(tree, str)
            or identity.get("producer") != "test"
            or identity.get("policy_sha256") != policy_sha256
            or not source_nodes
            or tuple(sorted(source_nodes)) != source_nodes
            or len(set(source_nodes)) != len(source_nodes)
            or not set(source_nodes).issubset(current_nodes)
            or not _is_ancestor(repo_root, commit)
        ):
            continue
        try:
            durations = _junit_durations(junit)
        except TestDurationObservationError:
            continue
        if tuple(sorted(durations)) != source_nodes:
            continue
        selected = evidence_payload.get("observations", {}).get("execution_environment", {}).get("selected_interpreter")
        bundle_digest = proof_payload.get("bundle_sha256")
        if not isinstance(selected, dict) or not isinstance(bundle_digest, str) or len(bundle_digest) != 64:
            continue
        interpreter_digest = selected.get("binary_sha256")
        if not isinstance(interpreter_digest, str) or len(interpreter_digest) != 64:
            continue
        sources.setdefault(commit, []).append(
            (bundle_digest, durations, tree, interpreter_digest, source_nodes)
        )
    return sources


def _newest_ancestor(repo_root: Path, commits: Iterable[str]) -> str | None:
    candidates = set(commits)
    if not candidates:
        return None
    for commit in _git(repo_root, "rev-list", "HEAD").splitlines():
        if commit in candidates:
            return commit
    return None


def compile_test_duration_observations(repo_root: Path) -> dict[str, Any]:
    """Compile the newest applicable ancestor JUnit into one compact vector."""

    nodes = _manifest_nodes(repo_root)
    manifest_sha256 = _sha256(repo_root / MANIFEST_PATH)
    policy_sha256 = _sha256(repo_root / POLICY_PATH)
    sources = _candidate_sources(repo_root, nodes, policy_sha256)
    selected_commit = _newest_ancestor(repo_root, sources)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "kind": "bcf.test-duration-observations.v1",
        "authority": False,
        "test_manifest": {
            "path": MANIFEST_PATH.as_posix(),
            "sha256": manifest_sha256,
            "node_count": len(nodes),
        },
        "policy_sha256": policy_sha256,
    }
    if selected_commit is None:
        payload.update({"status": "absent", "source": None, "durations_ms": []})
    else:
        selected = sorted(sources[selected_commit], key=lambda item: item[0])
        trees = {item[2] for item in selected}
        interpreters = {item[3] for item in selected}
        inventories = {item[4] for item in selected}
        if len(trees) != 1 or len(interpreters) != 1 or len(inventories) != 1:
            raise TestDurationObservationError("test duration source identity is ambiguous")
        source_nodes = next(iter(inventories))
        source_node_set = set(source_nodes)
        vector = [
            (
                sorted(item[1][node] for item in selected)[(len(selected) - 1) // 2]
                if node in source_node_set
                else 0
            )
            for node in nodes
        ]
        payload.update(
            {
                "status": "observed" if len(source_nodes) == len(nodes) else "observed_partial",
                "source": {
                    "subject_commit": selected_commit,
                    "subject_tree": next(iter(trees)),
                    "proof_bundle_sha256": [item[0] for item in selected],
                    "interpreter_sha256": next(iter(interpreters)),
                    "observed_node_count": len(source_nodes),
                    "observed_node_inventory_sha256": hashlib.sha256(
                        _canonical({"nodes": list(source_nodes)})
                    ).hexdigest(),
                },
                "durations_ms": vector,
            }
        )
    payload["observations_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return payload


def validate_test_duration_observations(repo_root: Path, payload: dict[str, Any]) -> dict[str, int]:
    """Validate exact current inventory and return the reconstructed duration mapping."""

    nodes = _manifest_nodes(repo_root)
    expected_keys = {
        "schema_version", "kind", "authority", "status", "test_manifest",
        "policy_sha256", "source", "durations_ms", "observations_sha256",
    }
    unsigned = {key: value for key, value in payload.items() if key != "observations_sha256"}
    if (
        set(payload) != expected_keys
        or payload.get("schema_version") != "1.0"
        or payload.get("kind") != "bcf.test-duration-observations.v1"
        or payload.get("authority") is not False
        or payload.get("status") not in {"absent", "observed", "observed_partial"}
        or payload.get("policy_sha256") != _sha256(repo_root / POLICY_PATH)
        or payload.get("test_manifest") != {
            "path": MANIFEST_PATH.as_posix(),
            "sha256": _sha256(repo_root / MANIFEST_PATH),
            "node_count": len(nodes),
        }
        or payload.get("observations_sha256") != hashlib.sha256(_canonical(unsigned)).hexdigest()
    ):
        raise TestDurationObservationError("test duration observation identity is invalid")
    durations = payload.get("durations_ms")
    if payload["status"] == "absent":
        if payload.get("source") is not None or durations != []:
            raise TestDurationObservationError("absent test duration observation carries data")
        return {}
    source = payload.get("source")
    source_keys = {
        "subject_commit", "subject_tree", "proof_bundle_sha256", "interpreter_sha256",
        "observed_node_count", "observed_node_inventory_sha256",
    }
    if (
        not isinstance(source, dict)
        or set(source) != source_keys
        or not _is_ancestor(repo_root, str(source.get("subject_commit", "")))
        or not isinstance(durations, list)
        or len(durations) != len(nodes)
        or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in durations)
    ):
        raise TestDurationObservationError("observed test duration source is invalid")
    observed_nodes = tuple(
        node for node, duration in zip(nodes, durations, strict=True) if duration > 0
    )
    if (
        not observed_nodes
        or source.get("observed_node_count") != len(observed_nodes)
        or source.get("observed_node_inventory_sha256")
        != hashlib.sha256(_canonical({"nodes": list(observed_nodes)})).hexdigest()
        or (payload["status"] == "observed" and len(observed_nodes) != len(nodes))
        or (payload["status"] == "observed_partial" and len(observed_nodes) >= len(nodes))
    ):
        raise TestDurationObservationError("observed test duration inventory is invalid")
    return {
        node: duration
        for node, duration in zip(nodes, durations, strict=True)
        if duration > 0
    }


def reconcile_test_duration_observations(repo_root: Path, *, apply: bool) -> None:
    """Project observations when locally available; otherwise validate tracked bytes."""

    path = repo_root / OBSERVATIONS_PATH
    compiled = compile_test_duration_observations(repo_root)
    expected = _canonical(compiled)
    if path.is_file():
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
            validate_test_duration_observations(repo_root, current)
        except (OSError, json.JSONDecodeError, TestDurationObservationError) as exc:
            if not apply:
                raise TestDurationObservationError("test duration observations require reconciliation") from exc
        else:
            if compiled["status"] == "absent":
                return
            if path.read_bytes() == expected:
                return
    elif compiled["status"] == "absent" and not apply:
        return
    if not apply:
        raise TestDurationObservationError("test duration observations require reconciliation")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(expected)


def load_test_duration_observations(repo_root: Path) -> dict[str, int]:
    path = repo_root / OBSERVATIONS_PATH
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TestDurationObservationError("test duration observations are unreadable") from exc
    return validate_test_duration_observations(repo_root, payload)
