from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling.test_duration_observations import (
    TestDurationObservationError as DurationObservationError,
    compile_test_duration_observations,
    load_test_duration_observations,
    reconcile_test_duration_observations,
)


NODES = ("tests.test_demo::test_a", "tests.test_demo::test_b")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "governance/test-manifests").mkdir(parents=True)
    (root / "governance/test-manifests/test.txt").write_text("\n".join(NODES) + "\n")
    (root / "governance/gate-contracts.yml").write_text("schema_version: '1.0'\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
    return root


def _bundle(root: Path, *, suffix: str, times: tuple[float, float]) -> None:
    common = Path(_git(root, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    bundle = common / "bcf/proof-bundles" / suffix
    evidence = bundle / "evidence/test"
    evidence.mkdir(parents=True)
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    policy = hashlib.sha256((root / "governance/gate-contracts.yml").read_bytes()).hexdigest()
    (bundle / "proof-bundle.json").write_text(json.dumps({"bundle_sha256": suffix}))
    (evidence / "test.partition.json").write_text(
        json.dumps(
            {
                "identity": {
                    "subject_commit": commit,
                    "subject_tree": tree,
                    "producer": "test",
                    "policy_sha256": policy,
                },
                "node_inventory": list(NODES),
            }
        )
    )
    (evidence / "test.evidence.json").write_text(
        json.dumps(
            {
                "observations": {
                    "execution_environment": {
                        "selected_interpreter": {"binary_sha256": "f" * 64}
                    }
                }
            }
        )
    )
    (evidence / "test.junit.xml").write_text(
        "<testsuite>"
        f'<testcase classname="tests.test_demo" name="test_a" time="{times[0]}" />'
        f'<testcase classname="tests.test_demo" name="test_b" time="{times[1]}" />'
        "</testsuite>"
    )


def test_reconcile_projects_compact_median_from_exact_ancestor_proofs(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    _bundle(root, suffix="a" * 64, times=(0.010, 0.040))
    _bundle(root, suffix="b" * 64, times=(0.030, 0.020))

    compiled = compile_test_duration_observations(root)

    assert compiled["status"] == "observed"
    assert compiled["durations_ms"] == [10, 20]
    reconcile_test_duration_observations(root, apply=True)
    assert load_test_duration_observations(root) == {NODES[0]: 10, NODES[1]: 20}
    reconcile_test_duration_observations(root, apply=False)


def test_missing_history_is_typed_absence_and_uses_lexical_fallback(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    payload = compile_test_duration_observations(root)
    assert payload["status"] == "absent"
    reconcile_test_duration_observations(root, apply=True)
    assert load_test_duration_observations(root) == {}


def test_exact_ancestor_subset_is_retained_for_unchanged_nodes(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    _bundle(root, suffix="d" * 64, times=(0.010, 0.020))
    manifest = root / "governance/test-manifests/test.txt"
    manifest.write_text(manifest.read_text() + "tests.test_demo::test_new\n")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "add node"], check=True)

    compiled = compile_test_duration_observations(root)

    assert compiled["status"] == "observed_partial"
    assert compiled["durations_ms"] == [10, 20, 0]
    reconcile_test_duration_observations(root, apply=True)
    assert load_test_duration_observations(root) == {NODES[0]: 10, NODES[1]: 20}
    reconcile_test_duration_observations(root, apply=False)


def test_duration_observation_tampering_fails_closed(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    _bundle(root, suffix="c" * 64, times=(0.010, 0.020))
    reconcile_test_duration_observations(root, apply=True)
    path = root / "governance/test-duration-observations.json"
    payload = json.loads(path.read_text())
    payload["durations_ms"][0] += 1
    path.write_text(json.dumps(payload))

    with pytest.raises(DurationObservationError, match="identity is invalid"):
        load_test_duration_observations(root)
