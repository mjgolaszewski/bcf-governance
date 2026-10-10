from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
import zipfile

from bcf_governance.tooling.evidence_scheduling import compile_test_splinter_plan
from bcf_governance.tooling.evidence_test_adapters import _capture_splinter_proofs
from bcf_governance.tooling.test_splinter_proofs import (
    repository_proof_members,
    select_applicable_proof,
    materialize_prior_provider_proofs,
    write_successful_proof,
)


def test_proof_members_are_exact_repository_relative_paths(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    proof_root = repo_root / ".artifacts/junit/test.splinter-proofs"
    assert repository_proof_members(repo_root, proof_root, "splinter-3") == {
        "manifest": ".artifacts/junit/test.splinter-proofs/splinter-3.proof.json",
        "junit": ".artifacts/junit/test.splinter-proofs/splinter-3.junit.xml",
    }
    try:
        repository_proof_members(repo_root, tmp_path / "outside", "splinter-3")
    except ValueError as exc:
        assert str(exc) == "test splinter proof root escapes the repository"
    else:
        raise AssertionError("outside proof root was accepted")


def _plan(session: str = "a" * 32) -> dict[str, object]:
    return compile_test_splinter_plan(
        {"tests.one::test_a": "tests/one.py::test_a"},
        {},
        max_splinters=1,
        identity={
            "subject_commit": "a" * 40,
            "subject_tree": "b" * 40,
            "session": session,
            "policy_sha256": "c" * 64,
            "producer": "test",
        },
    )


def _source(attempt: str = "1") -> dict[str, str]:
    return {
        "repository": "owner/repo",
        "repository_id": "123",
        "run_id": "456",
        "run_attempt": attempt,
        "job": "evidence",
        "shard": "3",
        "session": "a" * 32,
    }


def test_successful_splinter_proof_reuses_across_attempt_local_session(tmp_path: Path) -> None:
    plan = _plan()
    junit = tmp_path / "source.xml"
    junit.write_text(
        '<testsuite tests="1"><testcase classname="tests.one" name="test_a"/></testsuite>',
        encoding="utf-8",
    )
    write_successful_proof(
        tmp_path / "proofs",
        plan=plan,
        splinter=plan["splinters"][0],
        toolchain_sha256="d" * 64,
        junit=junit,
        observed_nodes=["tests.one::test_a"],
        execution_state={"retired": True, "removal_verified": True},
        worktree_removed=True,
        source=_source(),
    )
    current_plan = _plan("e" * 32)
    proof, restored, reason = select_applicable_proof(
        [tmp_path / "proofs"],
        plan=current_plan,
        splinter=current_plan["splinters"][0],
        toolchain_sha256="d" * 64,
        current=_source("2"),
    )
    assert proof is not None and restored is not None
    assert reason == "exact_prior_proof"


def test_splinter_proof_wrong_identity_or_bytes_recomputes(tmp_path: Path) -> None:
    plan = _plan()
    junit = tmp_path / "source.xml"
    junit.write_text(
        '<testsuite tests="1"><testcase classname="tests.one" name="test_a"/></testsuite>',
        encoding="utf-8",
    )
    manifest, copied = write_successful_proof(
        tmp_path / "proofs",
        plan=plan,
        splinter=plan["splinters"][0],
        toolchain_sha256="d" * 64,
        junit=junit,
        observed_nodes=["tests.one::test_a"],
        execution_state=None,
        worktree_removed=True,
        source=_source(),
    )
    copied.write_text("tampered", encoding="utf-8")
    proof, restored, reason = select_applicable_proof(
        [tmp_path / "proofs"],
        plan=plan,
        splinter=plan["splinters"][0],
        toolchain_sha256="d" * 64,
        current=_source("2"),
    )
    assert proof is None and restored is None and reason == "prior_proof_inapplicable"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["source"]["run_attempt"] == "1"


class _API:
    def __init__(self, artifact: dict[str, object], raw: bytes) -> None:
        self.artifact = artifact
        self.raw = raw

    def artifacts(self, repository: str, run_id: str) -> tuple[dict[str, object], ...]:
        assert repository == "owner/repo" and run_id == "456"
        return (self.artifact,)

    def artifact_bytes(self, repository: str, artifact_id: int, *, maximum_bytes: int) -> bytes:
        assert artifact_id == 99 and maximum_bytes == 104_857_600
        return self.raw

    def jobs(self, repository: str, run_id: str, *, attempt: int) -> tuple[dict[str, object], ...]:
        assert repository == "owner/repo" and run_id == "456" and attempt == 1
        return ({
            "id": 77,
            "name": "Evidence / Evidence shard 3",
            "status": "completed",
            "conclusion": "failure",
            "head_sha": "a" * 40,
        },)


def test_prior_provider_proof_materialization_authenticates_attempt_and_digest(
    tmp_path: Path,
) -> None:
    plan = _plan()
    junit = tmp_path / "source.xml"
    junit.write_text(
        '<testsuite tests="1"><testcase classname="tests.one" name="test_a"/></testsuite>',
        encoding="utf-8",
    )
    manifest, copied = write_successful_proof(
        tmp_path / "proofs",
        plan=plan,
        splinter=plan["splinters"][0],
        toolchain_sha256="d" * 64,
        junit=junit,
        observed_nodes=["tests.one::test_a"],
        execution_state=None,
        worktree_removed=True,
        source=_source(),
    )
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.write(manifest, "session/test/splinter-0.proof.json")
        archive.write(copied, "session/test/splinter-0.junit.xml")
    raw = buffer.getvalue()
    artifact = {
        "id": 99,
        "name": "bcf-evidence-456-1-shard-3",
        "expired": False,
        "digest": "sha256:" + __import__("hashlib").sha256(raw).hexdigest(),
        "workflow_run": {
            "id": 456,
            "repository_id": 123,
            "head_repository_id": 123,
            "head_sha": "a" * 40,
        },
    }
    report = materialize_prior_provider_proofs(
        _API(artifact, raw),
        tmp_path / "restored",
        repository="owner/repo",
        repository_id="123",
        head_sha="a" * 40,
        run_id="456",
        current_attempt=2,
        job="evidence",
        shard=3,
    )
    assert report["status"] == "materialized"
    assert (tmp_path / "restored/attempt-1/splinter-0.proof.json").is_file()


def test_successful_sibling_is_reused_while_failed_sibling_recomputes(tmp_path: Path) -> None:
    plan = compile_test_splinter_plan(
        {
            "tests.one::test_a": "tests/one.py::test_a",
            "tests.two::test_b": "tests/two.py::test_b",
        },
        {},
        max_splinters=2,
        identity={
            "subject_commit": "a" * 40,
            "subject_tree": "b" * 40,
            "session": "a" * 32,
            "policy_sha256": "c" * 64,
            "producer": "test",
        },
    )
    successful = plan["splinters"][0]
    junit = tmp_path / "source.xml"
    node = successful["nodes"][0]
    classname, name = node.split("::", 1)
    junit.write_text(
        f'<testsuite tests="1"><testcase classname="{classname}" name="{name}"/></testsuite>',
        encoding="utf-8",
    )
    write_successful_proof(
        tmp_path / "proofs",
        plan=plan,
        splinter=successful,
        toolchain_sha256="d" * 64,
        junit=junit,
        observed_nodes=[node],
        execution_state=None,
        worktree_removed=True,
        source=_source(),
    )
    current = {**plan, "identity": {**plan["identity"], "session": "e" * 32}}
    unsigned = {key: value for key, value in current.items() if key != "partition_sha256"}
    current["partition_sha256"] = __import__("hashlib").sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    first = select_applicable_proof(
        [tmp_path / "proofs"], plan=current, splinter=current["splinters"][0],
        toolchain_sha256="d" * 64, current=_source("2"),
    )
    second = select_applicable_proof(
        [tmp_path / "proofs"], plan=current, splinter=current["splinters"][1],
        toolchain_sha256="d" * 64, current=_source("2"),
    )
    assert first[2] == "exact_prior_proof"
    assert second == (None, None, "prior_proof_absent")


def test_aggregate_capture_requires_exact_proof_and_junit_bytes(tmp_path: Path) -> None:
    plan = _plan()
    proof_root = tmp_path / "test.splinter-proofs"
    junit = tmp_path / "source.xml"
    junit.write_text(
        '<testsuite tests="1"><testcase classname="tests.one" name="test_a"/></testsuite>',
        encoding="utf-8",
    )
    manifest, copied = write_successful_proof(
        proof_root,
        plan=plan,
        splinter=plan["splinters"][0],
        toolchain_sha256="d" * 64,
        junit=junit,
        observed_nodes=["tests.one::test_a"],
        execution_state=None,
        worktree_removed=True,
        source=_source(),
    )
    proof = json.loads(manifest.read_text(encoding="utf-8"))
    report = {
        **plan,
        "results": [{
            "id": "splinter-0", "returncode": 0, "proof_status": "fresh"
        }],
        "proofs": [{
            "id": "splinter-0",
            "status": "fresh",
            "proof_sha256": proof["proof_sha256"],
            "manifest": "test.splinter-proofs/splinter-0.proof.json",
            "junit": "test.splinter-proofs/splinter-0.junit.xml",
        }],
    }
    (tmp_path / "captured").mkdir()
    valid, artifacts = _capture_splinter_proofs(tmp_path, tmp_path / "captured", report)
    assert valid is True
    assert {value["path"] for value in artifacts} == {
        "splinter-0.proof.json", "splinter-0.junit.xml"
    }
    copied.write_text("tampered", encoding="utf-8")
    (tmp_path / "bad").mkdir()
    assert _capture_splinter_proofs(tmp_path, tmp_path / "bad", report)[0] is False
