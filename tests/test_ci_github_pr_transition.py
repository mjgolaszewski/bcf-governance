from __future__ import annotations

import copy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import zipfile

import pytest
import yaml

from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import GitHubControllerError, MainIdentity
from bcf_governance.tooling.ci_github_pr import finalize_pr
from bcf_governance.tooling.ci_pr_transition import (
    TransitionRejected,
    load_transition_bytes,
    transition_is_applicable,
    verify_transition_equivalence,
)
from bcf_governance.tooling.github_protection import load_protection


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mjgolaszewski/bcf-governance"
REPOSITORY_ID = "1207503211"
MAIN = "a" * 40
MAIN_TREE = "b" * 40
HEAD = "c" * 40
HEAD_TREE = "d" * 40
MERGE = "f" * 40
BLOB = "e" * 40
SESSION_ID = "1" * 32
WORKFLOW = b"name: trusted\n"
ORIGINAL_SUCCESSOR_GRAPH = "180667259dd349c4b49d6ae6114caec95d6da2a659e5b7923ae6d1999259fbe2"
ORIGINAL_SUCCESSOR_WORKFLOW = "b769e135061b7bc0ec06fb298923269c46191979855776c09cc574e6b864dca9"
FROZEN_SUCCESSOR = {
    "ci_graph": "f7ea355ebff41ecfd010ac7e9e213972ea6ec176418d1d4931640bf0bdea4483",
    "protection": "5f8c6fcd0d569e17050f694571474faa0f7538d12a5d11cc51891cf01c59a53a",
    "github_topology": "4a87476cb36055a8820182b2def7b41ffa7ba572defc63727aac7f7031ca3cb8",
    "governance_workflow": "0769cb712f23e9887de30b433d3c2fe814224bc6f319fd1d5eec9acd99d5b885",
}
JOBS = [
    "Validate governance front door",
    "Evidence / Boundaries, contracts, runtime, types, and secrets",
    "Evidence / CQRS, module size, exposure, and dependency risk",
    "Evidence / Duplication, routers, governance, and ownership",
    "Evidence / Full tests, lint, import boundaries, and SBOM",
    "Verify exact-tree governance evidence",
]
GATES = [
    "runtime-smoke",
    "security-dependency-audit",
    "security-sbom",
    "security-secret-scan",
    "security-vulnerability-scan",
    "test",
    "typecheck",
]


def _zip(files: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(files.items()):
            archive.writestr(name, raw)
    return output.getvalue()


def _json(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True).encode()


class TransitionAPI:
    def __init__(self) -> None:
        current_protection = (ROOT / "governance/github-protection.yml").read_bytes()
        successor_protection_value = yaml.safe_load(current_protection)
        successor_protection_value["pr_certification"]["producer_workflows"] = [
            successor_protection_value["pr_certification"]["producer_workflows"][0]
        ]
        successor_protection = yaml.safe_dump(successor_protection_value, sort_keys=False).encode()
        self.current_files = {
            "governance/ci-graph.yml": b"current graph",
            "governance/github-protection.yml": current_protection,
            ".github/workflows/governance-pack.yml": b"current package workflow",
            ".github/workflows/governance.yml": WORKFLOW,
            ".github/workflows/bcf-pr-finalizer.yml": WORKFLOW,
        }
        self.successor_files = {
            "governance/ci-graph.yml": b"successor graph",
            "governance/github-protection.yml": successor_protection,
            "governance/github-ci-topology.yml": b"successor provider topology",
            ".github/workflows/governance.yml": b"successor governance workflow",
        }
        self.contract = yaml.safe_load((ROOT / "governance/pr-transition.yml").read_text())
        for expected in self.contract["activation"]["current_topology"].values():
            expected["sha256"] = hashlib.sha256(self.current_files[expected["path"]]).hexdigest()
        for expected in self.contract["activation"]["successor_topology"].values():
            expected["sha256"] = hashlib.sha256(self.successor_files[expected["path"]]).hexdigest()
        self.head = HEAD
        self.branch = "release/2.0.0-final-activation"
        self.run_record = {
            "id": 30,
            "run_attempt": 1,
            "workflow_id": 201,
            "repository": {"id": int(REPOSITORY_ID)},
            "event": "pull_request",
            "head_sha": HEAD,
            "status": "completed",
            "conclusion": "success",
            "pull_requests": [{"number": 7}],
        }
        self.finalizer = {
            "id": 50,
            "run_attempt": 1,
            "workflow_id": 105,
            "repository": {"id": int(REPOSITORY_ID)},
            "event": "workflow_run",
            "head_sha": MAIN,
            "status": "in_progress",
            "conclusion": None,
            "pull_requests": [],
        }
        self.session = {
            "schema_version": "2.0",
            "session_id": SESSION_ID,
            "subject": {"commit_sha": MERGE, "tree_sha": HEAD_TREE},
            "profile": "standard",
            "profile_contract_version": "3.0",
            "producer": {
                "kind": "workflow",
                "producer_id": "preflight",
                "provider": "github-actions",
                "repository": REPOSITORY,
                "repository_id": REPOSITORY_ID,
                "run_attempt": "1",
                "run_id": "30",
            },
            "expected_gate_inventory": GATES,
            "expected_producer_inventory": ["evidence"],
            "preflight_satisfied_claims": [
                "governance-contracts-valid",
                "source-syntax-format",
            ],
        }
        self.truth = {
            "schema_version": "3.0",
            "subject": {
                "commit_sha": MERGE,
                "tracked_clean": True,
                "tree_sha": HEAD_TREE,
                "untracked_clean": True,
            },
            "evaluation_mode": "pr",
            "status": "pass",
            "merge_eligibility": "eligible",
            "durable_ref": f"github-actions://{REPOSITORY}/runs/30/attempts/1/bcf-governance-truth",
            "issues": [],
            "claims": {
                "security_review_complete": {
                    "effective_state": "verified",
                    "evidence_refs": [
                        {
                            "evidence_id": "preflight:governance-contracts-valid",
                            "result": "verified",
                            "source": "evidence-session-v2",
                        }
                    ],
                },
                "required_suites_green": {
                    "effective_state": "verified",
                    "evidence_refs": [
                        {
                            "evidence_id": "preflight:source-syntax-format",
                            "result": "verified",
                            "source": "evidence-session-v2",
                        }
                    ],
                },
            },
        }
        self.junit = (
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
            b'<testcase classname="tests.test_pack_sync" name="test_complete_pack_manifest_check"/>'
            b"</testsuite></testsuites>"
        )
        self.receipt: dict[str, object] = {}
        self.archives: dict[str, bytes] = {}
        self.artifact_records: tuple[dict[str, object], ...] = ()
        self.refresh_artifacts()

    def refresh_artifacts(self) -> None:
        session_raw = _json(self.session)
        self.receipt = {
            "schema_version": "3.0",
            "gate_id": "test",
            "result": "passed",
            "claims": ["test"],
            "producer": {"id": "mjgolaszewski", "kind": "workflow"},
            "subject": {
                "binding": "exact_tree",
                "commit_sha": MERGE,
                "execution_tree_sha": HEAD_TREE,
                "status_porcelain_sha256": hashlib.sha256(b"").hexdigest(),
                "tracked_clean": True,
                "tree_sha": HEAD_TREE,
                "untracked_clean": True,
            },
            "invocation": {
                "workflow": {
                    "job": "evidence",
                    "matrix": {"gate": "test"},
                    "path": f"{REPOSITORY}/.github/workflows/governance.yml@refs/pull/7/merge",
                    "provider": "github-actions",
                    "run_attempt": "1",
                    "run_id": "30",
                }
            },
            "artifacts": [
                {
                    "path": "evidence-session.json",
                    "media_type": "application/vnd.bcf.evidence-session+json",
                    "sha256": hashlib.sha256(session_raw).hexdigest(),
                },
                {
                    "path": "test.junit.xml",
                    "media_type": "application/junit+xml",
                    "sha256": hashlib.sha256(self.junit).hexdigest(),
                },
            ],
        }
        prefix = SESSION_ID
        self.archives = {
            "bcf-session-30-1": _zip({f"{prefix}/evidence-session.json": session_raw}),
            "bcf-governance-truth-30-1": _zip({"truth-report.json": _json(self.truth)}),
            "bcf-evidence-30-1-shard-0": _zip(
                {
                    f"{prefix}/evidence-session.json": session_raw,
                    f"{prefix}/test/test.evidence.json": _json(self.receipt),
                    f"{prefix}/test/test.junit.xml": self.junit,
                }
            ),
            **{
                f"bcf-evidence-30-1-shard-{index}": _zip(
                    {f"{prefix}/evidence-session.json": session_raw}
                )
                for index in range(1, 4)
            },
        }
        records = []
        for artifact_id, (name, raw) in enumerate(sorted(self.archives.items()), start=900):
            records.append(
                {
                    "id": artifact_id,
                    "name": name,
                    "expired": False,
                    "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "workflow_run": {
                        "id": 30,
                        "repository_id": int(REPOSITORY_ID),
                        "head_repository_id": int(REPOSITORY_ID),
                        "head_branch": self.branch,
                        "head_sha": HEAD,
                    },
                }
            )
        self.artifact_records = tuple(records)

    def repository(self, repository: str) -> dict[str, object]:
        return {"id": int(REPOSITORY_ID), "default_branch": "main"}

    def reference(self, repository: str, ref: str) -> dict[str, object]:
        return {"object": {"type": "commit", "sha": MAIN}}

    def commit(self, repository: str, sha: str) -> dict[str, object]:
        return {"tree": {"sha": MAIN_TREE if sha == MAIN else HEAD_TREE}}

    def run(self, repository: str, run_id: object) -> dict[str, object]:
        return copy.deepcopy(self.run_record if str(run_id) == "30" else self.finalizer)

    def workflow(self, repository: str, workflow_id: object) -> dict[str, object]:
        paths = {"105": ".github/workflows/bcf-pr-finalizer.yml", "201": ".github/workflows/governance.yml"}
        return {"id": int(str(workflow_id)), "path": paths[str(workflow_id)]}

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        if ref == MAIN and path == "governance/pr-transition.yml":
            raw = yaml.safe_dump(self.contract, sort_keys=False).encode()
        elif ref == MAIN:
            raw = self.current_files[path]
        else:
            raw = self.successor_files[path]
        return GitHubContent(path, BLOB, raw)

    def pull_request(self, repository: str, number: object) -> dict[str, object]:
        return {
            "number": 7,
            "state": "open",
            "head": {"sha": self.head, "ref": self.branch, "repo": {"id": int(REPOSITORY_ID)}},
            "base": {"ref": "main", "repo": {"id": int(REPOSITORY_ID)}},
        }

    def workflow_runs(self, repository: str, workflow_id: object, *, head_sha: str, event: str) -> tuple[dict[str, object], ...]:
        return () if str(workflow_id) == "governance-pack.yml" else (copy.deepcopy(self.run_record),)

    def jobs(self, repository: str, run_id: object, *, attempt: int) -> tuple[dict[str, object], ...]:
        return tuple({"name": name, "status": "completed", "conclusion": "success"} for name in JOBS)

    def artifacts(self, repository: str, run_id: object) -> tuple[dict[str, object], ...]:
        return copy.deepcopy(self.artifact_records)

    def artifact_bytes(self, repository: str, artifact_id: object, *, maximum_bytes: int) -> bytes:
        record = next(item for item in self.artifact_records if str(item["id"]) == str(artifact_id))
        return self.archives[str(record["name"])]


def _main() -> MainIdentity:
    return MainIdentity(REPOSITORY_ID, "main", MAIN, MAIN_TREE)


def _governance_state() -> dict[str, object]:
    return {"id": "governance", "state": "successful", "run_id": "30", "run_attempt": 1}


def _applicable(api: TransitionAPI) -> dict[str, object]:
    result = transition_is_applicable(
        api,
        repository=REPOSITORY,
        main=_main(),
        protection=load_protection(ROOT),
        head_sha=HEAD,
        head_branch=api.branch,
        package_state={"id": "package", "state": "pending", "reason": "not_started"},
        schema_root=ROOT,
    )
    assert result is not None
    return result[0]


def _verify(api: TransitionAPI, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "repository": REPOSITORY,
        "main": _main(),
        "contract": _applicable(api),
        "pr_number": 7,
        "head_sha": HEAD,
        "head_tree": HEAD_TREE,
        "head_branch": api.branch,
        "governance_state": _governance_state(),
    }
    values.update(overrides)
    return verify_transition_equivalence(api, **values)  # type: ignore[arg-type]


def test_successor_equivalence_is_trusted_reconstructed_and_exact() -> None:
    result = _verify(TransitionAPI())
    assert result["state"] == "successful"
    assert result["reason"] == "authenticated_bcf2_transition_equivalence"
    assert result["transition"]["subject"] == {"commit_sha": HEAD, "tree_sha": HEAD_TREE, "branch": "release/2.0.0-final-activation"}


def test_ordinary_missing_package_and_carrier_self_use_remain_pending(tmp_path: Path) -> None:
    for branch in (
        "ordinary/change",
        "release/2.0.0-activation",
        "release/2.0.0-transition-carrier",
        "transition/2.0-successor-snapshot-refresh",
        "transition/2.0-successor-branch-refresh",
    ):
        api = TransitionAPI()
        api.branch = branch
        result = finalize_pr(
            api, repository=REPOSITORY,
            event={"workflow_run": {"id": 30, "run_attempt": 1}},
            finalizer_run_id=50, finalizer_run_attempt=1,
            output_root=tmp_path / branch.replace("/", "-"),
        )
        assert result["computed_state"] == "pending"
        assert result["producers"][1] == {"id": "package", "state": "pending", "reason": "not_started"}


@pytest.mark.parametrize(
    "branch",
    [
        "release/2.0.0-activation",
        "release/2.0.0-",
        "release/2.0.0-final",
        "release/2.0.0-final-activation-extra",
        "Release/2.0.0-final-activation",
        "release/2.0.0-FINAL-activation",
        "arbitrary/change",
    ],
)
def test_only_exact_final_successor_branch_is_authorized(branch: str) -> None:
    api = TransitionAPI()
    api.branch = branch
    assert transition_is_applicable(
        api,
        repository=REPOSITORY,
        main=_main(),
        protection=load_protection(ROOT),
        head_sha=HEAD,
        head_branch=branch,
        package_state={"id": "package", "state": "pending", "reason": "not_started"},
        schema_root=ROOT,
    ) is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("head_sha", "9" * 40, "replayed"),
        ("head_tree", "8" * 40, "tree-equivalent"),
        ("pr_number", 8, "replayed"),
    ],
)
def test_wrong_candidate_commit_tree_or_pr_is_rejected(field: str, value: object, message: str) -> None:
    with pytest.raises(TransitionRejected, match=message):
        _verify(TransitionAPI(), **{field: value})


def test_wrong_current_or_successor_topology_and_retired_producer_are_rejected() -> None:
    api = TransitionAPI()
    api.successor_files["governance/ci-graph.yml"] = b"wrong successor"
    assert transition_is_applicable(
        api, repository=REPOSITORY, main=_main(), protection=load_protection(ROOT),
        head_sha=HEAD, head_branch=api.branch,
        package_state={"id": "package", "state": "pending", "reason": "not_started"}, schema_root=ROOT,
    ) is None
    api = TransitionAPI()
    api.contract["activation"]["retired_producer"]["id"] = "other"
    with pytest.raises(GitHubControllerError, match="producer topology"):
        _applicable(api)


@pytest.mark.parametrize(
    "path",
    [
        "governance/ci-graph.yml",
        "governance/github-protection.yml",
        "governance/github-ci-topology.yml",
        ".github/workflows/governance.yml",
    ],
)
def test_each_wrong_successor_topology_anchor_is_rejected(path: str) -> None:
    api = TransitionAPI()
    api.successor_files[path] += b"\nwrong successor topology\n"
    assert transition_is_applicable(
        api,
        repository=REPOSITORY,
        main=_main(),
        protection=load_protection(ROOT),
        head_sha=HEAD,
        head_branch=api.branch,
        package_state={"id": "package", "state": "pending", "reason": "not_started"},
        schema_root=ROOT,
    ) is None


@pytest.mark.parametrize(
    "path",
    [
        "governance/ci-graph.yml",
        "governance/github-protection.yml",
        ".github/workflows/governance-pack.yml",
    ],
)
def test_each_wrong_current_topology_anchor_is_rejected(path: str) -> None:
    api = TransitionAPI()
    api.current_files[path] += b"\nwrong current topology\n"
    with pytest.raises(GitHubControllerError, match="current PR topology"):
        _applicable(api)


def test_post_rotation_current_anchors_are_exact_and_stale_snapshot_is_rejected() -> None:
    contract = yaml.safe_load((ROOT / "governance/pr-transition.yml").read_text())
    current = contract["activation"]["current_topology"]
    for expected in current.values():
        assert hashlib.sha256((ROOT / expected["path"]).read_bytes()).hexdigest() == expected["sha256"]

    api = TransitionAPI()
    api.contract["activation"]["current_topology"]["ci_graph"]["sha256"] = (
        "5789ea9ba07452457ab5f2531fde563bfb73a5813f676fd8b6d77c88ff1423ef"
    )
    with pytest.raises(GitHubControllerError, match="current PR topology"):
        _applicable(api)


def test_missing_current_topology_anchor_is_rejected() -> None:
    value = yaml.safe_load((ROOT / "governance/pr-transition.yml").read_text())
    value["activation"]["current_topology"].pop("package_workflow")
    with pytest.raises(GitHubControllerError, match="schema violation"):
        load_transition_bytes(
            yaml.safe_dump(value).encode(), schema_path=ROOT / "schemas/pr-transition.schema.json"
        )


def test_missing_successor_topology_anchor_is_rejected() -> None:
    value = yaml.safe_load((ROOT / "governance/pr-transition.yml").read_text())
    value["activation"]["successor_topology"].pop("governance_workflow")
    with pytest.raises(GitHubControllerError, match="schema violation"):
        load_transition_bytes(
            yaml.safe_dump(value).encode(), schema_path=ROOT / "schemas/pr-transition.schema.json"
        )


def test_authoritative_successor_snapshot_is_exact_and_candidate_cannot_replace_it() -> None:
    contract = yaml.safe_load((ROOT / "governance/pr-transition.yml").read_text())
    successor = contract["activation"]["successor_topology"]
    assert {key: value["sha256"] for key, value in successor.items()} == FROZEN_SUCCESSOR
    assert successor["ci_graph"]["sha256"] != ORIGINAL_SUCCESSOR_GRAPH
    assert successor["governance_workflow"]["sha256"] != ORIGINAL_SUCCESSOR_WORKFLOW

    api = TransitionAPI()
    api.successor_files["governance/pr-transition.yml"] = yaml.safe_dump(
        {"candidate": "self-asserted authority"}
    ).encode()
    assert _verify(api)["state"] == "successful"
    api.contract["activation"]["successor_topology"]["ci_graph"]["sha256"] = (
        ORIGINAL_SUCCESSOR_GRAPH
    )
    assert transition_is_applicable(
        api,
        repository=REPOSITORY,
        main=_main(),
        protection=load_protection(ROOT),
        head_sha=HEAD,
        head_branch=api.branch,
        package_state={"id": "package", "state": "pending", "reason": "not_started"},
        schema_root=ROOT,
    ) is None


def test_repaired_controller_and_race_safe_admission_remain_authoritative() -> None:
    policy = yaml.safe_load((ROOT / "governance/self-governance-policy.yml").read_text())
    runner = policy["runner_security"]
    assert runner["trusted_controller_artifact"]["BCF_BOOTSTRAP_COMMIT_SHA"] == (
        "78f12c6d4acc6e389c6deef41c4933f3a46ceb36"
    )
    assert runner["trusted_controller_installation"]["installed_commit_sha"] == (
        "78f12c6d4acc6e389c6deef41c4933f3a46ceb36"
    )
    exact_main = (ROOT / "bcf_governance/tooling/ci_github_exact_main.py").read_text()
    membership = (ROOT / "bcf_governance/tooling/ci_github_membership.py").read_text()
    assert "trigger_run_id" in exact_main
    assert "trigger_run_attempt" in exact_main
    assert "trigger_run_id" in membership


def test_incomplete_mapping_and_failed_mapped_claim_are_rejected() -> None:
    value = yaml.safe_load((ROOT / "governance/pr-transition.yml").read_text())
    value["assurance_mapping"].pop()
    with pytest.raises(GitHubControllerError, match="schema violation|mapping"):
        load_transition_bytes(
            yaml.safe_dump(value).encode(), schema_path=ROOT / "schemas/pr-transition.schema.json"
        )
    api = TransitionAPI()
    api.session["preflight_satisfied_claims"] = ["governance-contracts-valid"]
    api.refresh_artifacts()
    with pytest.raises(TransitionRejected, match="claim mapping"):
        _verify(api)


def test_candidate_assertion_replay_legacy_and_provider_mismatch_are_rejected() -> None:
    api = TransitionAPI()
    api.artifact_records = tuple(item for item in api.artifact_records if "evidence-30" not in str(item["name"]))
    with pytest.raises(TransitionRejected, match="artifact inventory"):
        _verify(api)
    api = TransitionAPI()
    api.session["schema_version"] = "1.0"
    api.refresh_artifacts()
    with pytest.raises(TransitionRejected, match="legacy"):
        _verify(api)
    api = TransitionAPI()
    api.receipt["invocation"]["workflow"]["path"] = f"{REPOSITORY}/.github/workflows/governance.yml@refs/pull/8/merge"  # type: ignore[index]
    prefix = SESSION_ID
    session_raw = _json(api.session)
    api.archives["bcf-evidence-30-1-shard-0"] = _zip({
        f"{prefix}/evidence-session.json": session_raw,
        f"{prefix}/test/test.evidence.json": _json(api.receipt),
        f"{prefix}/test/test.junit.xml": api.junit,
    })
    records = list(api.artifact_records)
    for record in records:
        if record["name"] == "bcf-evidence-30-1-shard-0":
            record["digest"] = "sha256:" + hashlib.sha256(api.archives[str(record["name"])]).hexdigest()
    api.artifact_records = tuple(records)
    with pytest.raises(TransitionRejected, match="receipt identity"):
        _verify(api)
    api = TransitionAPI()
    api.artifact_records[0]["workflow_run"]["repository_id"] = 1  # type: ignore[index]
    with pytest.raises(TransitionRejected, match="provider subject"):
        _verify(api)


def test_failed_pack_node_and_job_block_transition() -> None:
    api = TransitionAPI()
    api.junit = api.junit.replace(b"test_complete_pack_manifest_check", b"other_test")
    api.refresh_artifacts()
    with pytest.raises(TransitionRejected, match="pack-manifest"):
        _verify(api)
    api = TransitionAPI()
    api.jobs = lambda *_args, **_kwargs: tuple(  # type: ignore[method-assign]
        {"name": name, "status": "completed", "conclusion": "failure" if name == JOBS[-1] else "success"}
        for name in JOBS
    )
    with pytest.raises(TransitionRejected, match="job inventory"):
        _verify(api)


def test_old_topology_and_canonical_publisher_context_are_unchanged() -> None:
    protection = load_protection(ROOT)
    assert [item["id"] for item in protection["pr_certification"]["producer_workflows"]] == ["governance", "package"]
    assert protection["pr_certification"]["context"] == "bcf/pr-certification"
    assert (ROOT / ".github/workflows/governance-pack.yml").is_file()
    publisher = (ROOT / "bcf_governance/tooling/ci_github_pr.py").read_text()
    assert "require_success=True" in publisher
