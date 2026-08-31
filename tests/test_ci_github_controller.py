from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.ci_github_api import GitHubAPI, GitHubAPIError, GitHubContent
from bcf_governance.tooling.ci_github_controller import (
    GitHubControllerError,
    admission_ordinal,
    finalize,
    kickoff,
    publish,
)
from bcf_governance.tooling.ci_github_identity import resolve_main, resolve_trusted_run


SHA_A = "a" * 40
SHA_B = "b" * 40
TREE = "c" * 40
WORKFLOW = b"name: governed\n"
DIGEST = hashlib.sha256(WORKFLOW).hexdigest()
CONTROL_IDENTITY = {
    "control_workflow_id": 99,
    "control_workflow_path": ".github/workflows/control.yml",
    "control_workflow_sha256": DIGEST,
}
COLLECTOR_IDENTITY = {
    "collector_workflow_id": 98,
    "collector_workflow_path": ".github/workflows/finalizer.yml",
    "collector_workflow_sha256": DIGEST,
}


def _producer(producer_id: str, workflow_id: str, path: str, job: str) -> dict[str, object]:
    return {
        "producer_id": producer_id,
        "workflow": {
            "workflow_id": workflow_id,
            "active_path": path,
            "trusted_workflow_blob_oid": SHA_A,
            "trusted_workflow_sha256": DIGEST,
            "trusted_workflow_definition_commit": SHA_A,
            "allowed_events": ["push"],
        },
        "expected_jobs": [{"job_id": job}],
    }


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.chmod(0o600)
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _refresh_bundle_inventory(root: Path) -> None:
    path = root / "bundle-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for relative in manifest["files"]:
        manifest["files"][relative] = hashlib.sha256(
            (root / relative).read_bytes()
        ).hexdigest()
    _write_json(path, manifest)


class FakeAPI:
    def __init__(self) -> None:
        self.main = SHA_A
        self.dispatches: list[tuple[str, dict[str, object]]] = []
        self.published_statuses: list[dict[str, str]] = []
        self.existing_statuses: list[dict[str, str]] = []
        self.authority = {
            "schema_version": "1.0",
            "repository": {"provider": "github", "repository_id": "42"},
            "admission_workflow": {
                "workflow_id": "99",
                "active_path": ".github/workflows/control.yml",
                "trusted_workflow_blob_oid": SHA_A,
                "trusted_workflow_sha256": DIGEST,
                "trusted_workflow_definition_commit": SHA_A,
                "allowed_events": ["push"],
            },
            "producers": [
                _producer("governance", "10", ".github/workflows/governance.yml", "truth"),
                _producer("pack", "11", ".github/workflows/pack.yml", "pack"),
            ],
            "trusted_external_inputs": [],
        }
        self.runs = {
            "100": {
                "id": 100,
                "run_attempt": 1,
                "workflow_id": 99,
                "repository": {"id": 42},
                "event": "push",
                "head_sha": SHA_A,
                "status": "completed",
                "conclusion": "success",
            },
            "400": {
                "id": 400,
                "run_attempt": 1,
                "workflow_id": 98,
                "repository": {"id": 42},
                "event": "workflow_run",
                "head_sha": SHA_A,
                "status": "in_progress",
                "conclusion": None,
            },
            "200": self._producer_run(200, 10),
            "300": self._producer_run(300, 11),
        }
        self.job_names = {"200": "truth", "300": "pack"}
        self.missing_workflows: set[str] = set()

    @staticmethod
    def _producer_run(run_id: int, workflow_id: int) -> dict[str, object]:
        return {
            "id": run_id,
            "run_attempt": 1,
            "workflow_id": workflow_id,
            "repository": {"id": 42},
            "event": "push",
            "head_sha": SHA_A,
            "status": "completed",
            "conclusion": "success",
        }

    def repository(self, repository: str) -> dict[str, object]:
        assert repository == "owner/repo"
        return {"id": 42, "default_branch": "main"}

    def reference(self, repository: str, ref: str) -> dict[str, object]:
        assert repository == "owner/repo" and ref == "heads/main"
        return {"object": {"type": "commit", "sha": self.main}}

    def commit(self, repository: str, sha: str) -> dict[str, object]:
        assert repository == "owner/repo" and sha in {self.main, SHA_A}
        return {"sha": sha, "tree": {"sha": TREE}}

    def run(self, repository: str, run_id: str | int) -> dict[str, object]:
        assert repository == "owner/repo"
        return dict(self.runs[str(run_id)])

    def workflow(self, repository: str, workflow_id: str | int) -> dict[str, object]:
        assert repository == "owner/repo"
        paths = {
            "10": ".github/workflows/governance.yml",
            "11": ".github/workflows/pack.yml",
            "99": ".github/workflows/control.yml",
            "98": ".github/workflows/finalizer.yml",
        }
        return {
            "id": int(workflow_id),
            "path": paths[str(workflow_id)],
        }

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        assert repository == "owner/repo" and ref in {self.main, SHA_A}
        if path == "governance/ci-authority.yml":
            raw = yaml.safe_dump(self.authority, sort_keys=False).encode()
            return GitHubContent(path, SHA_B, raw)
        return GitHubContent(path, SHA_A, WORKFLOW)

    def workflow_runs(
        self,
        repository: str,
        workflow_id: str | int,
        *,
        head_sha: str,
        event: str,
    ) -> tuple[dict[str, object], ...]:
        assert repository == "owner/repo" and head_sha == self.main and event == "push"
        if str(workflow_id) in self.missing_workflows:
            return ()
        if str(workflow_id) == "control.yml":
            return tuple(
                dict(value)
                for value in self.runs.values()
                if value["workflow_id"] == 99
            )
        return (dict(self.runs["200" if str(workflow_id) == "10" else "300"]),)

    def jobs(
        self,
        repository: str,
        run_id: str | int,
        *,
        attempt: int,
    ) -> tuple[dict[str, object], ...]:
        assert repository == "owner/repo" and attempt == 1
        return (
            {
                "name": self.job_names[str(run_id)],
                "status": "completed",
                "conclusion": "success",
            },
        )

    def dispatch(self, repository: str, *, event_type: str, client_payload: dict[str, object]) -> None:
        assert repository == "owner/repo"
        self.dispatches.append((event_type, client_payload))

    def status(self, repository: str, **payload: str) -> None:
        assert repository == "owner/repo"
        self.published_statuses.append(payload)

    def commit_statuses(self, repository: str, *, sha: str) -> tuple[dict[str, str], ...]:
        assert repository == "owner/repo" and sha == SHA_A
        return tuple(self.existing_statuses)


def test_admission_ordinal_preserves_total_github_order() -> None:
    assert admission_ordinal(100, 2, 3) < admission_ordinal(101, 1, 1)
    assert admission_ordinal(100, 2, 3) < admission_ordinal(100, 2, 4)
    with pytest.raises(GitHubControllerError, match="below 1000"):
        admission_ordinal(100, 1, 1000)


def test_kickoff_authenticates_current_main_before_dispatch() -> None:
    api = FakeAPI()
    result = kickoff(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        expected_sha=SHA_A,
        control_run_id="100",
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        dispatch_exact_ref=True,
    )
    assert result.status == "admitted"
    assert result.tree_sha == TREE
    assert api.dispatches[0][1]["admission_ordinal"] == str(result.admission_ordinal)


@pytest.mark.parametrize("mutation", ["moved-main", "wrong-run", "wrong-attempt"])
def test_kickoff_identity_mutants_fail_before_dispatch(mutation: str) -> None:
    api = FakeAPI()
    if mutation == "moved-main":
        api.main = SHA_B
    elif mutation == "wrong-run":
        api.runs["100"]["repository"] = {"id": 99}
    else:
        api.runs["100"]["run_attempt"] = 2
    with pytest.raises(GitHubControllerError):
        kickoff(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            expected_sha=SHA_A,
            control_run_id=100,
            control_run_attempt=1,
            **CONTROL_IDENTITY,
            dispatch_exact_ref=True,
        )
    assert api.dispatches == []


def test_finalizer_reconstructs_terminal_bundle_and_publisher_reverifies(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    assert result.status == "terminal"
    assert result.computed_state == "certified"
    assert result.bundle_dir is not None
    assert (Path(result.bundle_dir) / "bundle-manifest.json").is_file()

    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"
    published = publish(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=Path(result.bundle_dir),
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
    )
    assert published["status"] == "published"
    assert api.published_statuses == [
        {
            "sha": SHA_A,
            "state": "success",
            "context": "bcf/exact-main-certification",
            "description": "BCF exact-main certified",
            "target_url": (
                "https://github.example/runs/400?"
                f"bcf_attempt=1&bcf_ordinal={result.admission_ordinal}"
            ),
        }
    ]


def test_finalizer_returns_pending_without_writing_partial_bundle(tmp_path: Path) -> None:
    api = FakeAPI()
    api.runs["300"]["status"] = "in_progress"
    api.runs["300"]["conclusion"] = None
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    assert result.status == "pending"
    assert not (tmp_path / "bundle").exists()


def test_first_callback_is_cleanly_pending_before_other_producer_starts(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    api.missing_workflows.add("11")
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    assert result.status == "pending"
    assert result.producer_runs == (("governance", "200", 1),)
    assert not (tmp_path / "bundle").exists()


def test_wrong_workflow_bytes_fail_before_bundle_creation(tmp_path: Path) -> None:
    api = FakeAPI()
    api.authority["producers"][0]["workflow"]["trusted_workflow_sha256"] = "d" * 64
    with pytest.raises(GitHubControllerError, match="trusted workflow bytes"):
        finalize(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            control_run_id=100,
            control_run_attempt=1,
            **CONTROL_IDENTITY,
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
            output_dir=tmp_path / "bundle",
        )
    assert not (tmp_path / "bundle").exists()


def test_finalizer_authenticates_its_own_run_before_bundle_creation(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    api.runs["400"]["workflow_id"] = 99

    with pytest.raises(GitHubControllerError, match="not authenticated"):
        finalize(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            control_run_id=100,
            control_run_attempt=1,
            **CONTROL_IDENTITY,
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
            output_dir=tmp_path / "bundle",
        )

    assert not (tmp_path / "bundle").exists()


def test_publisher_suppresses_bundle_after_default_main_moves(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"
    api.main = SHA_B
    published = publish(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=Path(result.bundle_dir or ""),
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
    )
    assert published["status"] == "suppressed"
    assert published["reason"] == "default_main_moved"
    assert api.published_statuses == []


def test_publisher_rejects_bundle_from_wrong_finalizer_attempt(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"
    api.runs["400"]["run_attempt"] = 2

    with pytest.raises(GitHubControllerError, match="current exact main"):
        publish(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            bundle_dir=Path(result.bundle_dir or ""),
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
        )

    assert api.published_statuses == []


def test_publisher_rejects_finalizer_session_identity_forgery(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    root = Path(result.bundle_dir or "")
    session_path = root / "evidence-session.json"
    session = json.loads(session_path.read_text(encoding="utf-8"))
    session["producer"]["producer_id"] = "candidate-forgery"
    _write_json(session_path, session)
    report_path = root / "ci-certification.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["evidence_session"]["manifest_sha256"] = hashlib.sha256(
        session_path.read_bytes()
    ).hexdigest()
    _write_json(report_path, report)
    _refresh_bundle_inventory(root)
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"

    with pytest.raises(GitHubControllerError, match="authenticated finalizer run"):
        publish(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            bundle_dir=root,
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
        )

    assert api.published_statuses == []


def test_publisher_rejects_bundle_manifest_semantic_forgery(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    root = Path(result.bundle_dir or "")
    manifest_path = root / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["computed_state"] = "failed"
    _write_json(manifest_path, manifest)
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"

    with pytest.raises(GitHubControllerError, match="verified certification"):
        publish(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            bundle_dir=root,
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
        )

    assert api.published_statuses == []


def test_older_callback_cannot_overwrite_newer_published_authority(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    api.existing_statuses = [
        {
            "context": "bcf/exact-main-certification",
            "state": "failure",
            "target_url": (
                "https://github.example/runs/500?"
                f"bcf_attempt=1&bcf_ordinal={result.admission_ordinal + 1}"
            ),
        }
    ]
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"
    published = publish(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=Path(result.bundle_dir or ""),
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
    )
    assert published["status"] == "suppressed"
    assert published["reason"] == "older_authority_cannot_overwrite"
    assert api.published_statuses == []


@pytest.mark.parametrize("mutation", ["manual-event", "wrong-workflow", "wrong-bytes"])
def test_control_plane_identity_mutants_are_unadmitted(mutation: str) -> None:
    api = FakeAPI()
    identity = dict(CONTROL_IDENTITY)
    if mutation == "manual-event":
        api.runs["100"]["event"] = "workflow_dispatch"
    elif mutation == "wrong-workflow":
        api.runs["100"]["workflow_id"] = 98
    else:
        identity["control_workflow_sha256"] = "d" * 64
    with pytest.raises(GitHubControllerError, match="not authenticated"):
        kickoff(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            expected_sha=SHA_A,
            control_run_id=100,
            control_run_attempt=1,
            **identity,
            dispatch_exact_ref=True,
        )
    assert api.dispatches == []


def test_control_run_resolution_ignores_unadmitted_manual_run() -> None:
    api = FakeAPI()
    api.runs["101"] = {
        **api.runs["100"],
        "id": 101,
        "event": "workflow_dispatch",
    }

    identity = resolve_trusted_run(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        main=resolve_main(api, "owner/repo"),  # type: ignore[arg-type]
        workflow_path=".github/workflows/control.yml",
        expected_event="push",
        require_success=True,
    )

    assert identity.run_id == "100"


def test_latest_admitted_control_failure_revokes_prior_success() -> None:
    api = FakeAPI()
    api.runs["101"] = {
        **api.runs["100"],
        "id": 101,
        "status": "completed",
        "conclusion": "failure",
    }

    with pytest.raises(GitHubControllerError, match="latest trusted run attempt"):
        resolve_trusted_run(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            main=resolve_main(api, "owner/repo"),  # type: ignore[arg-type]
            workflow_path=".github/workflows/control.yml",
            expected_event="push",
            require_success=True,
        )


def test_duplicate_status_authority_is_rejected(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_dir=tmp_path / "bundle",
    )
    api.existing_statuses = [
        {
            "context": "bcf/exact-main-certification",
            "state": "success",
            "target_url": (
                "https://github.example/runs/400?"
                f"bcf_attempt=1&bcf_ordinal={result.admission_ordinal}"
                f"&bcf_ordinal={result.admission_ordinal}"
            ),
        }
    ]
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"
    with pytest.raises(GitHubControllerError, match="duplicate admission"):
        publish(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            bundle_dir=Path(result.bundle_dir or ""),
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
        )


def test_api_rejects_unsafe_identity_before_network() -> None:
    api = GitHubAPI(token="test")
    with pytest.raises(GitHubAPIError, match="owner/name"):
        api.repository("../repo")
    with pytest.raises(GitHubAPIError, match="unsafe"):
        api.content("owner/repo", "../secret", ref=SHA_A)
    with pytest.raises(GitHubAPIError, match="workflow reference"):
        api.workflow("owner/repo", "../control.yml")


def test_api_rejects_truncated_workflow_run_inventory() -> None:
    class TruncatedAPI(GitHubAPI):
        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            return {"total_count": 2, "workflow_runs": [{"id": 1}]}

    api = TruncatedAPI(token="test")
    with pytest.raises(GitHubAPIError, match="exceeds one authenticated page"):
        api.workflow_runs("owner/repo", 10, head_sha=SHA_A, event="push")
