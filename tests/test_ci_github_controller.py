from __future__ import annotations

import hashlib
from io import BytesIO
import json
from pathlib import Path
import zipfile

import pytest
import yaml

from bcf_governance.tooling import ci_github_callbacks as callbacks
from bcf_governance.tooling.ci_github_api import GitHubAPI, GitHubAPIError, GitHubContent
from bcf_governance.tooling.ci_github_callbacks import (
    finalize_callback,
    publish_callback,
)
from bcf_governance.tooling.ci_github_controller import (
    GitHubControllerError,
    admission_ordinal,
    finalize,
    kickoff,
    publish,
)
from bcf_governance.tooling.ci_github_identity import resolve_main, resolve_trusted_run
from bcf_governance.tooling.ci_github_membership import (
    AdmissionTopologyState,
    certification_producer_ids,
    classify_admission_topology,
    collect_same_run_producers,
    select_latest_admission,
)
from bcf_governance.tooling.ci_github_exact_main import (
    admit_exact_main,
    finalize_exact_main,
    publish_exact_main,
)
from bcf_governance.tooling.ci_graph_controller_lifecycle import (
    ControllerLifecycleState,
    resolve_controller_lifecycle,
)
from bcf_governance.tooling.evaluation_scope import is_terminal_phase_certification


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
        self.tree = TREE
        self.dispatches: list[tuple[str, dict[str, object]]] = []
        self.run_calls: list[str] = []
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
                "head_repository": {"id": 42},
                "head_branch": "main",
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
                "head_repository": {"id": 42},
                "head_branch": "main",
                "event": "workflow_run",
                "head_sha": SHA_A,
                "status": "in_progress",
                "conclusion": None,
            },
            "200": self._producer_run(200, 10),
            "300": self._producer_run(300, 11),
        }
        self.job_names = {"200": "truth", "300": "pack"}
        self.run_job_names: dict[str, tuple[str, ...]] = {}
        self.run_job_statuses: dict[str, str] = {}
        self.run_job_conclusions: dict[str, dict[str, object]] = {}
        self.missing_workflows: set[str] = set()
        self.workflow_versions: dict[str, tuple[str, bytes]] = {}
        self.workflow_path_versions: dict[tuple[str, str], tuple[str, bytes]] = {}
        self.workflow_paths = {
            "10": ".github/workflows/governance.yml",
            "11": ".github/workflows/pack.yml",
            "99": ".github/workflows/control.yml",
            "98": ".github/workflows/finalizer.yml",
            "97": ".github/workflows/status.yml",
        }
        self.truth_artifact_override: dict[str, object] | None = None

    @staticmethod
    def _producer_run(run_id: int, workflow_id: int) -> dict[str, object]:
        return {
            "id": run_id,
            "run_attempt": 1,
            "workflow_id": workflow_id,
            "repository": {"id": 42},
            "head_repository": {"id": 42},
            "head_branch": "main",
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
        return {"sha": sha, "tree": {"sha": self.tree}}

    def run(self, repository: str, run_id: str | int) -> dict[str, object]:
        assert repository == "owner/repo"
        self.run_calls.append(str(run_id))
        return dict(self.runs[str(run_id)])

    def workflow(self, repository: str, workflow_id: str | int) -> dict[str, object]:
        assert repository == "owner/repo"
        return {
            "id": int(workflow_id),
            "path": self.workflow_paths[str(workflow_id)],
        }

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        assert repository == "owner/repo" and ref in {self.main, SHA_A, SHA_B}
        if path == "governance/ci-authority.yml":
            raw = yaml.safe_dump(self.authority, sort_keys=False).encode()
            return GitHubContent(path, SHA_B, raw)
        blob_oid, content = self.workflow_path_versions.get(
            (ref, path), self.workflow_versions.get(ref, (SHA_A, WORKFLOW))
        )
        return GitHubContent(path, blob_oid, content)

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
        if str(workflow_id) in {"control.yml", "99"}:
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
        assert repository == "owner/repo"
        assert attempt == int(self.runs[str(run_id)]["run_attempt"])
        names = self.run_job_names.get(str(run_id))
        if names is None:
            names = (self.job_names[str(run_id)],)
        return tuple(
            {
                "name": name,
                "status": self.run_job_statuses.get(str(run_id), "completed"),
                "conclusion": (
                    self.run_job_conclusions.get(str(run_id), {}).get(
                        name, self.runs[str(run_id)].get("conclusion")
                    )
                    if self.run_job_statuses.get(str(run_id), "completed") == "completed"
                    else None
                ),
            }
            for name in names
        )

    def dispatch(self, repository: str, *, event_type: str, client_payload: dict[str, object]) -> None:
        assert repository == "owner/repo"
        self.dispatches.append((event_type, client_payload))

    def status(self, repository: str, **payload: str) -> None:
        assert repository == "owner/repo"
        self.published_statuses.append(payload)

    def commit_statuses(self, repository: str, *, sha: str) -> tuple[dict[str, str], ...]:
        assert repository == "owner/repo" and sha in {SHA_A, SHA_B}
        return tuple(self.existing_statuses)

    def _truth_archive(self) -> bytes:
        conclusion = str(self.runs["100"].get("conclusion"))
        report: dict[str, object] = self.truth_artifact_override or {
            "status": "pass" if conclusion == "success" else "fail",
            "subject": {
                "commit_sha": str(self.runs["100"]["head_sha"]),
                "tree_sha": self.tree,
            },
            "evaluation_scope": {
                "intent": "closure",
                "target": {"kind": "phase", "id": "P01"},
            },
            "certified_proposition": {
                "predicate": "phase_closed",
                "target": {"kind": "phase", "id": "P01"},
                "subject": {
                    "commit_sha": str(self.runs["100"]["head_sha"]),
                    "tree_sha": self.tree,
                },
                "conclusion": "success" if conclusion == "success" else "failure",
                "authorizes": [],
                "eligible_successors": [],
            },
            "durable_ref": (
                "github-actions://owner/repo/runs/100/attempts/1/"
                "bcf-governance-truth"
            ),
        }
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            info = zipfile.ZipInfo("truth-report.json", (2026, 1, 1, 0, 0, 0))
            archive.writestr(info, json.dumps(report, sort_keys=True) + "\n")
        return stream.getvalue()

    def artifacts(self, repository: str, run_id: str | int) -> tuple[dict[str, object], ...]:
        assert repository == "owner/repo" and str(run_id) == "100"
        raw = self._truth_archive()
        return ({
            "id": 700,
            "name": "bcf-governance-truth-100-1",
            "expired": False,
            "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "workflow_run": {
                "id": 100,
                "repository_id": 42,
                "head_repository_id": 42,
                "head_branch": "main",
                "head_sha": str(self.runs["100"]["head_sha"]),
            },
        },)

    def artifact_bytes(
        self, repository: str, artifact_id: str | int, *, maximum_bytes: int
    ) -> bytes:
        assert repository == "owner/repo" and str(artifact_id) == "700"
        raw = self._truth_archive()
        assert len(raw) <= maximum_bytes
        return raw


def test_admission_ordinal_preserves_total_github_order() -> None:
    assert admission_ordinal(100, 2, 3) < admission_ordinal(101, 1, 1)
    assert admission_ordinal(100, 2, 3) < admission_ordinal(100, 2, 4)
    with pytest.raises(GitHubControllerError, match="below 1000"):
        admission_ordinal(100, 1, 1000)


def _v11_authority() -> dict[str, object]:
    admission = {
        "workflow_id": "99",
        "active_path": ".github/workflows/control.yml",
        "trusted_workflow_blob_oid": SHA_A,
        "trusted_workflow_sha256": DIGEST,
        "trusted_workflow_definition_commit": SHA_A,
        "allowed_events": ["push"],
        "job_roles": {
            "admit": "admission",
            "governance": "producer",
            "pack": "producer",
        },
    }
    governance = {
        **admission,
        "workflow_id": "10",
        "active_path": ".github/workflows/governance.yml",
        "allowed_events": ["workflow_call"],
    }
    governance.pop("job_roles")
    pack = {
        **admission,
        "workflow_id": "11",
        "active_path": ".github/workflows/pack.yml",
        "allowed_events": ["workflow_call"],
    }
    pack.pop("job_roles")
    registry: dict[str, object] = {
        "admission": admission,
        "governance": governance,
        "pack": pack,
    }
    registry["finalizer"] = {
        **admission,
        "workflow_id": "98",
        "active_path": ".github/workflows/finalizer.yml",
        "allowed_events": ["workflow_run"],
        "expected_jobs": [{"job_id": "Finalize"}],
    }
    registry["finalizer"].pop("job_roles")
    registry["status"] = {
        **admission,
        "workflow_id": "97",
        "active_path": ".github/workflows/status.yml",
        "allowed_events": ["workflow_run"],
        "expected_jobs": [{"job_id": "Publish"}],
    }
    registry["status"].pop("job_roles")
    role_names = (
        "bootstrap", "probe", "release-authorizer", "release-build",
        "release-verifier", "release-collector", "release-publisher", "canary",
    )
    for index, name in enumerate(role_names, start=500):
        registry[name] = {
            **admission,
            "workflow_id": str(index),
            "active_path": f".github/workflows/{name}.yml",
            "allowed_events": ["workflow_dispatch"],
            "expected_jobs": [{"job_id": f"{name}-job"}],
        }
        registry[name].pop("job_roles")
    registry["canary"]["job_roles"] = {
        "admit": "admission",
        "producer-a": "producer",
        "producer-b": "producer",
        "observe": "observer",
    }
    registry["canary"]["expected_jobs"] = [
        {"job_id": "canary-admit", "role": "admission"},
        {"job_id": "canary-a", "role": "producer"},
        {"job_id": "canary-b", "role": "producer"},
        {"job_id": "canary-observe", "role": "observer"},
    ]
    return {
        "schema_version": "1.1",
        "repository": {"provider": "github", "repository_id": "42"},
        "workflow_registry": registry,
        "roles": {
            "admission": "admission",
            "reusable_producers": ["governance", "pack"],
            "finalizer": "finalizer",
            "status_publisher": "status",
            "bootstrap": "bootstrap",
            "probe": "probe",
            "release_authorizer": "release-authorizer",
            "release_build": "release-build",
            "release_verifier": "release-verifier",
            "release_collector": "release-collector",
            "release_publisher": "release-publisher",
            "authority_canary": "canary",
        },
        "admission_jobs": [{"job_id": "Admit exact main"}],
        "producers": [
            {
                "producer_id": "governance",
                "workflow_ref": "governance",
                "expected_jobs": [{"job_id": "Governance truth"}],
            },
            {
                "producer_id": "pack",
                "workflow_ref": "pack",
                "expected_jobs": [{"job_id": "Package proof"}],
            },
        ],
        "trusted_external_inputs": [],
    }


def _prepare_v11_run(api: FakeAPI) -> dict[str, object]:
    authority = _v11_authority()
    api.authority = authority
    api.runs["100"]["referenced_workflows"] = [
        {"path": ".github/workflows/governance.yml", "sha": SHA_A},
        {"path": ".github/workflows/pack.yml", "sha": SHA_A},
    ]
    api.run_job_names["100"] = (
        "Admit exact main", "Governance truth", "Package proof",
    )
    return authority


def test_v11_collects_all_producers_from_one_exact_admission_attempt() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]
    run_id, attempt = select_latest_admission(
        api, repository="owner/repo", main=main, authority=authority  # type: ignore[arg-type]
    )
    observed = collect_same_run_producers(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        main=main,
        authority=authority,
        admission_run_id=run_id,
        admission_run_attempt=attempt,
    )
    assert {(value["run_id"], value["attempts"][0]["run_attempt"]) for value in observed} == {
        ("100", 1)
    }
    assert {value["same_run_membership"]["producer_id"] for value in observed} == {
        "governance", "pack"
    }


def test_v11_bounded_admission_publishes_only_bounded_pending_context() -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    admit_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        expected_sha=SHA_A,
        run_id="100",
        run_attempt="1",
        target_url="https://github.example/runs/100",
        evaluation_mode="workitem",
        evaluation_target="P26-P0-01",
    )
    assert api.published_statuses[-1]["context"] == "bcf/workitem-certification"
    assert "P26-P0-01" in api.published_statuses[-1]["description"]


def test_v11_direct_trigger_survives_temporary_list_absence() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    api.missing_workflows.add("99")
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]

    assert select_latest_admission(
        api,
        repository="owner/repo",
        main=main,
        authority=authority,
        trigger_run_id=100,
        trigger_run_attempt=1,
    ) == ("100", 1)


def test_v11_direct_trigger_is_deduplicated_when_listed() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]

    assert select_latest_admission(
        api,
        repository="owner/repo",
        main=main,
        authority=authority,
        trigger_run_id=100,
        trigger_run_attempt=1,
    ) == ("100", 1)
    assert api.run_calls.count("100") == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "workflow-id",
        "workflow-path",
        "workflow-blob",
        "workflow-digest",
        "workflow-definition",
        "repository",
        "head-repository",
        "event",
        "branch",
        "commit",
        "run-id",
        "attempt",
    ],
)
def test_v11_direct_trigger_locator_cannot_confer_authority(mutation: str) -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    expected_attempt = 1
    if mutation == "workflow-id":
        api.runs["100"]["workflow_id"] = 98
    elif mutation == "workflow-path":
        api.workflow_paths["99"] = ".github/workflows/other.yml"
    elif mutation == "workflow-blob":
        authority["workflow_registry"]["admission"]["trusted_workflow_blob_oid"] = SHA_B  # type: ignore[index]
    elif mutation == "workflow-digest":
        authority["workflow_registry"]["admission"]["trusted_workflow_sha256"] = "0" * 64  # type: ignore[index]
    elif mutation == "workflow-definition":
        authority["workflow_registry"]["admission"]["trusted_workflow_definition_commit"] = SHA_B  # type: ignore[index]
        api.workflow_versions[SHA_B] = (SHA_B, b"changed workflow\n")
    elif mutation == "repository":
        api.runs["100"]["repository"] = {"id": 41}
    elif mutation == "head-repository":
        api.runs["100"]["head_repository"] = {"id": 41}
    elif mutation == "event":
        api.runs["100"]["event"] = "workflow_run"
    elif mutation == "branch":
        api.runs["100"]["head_branch"] = "other"
    elif mutation == "commit":
        api.runs["100"]["head_sha"] = SHA_B
    elif mutation == "run-id":
        api.runs["100"]["id"] = 101
    else:
        expected_attempt = 2
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]

    with pytest.raises(GitHubControllerError):
        select_latest_admission(
            api,
            repository="owner/repo",
            main=main,
            authority=authority,
            trigger_run_id=100,
            trigger_run_attempt=expected_attempt,
        )


def test_v11_direct_trigger_remains_bound_to_its_exact_admission() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    api.runs["101"] = {
        **api.runs["100"],
        "id": 101,
        "conclusion": "failure",
    }
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]

    assert select_latest_admission(
        api,
        repository="owner/repo",
        main=main,
        authority=authority,
        trigger_run_id=100,
        trigger_run_attempt=1,
    ) == ("100", 1)


def test_v11_untriggered_selection_uses_newest_without_success_fallback() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    api.runs["101"] = {
        **api.runs["100"],
        "id": 101,
        "conclusion": "failure",
    }
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]

    assert select_latest_admission(
        api, repository="owner/repo", main=main, authority=authority  # type: ignore[arg-type]
    ) == ("101", 1)


def test_v11_invalid_direct_trigger_cannot_fall_back_to_older_green() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    api.runs["101"] = {
        **api.runs["100"],
        "id": 101,
        "head_repository": {"id": 41},
    }
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]

    with pytest.raises(GitHubControllerError, match="head repository"):
        select_latest_admission(
            api,
            repository="owner/repo",
            main=main,
            authority=authority,
            trigger_run_id=101,
            trigger_run_attempt=1,
        )


def test_v11_finalizer_preserves_admitted_subject_after_main_moves(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    api.main = SHA_B
    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        trigger_run_id=100,
        trigger_run_attempt=1,
        output_dir=tmp_path / "bundle",
    )
    report = json.loads(
        (Path(result.bundle_dir) / "ci-certification.json").read_text()
    )
    assert report["subject"]["checkout_sha"] == SHA_A
    assert report["subject"]["tree_sha"] == TREE

    api.runs["400"].update(status="completed", conclusion="success")
    api.runs["401"] = {
        **api.runs["400"],
        "id": 401,
        "workflow_id": 97,
        "status": "in_progress",
        "conclusion": None,
    }
    published = publish_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=Path(result.bundle_dir),
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        publisher_run_id=401,
        publisher_run_attempt=1,
    )
    assert published["status"] == "suppressed"
    assert published["reason"] == "default_main_moved"
    assert api.published_statuses == []


def test_v11_publisher_rejects_run_for_different_subject(tmp_path: Path) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        trigger_run_id=100,
        trigger_run_attempt=1,
        output_dir=tmp_path / "bundle",
    )
    api.main = SHA_B
    api.runs["400"].update(status="completed", conclusion="success")
    api.runs["401"] = {
        **api.runs["400"],
        "id": 401,
        "workflow_id": 97,
        "head_sha": SHA_B,
        "status": "in_progress",
        "conclusion": None,
    }

    with pytest.raises(GitHubControllerError, match="certification subject"):
        publish_exact_main(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            bundle_dir=Path(result.bundle_dir),
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            publisher_run_id=401,
            publisher_run_attempt=1,
        )
    assert api.published_statuses == []


def test_v11_direct_trigger_uses_provider_status_and_commit_tree(tmp_path: Path) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    api.tree = SHA_B
    api.runs["100"]["conclusion"] = "failure"
    api.run_job_conclusions["100"] = {"Admit exact main": "success"}
    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        trigger_run_id=100,
        trigger_run_attempt=1,
        output_dir=tmp_path / "bundle",
    )

    assert result.computed_state == "failed"
    report = json.loads(
        (Path(result.bundle_dir) / "ci-certification.json").read_text()
    )
    assert report["subject"]["tree_sha"] == SHA_B


def test_v11_bootstrap_selects_one_complete_producer_from_partial_admission() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    api.run_job_names["100"] = (
        "Admit exact main",
        "Governance evidence / ${{ matrix.display_name }}",
        "Package proof",
    )
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]

    observed = collect_same_run_producers(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        main=main,
        authority=authority,
        admission_run_id="100",
        admission_run_attempt=1,
        producer_ids=("pack",),
        require_complete_admission_inventory=False,
    )

    assert [value["producer_id"] for value in observed] == ["pack"]
    assert observed[0]["same_run_membership"]["exact_job_inventory"] is True


def test_v11_bootstrap_rejects_missing_selected_producer_in_partial_admission() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    api.run_job_names["100"] = (
        "Admit exact main",
        "Governance evidence / ${{ matrix.display_name }}",
    )
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]

    with pytest.raises(GitHubControllerError, match="selected producer exact job inventory"):
        collect_same_run_producers(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            main=main,
            authority=authority,
            admission_run_id="100",
            admission_run_attempt=1,
            producer_ids=("pack",),
            require_complete_admission_inventory=False,
        )


def test_v11_finalizer_builds_certification_only_from_common_run(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        output_dir=tmp_path / "bundle",
    )
    assert result.status == "terminal"
    assert result.computed_state == "certified"
    report = json.loads(
        (Path(result.bundle_dir) / "ci-certification.json").read_text(encoding="utf-8")
    )
    assert report["authority_contract_version"] == "1.1"
    assert {
        (value["selected_attempt"]["run_id"], value["same_run_membership"]["admission_run_id"])
        for value in report["admission"]["producer_runs"]
    } == {("100", "100")}


def test_v11_post_install_chain_preserves_only_bounded_workitem_authority(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    api.main = SHA_B
    api.runs["100"]["head_sha"] = SHA_B
    api.runs["400"]["head_sha"] = SHA_B
    for reference in api.runs["100"]["referenced_workflows"]:
        reference["sha"] = SHA_B
    lifecycle = resolve_controller_lifecycle(
        Path(__file__).resolve().parents[1],
        {
            "trusted_controller_artifact": {
                "BCF_BOOTSTRAP_COMMIT_SHA": SHA_A,
            },
            "trusted_controller_installation": {
                "installed_commit_sha": SHA_A,
            },
        },
    )
    assert lifecycle.state is ControllerLifecycleState.ORDINARY_CURRENT
    api.truth_artifact_override = {
        "status": "pass",
        "subject": {
            "commit_sha": SHA_B,
            "tree_sha": TREE,
            "tracked_clean": True,
            "untracked_clean": True,
        },
        "evaluation_scope": {
            "intent": "workitem",
            "target": {"kind": "workitem", "id": "P26-P0-01"},
        },
        "certified_proposition": {
            "predicate": "workitem_closed",
            "target": {"kind": "workitem", "id": "P26-P0-01"},
            "subject": {"commit_sha": SHA_B, "tree_sha": TREE},
            "conclusion": "success",
            "authorizes": ["declared_successor_workitem_eligibility"],
            "eligible_successors": ["P26-P0-02"],
        },
        "durable_ref": (
            "github-actions://owner/repo/runs/100/attempts/1/"
            "bcf-governance-truth"
        ),
    }
    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        output_dir=tmp_path / "bundle",
    )
    report = json.loads(
        (Path(result.bundle_dir) / "ci-certification.json").read_text()
    )
    assert report["evaluation_scope"] == api.truth_artifact_override["evaluation_scope"]
    assert report["certified_proposition"] == api.truth_artifact_override["certified_proposition"]
    assert is_terminal_phase_certification(report) is False
    api.runs["400"].update(status="completed", conclusion="success")
    api.runs["401"] = {
        **api.runs["400"],
        "id": 401,
        "workflow_id": 97,
        "status": "in_progress",
        "conclusion": None,
    }
    publish_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=Path(result.bundle_dir),
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        publisher_run_id=401,
        publisher_run_attempt=1,
    )
    assert api.published_statuses[-1]["context"] == "bcf/workitem-certification"


@pytest.mark.parametrize(
    "metadata",
    [
        {"tracked_clean": True, "untracked_clean": True},
        {"canonical_metadata": {"schema_version": "future"}},
    ],
)
def test_v11_finalizer_projects_identity_from_richer_truth_subject(
    tmp_path: Path, metadata: dict[str, object]
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    api.truth_artifact_override = {
        "status": "pass",
        "subject": {"commit_sha": SHA_A, "tree_sha": TREE, **metadata},
        "evaluation_scope": {
            "intent": "workitem",
            "target": {"kind": "workitem", "id": "P26-P0-01"},
        },
        "certified_proposition": {
            "predicate": "workitem_closed",
            "target": {"kind": "workitem", "id": "P26-P0-01"},
            "subject": {"commit_sha": SHA_A, "tree_sha": TREE},
            "conclusion": "success",
            "authorizes": ["declared_successor_workitem_eligibility"],
            "eligible_successors": ["P26-P0-02"],
        },
        "durable_ref": (
            "github-actions://owner/repo/runs/100/attempts/1/"
            "bcf-governance-truth"
        ),
    }

    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        output_dir=tmp_path / "bundle",
    )

    assert result.computed_state == "certified"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("commit_sha", None),
        ("commit_sha", SHA_B),
        ("commit_sha", "malformed"),
        ("tree_sha", None),
        ("tree_sha", SHA_B),
        ("tree_sha", "malformed"),
    ],
)
def test_v11_finalizer_rejects_invalid_projected_truth_identity(
    tmp_path: Path, field: str, value: object
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    truth_subject: dict[str, object] = {
        "commit_sha": SHA_A,
        "tree_sha": TREE,
        "tracked_clean": True,
        "untracked_clean": True,
    }
    if value is None:
        truth_subject.pop(field)
    else:
        truth_subject[field] = value
    api.truth_artifact_override = {
        "status": "pass",
        "subject": truth_subject,
        "evaluation_scope": {
            "intent": "workitem",
            "target": {"kind": "workitem", "id": "P26-P0-01"},
        },
        "certified_proposition": {
            "predicate": "workitem_closed",
            "target": {"kind": "workitem", "id": "P26-P0-01"},
            "subject": {"commit_sha": SHA_A, "tree_sha": TREE},
            "conclusion": "success",
            "authorizes": ["declared_successor_workitem_eligibility"],
            "eligible_successors": ["P26-P0-02"],
        },
        "durable_ref": (
            "github-actions://owner/repo/runs/100/attempts/1/"
            "bcf-governance-truth"
        ),
    }

    with pytest.raises(GitHubControllerError, match="governance truth subject"):
        finalize_exact_main(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            collector_run_id=400,
            collector_run_attempt=1,
            output_dir=tmp_path / "bundle",
        )


@pytest.mark.parametrize("mutation", ["subject", "target", "run-attempt"])
def test_v11_finalizer_rejects_mismatched_bounded_truth(
    tmp_path: Path, mutation: str
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    scope = {"intent": "workitem", "target": {"kind": "workitem", "id": "P26-P0-01"}}
    proposition = {
        "predicate": "workitem_closed",
        "target": dict(scope["target"]),
        "subject": {"commit_sha": SHA_A, "tree_sha": TREE},
        "conclusion": "success",
        "authorizes": ["declared_successor_workitem_eligibility"],
        "eligible_successors": ["P26-P0-02"],
    }
    if mutation == "subject":
        proposition["subject"] = {"commit_sha": SHA_B, "tree_sha": TREE}
    elif mutation == "target":
        proposition["target"] = {"kind": "workitem", "id": "P26-P0-02"}
    api.truth_artifact_override = {
        "status": "pass",
        "subject": {"commit_sha": SHA_A, "tree_sha": TREE},
        "evaluation_scope": scope,
        "certified_proposition": proposition,
        "durable_ref": (
            "github-actions://owner/repo/runs/100/attempts/2/"
            "bcf-governance-truth"
            if mutation == "run-attempt"
            else "github-actions://owner/repo/runs/100/attempts/1/bcf-governance-truth"
        ),
    }
    with pytest.raises(GitHubControllerError):
        finalize_exact_main(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            collector_run_id=400,
            collector_run_attempt=1,
            output_dir=tmp_path / "bundle",
        )


def test_v11_incomplete_observation_is_noncertifying_without_borrowing_older_runs(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    api.run_job_statuses["100"] = "in_progress"
    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        output_dir=tmp_path / "bundle",
    )
    assert result.status == "noncertifying"
    assert result.bundle_dir is not None
    manifest = json.loads(
        (Path(result.bundle_dir) / "bundle-manifest.json").read_text()
    )
    assert manifest["kind"] == "authority_observation"
    api.runs["400"].update(status="completed", conclusion="success")
    api.runs["401"] = {
        **api.runs["400"],
        "id": 401,
        "workflow_id": 97,
        "status": "in_progress",
        "conclusion": None,
    }

    published = publish_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=Path(result.bundle_dir),
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        publisher_run_id=401,
        publisher_run_attempt=1,
    )

    assert published["computed_state"] == "noncertifying"
    assert published["reason"] == "certification_inapplicable"
    assert api.published_statuses == []


@pytest.mark.parametrize(
    "shape",
    ["missing-producer", "preflight-truncated", "admission-skipped"],
)
def test_v11_partial_topology_shapes_are_noncertifying(
    tmp_path: Path, shape: str
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    if shape == "missing-producer":
        api.run_job_names["100"] = ("Admit exact main", "Governance truth")
    elif shape == "preflight-truncated":
        placeholder = "Governance evidence / ${{ matrix.display_name }}"
        api.run_job_names["100"] = (
            "Admit exact main",
            "Governance truth",
            placeholder,
        )
        api.run_job_conclusions["100"] = {placeholder: "skipped"}
    else:
        api.run_job_conclusions["100"] = {"Admit exact main": "skipped"}

    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        trigger_run_id=100,
        trigger_run_attempt=1,
        output_dir=tmp_path / shape,
    )

    assert result.status == "noncertifying"
    assert result.computed_state == "noncertifying"
    assert not (Path(result.bundle_dir) / "ci-certification.json").exists()


def test_v11_pending_rotation_builder_only_path_stays_noncertifying(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    api.main = SHA_B
    api.runs["100"]["head_sha"] = SHA_B
    api.runs["400"]["head_sha"] = SHA_B
    for reference in api.runs["100"]["referenced_workflows"]:
        reference["sha"] = SHA_B
    authority["workflow_registry"]["admission"]["job_roles"][
        "trusted-controller-build"
    ] = "controller-builder"
    authority["controller_builder_jobs"] = [
        {"job_id": "Build independent exact-main trusted controller"}
    ]
    workflow = b"name: exact-main\njobs:\n  admit:\n    name: Admit exact main\n  governance:\n    name: Governance producer facade\n  pack:\n    name: Package producer facade\n  trusted-controller-build:\n    name: Build independent exact-main trusted controller\n"
    authority["workflow_registry"]["admission"]["trusted_workflow_sha256"] = (
        hashlib.sha256(workflow).hexdigest()
    )
    api.workflow_path_versions[(SHA_A, ".github/workflows/control.yml")] = (
        SHA_A,
        workflow,
    )
    api.workflow_path_versions[(SHA_B, ".github/workflows/control.yml")] = (
        SHA_A,
        workflow,
    )
    api.run_job_names["100"] = (
        "Build independent exact-main trusted controller",
        "Admit exact main",
        "Governance producer facade",
        "Package producer facade",
    )
    api.run_job_conclusions["100"] = {
        "Build independent exact-main trusted controller": "success",
        "Admit exact main": "skipped",
        "Governance producer facade": "skipped",
        "Package producer facade": "skipped",
    }

    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        trigger_run_id=100,
        trigger_run_attempt=1,
        output_dir=tmp_path / "pending-rotation",
    )

    assert result.status == "noncertifying"
    assert result.computed_state == "noncertifying"
    root = Path(result.bundle_dir)
    observation = json.loads((root / "authority-observation.json").read_text())
    assert observation["reason"] == "pending_controller_rotation"
    assert observation["subject"]["commit_sha"] == SHA_B
    assert (
        observation["collector"]["workflow"][
            "trusted_workflow_definition_commit"
        ]
        == SHA_A
    )
    assert not (root / "ci-certification.json").exists()

    api.runs["400"].update(status="completed", conclusion="success")
    api.runs["401"] = {
        **api.runs["400"],
        "id": 401,
        "workflow_id": 97,
        "status": "in_progress",
        "conclusion": None,
    }
    published = publish_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=root,
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        publisher_run_id=401,
        publisher_run_attempt=1,
    )
    assert published["computed_state"] == "noncertifying"
    assert api.published_statuses == []

    authority["workflow_registry"]["finalizer"][
        "trusted_workflow_definition_commit"
    ] = SHA_B
    with pytest.raises(
        GitHubControllerError, match="authority observation collector is not exact"
    ):
        publish_exact_main(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            bundle_dir=root,
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            publisher_run_id=401,
            publisher_run_attempt=1,
        )
    assert api.published_statuses == []


def test_v11_topology_classifies_only_exact_builder_only_shape_as_pending() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    authority["workflow_registry"]["admission"]["job_roles"][
        "trusted-controller-build"
    ] = "controller-builder"
    authority["controller_builder_jobs"] = [
        {"job_id": "Build independent exact-main trusted controller"}
    ]
    workflow = b"name: exact-main\njobs:\n  admit:\n    name: Admit exact main\n  governance:\n    name: Governance producer facade\n  pack:\n    name: Package producer facade\n  trusted-controller-build:\n    name: Build independent exact-main trusted controller\n"
    digest = hashlib.sha256(workflow).hexdigest()
    authority["workflow_registry"]["admission"]["trusted_workflow_sha256"] = digest
    api.workflow_path_versions[(SHA_A, ".github/workflows/control.yml")] = (
        SHA_A,
        workflow,
    )
    api.run_job_names["100"] = (
        "Build independent exact-main trusted controller",
        "Admit exact main",
        "Governance producer facade",
        "Package producer facade",
    )
    api.run_job_conclusions["100"] = {
        "Build independent exact-main trusted controller": "success",
        "Admit exact main": "skipped",
        "Governance producer facade": "skipped",
        "Package producer facade": "skipped",
    }
    main = resolve_main(api, "owner/repo")

    pending = classify_admission_topology(
        api,
        repository="owner/repo",
        main=main,
        authority=authority,
        admission_run_id="100",
        admission_run_attempt="1",
    )
    assert pending.state is AdmissionTopologyState.PENDING_ROTATION
    assert pending.reason == "pending_controller_rotation"

    api.run_job_conclusions["100"]["Admit exact main"] = "failure"
    failed = classify_admission_topology(
        api,
        repository="owner/repo",
        main=main,
        authority=authority,
        admission_run_id="100",
        admission_run_attempt="1",
    )
    assert failed.state is AdmissionTopologyState.NONCERTIFYING
    assert failed.reason == "admission_not_successful"


def test_v11_pending_rotation_rejects_child_or_unrelated_facade_laundering() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    authority["workflow_registry"]["admission"]["job_roles"][
        "trusted-controller-build"
    ] = "controller-builder"
    authority["controller_builder_jobs"] = [
        {"job_id": "Build independent exact-main trusted controller"}
    ]
    workflow = b"name: exact-main\njobs:\n  admit:\n    name: Admit exact main\n  governance:\n    name: Governance producer facade\n  pack:\n    name: Package producer facade\n  trusted-controller-build:\n    name: Build independent exact-main trusted controller\n"
    authority["workflow_registry"]["admission"]["trusted_workflow_sha256"] = (
        hashlib.sha256(workflow).hexdigest()
    )
    api.workflow_path_versions[(SHA_A, ".github/workflows/control.yml")] = (
        SHA_A,
        workflow,
    )
    api.run_job_names["100"] = (
        "Build independent exact-main trusted controller",
        "Admit exact main",
        "Governance truth",
    )
    api.run_job_conclusions["100"] = {
        "Build independent exact-main trusted controller": "success",
        "Admit exact main": "skipped",
        "Governance truth": "skipped",
    }

    result = classify_admission_topology(
        api,
        repository="owner/repo",
        main=resolve_main(api, "owner/repo"),
        authority=authority,
        admission_run_id="100",
        admission_run_attempt="1",
    )
    assert result.state is AdmissionTopologyState.NONCERTIFYING
    assert result.reason == "admission_not_successful"


@pytest.mark.parametrize("shape", ["active-extra", "duplicate"])
def test_v11_malformed_topology_cannot_be_reclassified_as_noncertifying(
    tmp_path: Path, shape: str
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    if shape == "active-extra":
        api.run_job_names["100"] += ("Unadmitted job",)
    else:
        api.run_job_names["100"] += ("Governance truth",)

    with pytest.raises(GitHubControllerError, match="job inventory"):
        finalize_exact_main(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            collector_run_id=400,
            collector_run_attempt=1,
            trigger_run_id=100,
            trigger_run_attempt=1,
            output_dir=tmp_path / shape,
        )


def test_v11_certification_producer_completeness_is_scope_aware() -> None:
    authority = _v11_authority()
    expected = ("governance", "pack")
    assert certification_producer_ids(
        authority,
        {"intent": "workitem", "target": {"kind": "workitem", "id": "P26-P0-01"}},
    ) == expected
    assert certification_producer_ids(
        authority,
        {"intent": "closure", "target": {"kind": "phase", "id": "P26"}},
    ) == expected
    with pytest.raises(GitHubControllerError, match="scope is unsupported"):
        certification_producer_ids(
            authority,
            {"intent": "pr", "target": {"kind": "pull_request_progress", "id": SHA_A}},
        )


def test_v11_missing_finalizer_bundle_cannot_manufacture_certification_failure(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    _prepare_v11_run(api)
    api.runs["400"].update(status="completed", conclusion="failure")
    api.runs["401"] = {
        **api.runs["400"],
        "id": 401,
        "workflow_id": 97,
        "status": "in_progress",
        "conclusion": None,
    }

    published = publish_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=tmp_path / "missing",
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        publisher_run_id=401,
        publisher_run_attempt=1,
    )

    assert published["status"] == "suppressed"
    assert published["reason"] == "certification_applicability_unproven"
    assert api.published_statuses == []


def test_independent_builder_success_does_not_certify_failed_governance(
    tmp_path: Path,
) -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    authority["workflow_registry"]["admission"]["job_roles"] = {  # type: ignore[index]
        "admit": "admission",
        "governance": "producer",
        "trusted-controller-build": "controller-builder",
    }
    authority["roles"]["reusable_producers"] = ["governance"]  # type: ignore[index]
    authority["producers"] = [authority["producers"][0]]  # type: ignore[index]
    authority["controller_builder_jobs"] = [
        {"job_id": "Build independent exact-main trusted controller"}
    ]
    api.runs["100"]["conclusion"] = "failure"
    api.runs["100"]["referenced_workflows"] = [
        {"path": ".github/workflows/governance.yml", "sha": SHA_A}
    ]

    def jobs(
        _repository: str, run_id: str | int, *, attempt: int
    ) -> tuple[dict[str, object], ...]:
        if str(run_id) != "100":
            return FakeAPI.jobs(api, _repository, run_id, attempt=attempt)
        return (
            {"name": "Admit exact main", "status": "completed", "conclusion": "success"},
            {"name": "Governance truth", "status": "completed", "conclusion": "failure"},
            {
                "name": "Build independent exact-main trusted controller",
                "status": "completed",
                "conclusion": "success",
            },
        )

    api.jobs = jobs  # type: ignore[method-assign]
    result = finalize_exact_main(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        collector_run_id=400,
        collector_run_attempt=1,
        output_dir=tmp_path / "bundle",
    )

    assert result.status == "terminal"
    assert result.computed_state == "failed"
    report = json.loads(
        (Path(result.bundle_dir) / "ci-certification.json").read_text(encoding="utf-8")
    )
    assert [
        value["producer_id"] for value in report["admission"]["producer_runs"]
    ] == ["governance"]


@pytest.mark.parametrize("mutation", ["mixed-run", "mixed-attempt", "wrong-ref", "extra-job"])
def test_v11_common_admission_mutants_fail_closed(mutation: str) -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    run_id: object = 100
    attempt: object = 1
    if mutation == "mixed-run":
        run_id = 200
    elif mutation == "mixed-attempt":
        attempt = 2
    elif mutation == "wrong-ref":
        api.runs["100"]["referenced_workflows"][0]["sha"] = SHA_B  # type: ignore[index]
    else:
        api.run_job_names["100"] += ("Unadmitted job",)
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]
    with pytest.raises(GitHubControllerError):
        collect_same_run_producers(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            main=main,
            authority=authority,
            admission_run_id=run_id,
            admission_run_attempt=attempt,
        )


def test_latest_failed_admission_is_selected_without_green_fallback() -> None:
    api = FakeAPI()
    authority = _prepare_v11_run(api)
    api.runs["101"] = {
        **api.runs["100"],
        "id": 101,
        "conclusion": "failure",
    }
    main = resolve_main(api, "owner/repo")  # type: ignore[arg-type]
    assert select_latest_admission(
        api, repository="owner/repo", main=main, authority=authority  # type: ignore[arg-type]
    ) == ("101", 1)


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


def test_pending_callback_is_authenticated_without_status_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = FakeAPI()
    api.runs["300"]["status"] = "in_progress"
    api.runs["300"]["conclusion"] = None
    result = finalize_callback(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_root=tmp_path / "callback",
    )
    root = Path(result["callback_dir"])
    assert result["status"] == "pending"
    assert {path.name for path in root.iterdir()} == {"callback-result.json"}
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"
    publish_calls: list[object] = []
    monkeypatch.setattr(
        callbacks,
        "publish",
        lambda *args, **kwargs: publish_calls.append((args, kwargs))
        or {"status": "published"},
    )

    published = publish_callback(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        callback_dir=root,
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
    )

    assert published["status"] == "suppressed"
    assert published["reason"] == "producers_pending"
    assert publish_calls == []
    assert api.published_statuses == []


def test_terminal_callback_binds_bundle_before_publication(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize_callback(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_root=tmp_path / "callback",
    )
    root = Path(result["callback_dir"])
    callback = json.loads((root / "callback-result.json").read_text())
    assert callback["status"] == "terminal"
    assert callback["bundle_manifest_sha256"] == hashlib.sha256(
        (root / "bundle/bundle-manifest.json").read_bytes()
    ).hexdigest()
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"

    published = publish_callback(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        callback_dir=root,
        target_url="https://github.example/runs/400",
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
    )

    assert published["status"] == "published"
    assert len(api.published_statuses) == 1


def test_callback_bundle_digest_tampering_is_rejected(tmp_path: Path) -> None:
    api = FakeAPI()
    result = finalize_callback(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_root=tmp_path / "callback",
    )
    root = Path(result["callback_dir"])
    callback_path = root / "callback-result.json"
    callback = json.loads(callback_path.read_text())
    callback["bundle_manifest_sha256"] = "d" * 64
    _write_json(callback_path, callback)
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"

    with pytest.raises(GitHubControllerError, match="bundle digest does not match"):
        publish_callback(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            callback_dir=root,
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
        )

    assert api.published_statuses == []


def test_pending_callback_rejects_unexpected_artifact_fan_in(tmp_path: Path) -> None:
    api = FakeAPI()
    api.runs["300"]["status"] = "in_progress"
    api.runs["300"]["conclusion"] = None
    result = finalize_callback(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_root=tmp_path / "callback",
    )
    root = Path(result["callback_dir"])
    (root / "candidate-content.txt").write_text("untrusted\n", encoding="utf-8")
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"

    with pytest.raises(GitHubControllerError, match="top-level inventory"):
        publish_callback(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            callback_dir=root,
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
        )

    assert api.published_statuses == []


def test_callback_rejects_wrong_triggering_collector(tmp_path: Path) -> None:
    api = FakeAPI()
    api.runs["300"]["status"] = "in_progress"
    api.runs["300"]["conclusion"] = None
    result = finalize_callback(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_root=tmp_path / "callback",
    )
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"
    api.runs["401"] = {**api.runs["400"], "id": 401}

    with pytest.raises(GitHubControllerError, match="triggering collector"):
        publish_callback(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            callback_dir=Path(result["callback_dir"]),
            target_url="https://github.example/runs/400",
            collector_run_id=401,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
        )

    assert api.published_statuses == []


def test_callback_rejects_symlinked_artifact_root(tmp_path: Path) -> None:
    api = FakeAPI()
    api.runs["300"]["status"] = "in_progress"
    api.runs["300"]["conclusion"] = None
    result = finalize_callback(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        control_run_id=100,
        control_run_attempt=1,
        **CONTROL_IDENTITY,
        collector_run_id=400,
        collector_run_attempt=1,
        **COLLECTOR_IDENTITY,
        output_root=tmp_path / "callback",
    )
    callback_link = tmp_path / "callback-link"
    callback_link.symlink_to(Path(result["callback_dir"]), target_is_directory=True)
    api.runs["400"]["status"] = "completed"
    api.runs["400"]["conclusion"] = "success"

    with pytest.raises(GitHubControllerError, match="cannot be a symlink"):
        publish_callback(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            callback_dir=callback_link,
            target_url="https://github.example/runs/400",
            collector_run_id=400,
            collector_run_attempt=1,
            **COLLECTOR_IDENTITY,
        )

    assert api.published_statuses == []


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


def test_pinned_definition_must_still_match_current_main(tmp_path: Path) -> None:
    api = FakeAPI()
    historical = b"name: historical producer\n"
    workflow = api.authority["producers"][0]["workflow"]
    workflow["trusted_workflow_definition_commit"] = SHA_B
    workflow["trusted_workflow_blob_oid"] = SHA_B
    workflow["trusted_workflow_sha256"] = hashlib.sha256(historical).hexdigest()
    api.workflow_versions[SHA_B] = (SHA_B, historical)

    with pytest.raises(GitHubControllerError, match="current default-main workflow bytes"):
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

    with pytest.raises(
        GitHubControllerError,
        match="not authenticated|trusted workflow bytes digest",
    ):
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
    with pytest.raises(
        GitHubControllerError,
        match="not authenticated|trusted workflow bytes digest",
    ):
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


def test_commit_comparison_is_exact_and_read_only() -> None:
    class RecordingAPI(GitHubAPI):
        def __init__(self) -> None:
            super().__init__(token="test")
            self.request: tuple[str, str] | None = None

        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            self.request = (method, path)
            return {"status": "ahead"}

    api = RecordingAPI()
    assert api.compare_commits("owner/repo", base=SHA_A, head=SHA_B) == {
        "status": "ahead"
    }
    assert api.request == (
        "GET",
        f"/repos/owner/repo/compare/{SHA_A}...{SHA_B}",
    )


def test_workflow_rerun_is_exactly_scoped_to_authenticated_run() -> None:
    class RecordingAPI(GitHubAPI):
        def __init__(self) -> None:
            super().__init__(token="test")
            self.request: tuple[str, str, object] | None = None

        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            self.request = (method, path, payload)

    api = RecordingAPI()
    api.rerun_workflow("owner/repo", "42")
    assert api.request == ("POST", "/repos/owner/repo/actions/runs/42/rerun", None)
    with pytest.raises(GitHubAPIError, match="positive numeric"):
        api.rerun_workflow("owner/repo", "../42")
    with pytest.raises(GitHubAPIError, match="SHA"):
        api.compare_commits("owner/repo", base="main", head=SHA_B)


def test_api_rejects_truncated_workflow_run_inventory() -> None:
    class TruncatedAPI(GitHubAPI):
        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            return {"total_count": 2, "workflow_runs": [{"id": 1}]}

    api = TruncatedAPI(token="test")
    with pytest.raises(GitHubAPIError, match="exceeds one authenticated page"):
        api.workflow_runs("owner/repo", 10, head_sha=SHA_A, event="push")


def test_break_glass_api_reads_are_exact_and_repository_scoped() -> None:
    class RecordingAPI(GitHubAPI):
        def __init__(self) -> None:
            super().__init__(token="test")
            self.paths: list[str] = []

        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            self.paths.append(path)
            if path == "/installation/repositories?per_page=100":
                return {"total_count": 1, "repositories": [{"id": 40}]}
            if path == "/users/owner":
                return {"id": 30, "login": "owner"}
            if path.endswith("/collaborators/owner/permission"):
                return {"permission": "admin"}
            return {"total_count": 1, "artifacts": [{"id": 40}]}

    api = RecordingAPI()
    assert api.installation_repositories()[0]["id"] == 40
    assert api.collaborator_permission("owner/repo", "owner")["permission"] == "admin"
    assert api.repository_artifacts("owner/repo", name="recovery-build-abc")[0]["id"] == 40
    assert api.paths == [
        "/installation/repositories?per_page=100",
        "/users/owner",
        "/repos/owner/repo/collaborators/owner/permission",
        "/repos/owner/repo/actions/artifacts?per_page=100&page=1&name=recovery-build-abc",
        "/repos/owner/repo/actions/artifacts?per_page=100&page=1&name=recovery-build-abc",
    ]
    with pytest.raises(GitHubAPIError, match="artifact name filter is unsafe"):
        api.repository_artifacts("owner/repo", name="../artifact")


def test_repository_artifact_inventory_is_complete_across_authenticated_pages() -> None:
    class PaginatedAPI(GitHubAPI):
        def __init__(self) -> None:
            super().__init__(token="test")
            self.paths: list[str] = []

        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            self.paths.append(path)
            page = 2 if "page=2" in path else 1
            start = 101 if page == 2 else 1
            stop = 102 if page == 2 else 101
            return {
                "total_count": 101,
                "artifacts": [{"id": value} for value in range(start, stop)],
            }

    api = PaginatedAPI()
    artifacts = api.repository_artifacts("owner/repo")

    assert [artifact["id"] for artifact in artifacts] == list(range(1, 102))
    assert api.paths == [
        "/repos/owner/repo/actions/artifacts?per_page=100&page=1",
        "/repos/owner/repo/actions/artifacts?per_page=100&page=2",
        "/repos/owner/repo/actions/artifacts?per_page=100&page=1",
        "/repos/owner/repo/actions/artifacts?per_page=100&page=2",
    ]


def test_repository_artifact_inventory_restarts_after_concurrent_upload() -> None:
    class ConcurrentUploadAPI(GitHubAPI):
        def __init__(self) -> None:
            super().__init__(token="test")
            self.request_count = 0

        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            self.request_count += 1
            page = 2 if "page=2" in path else 1
            if self.request_count <= 2:
                total = 101 if page == 1 else 102
            else:
                total = 102
            start = 101 if page == 2 else 1
            stop = 103 if page == 2 else 101
            return {
                "total_count": total,
                "artifacts": [{"id": value} for value in range(start, stop)],
            }

    api = ConcurrentUploadAPI()
    artifacts = api.repository_artifacts("owner/repo")

    assert [artifact["id"] for artifact in artifacts] == list(range(1, 103))
    assert api.request_count == 6


def test_repository_artifact_inventory_requires_consecutive_exact_snapshots() -> None:
    class SameCountReplacementAPI(GitHubAPI):
        def __init__(self) -> None:
            super().__init__(token="test")
            self.snapshot = 0

        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            if "page=1" in path:
                self.snapshot += 1
            first = 1 if self.snapshot == 1 else 2
            page = 2 if "page=2" in path else 1
            start = first + 100 if page == 2 else first
            stop = first + 101 if page == 2 else first + 100
            return {
                "total_count": 101,
                "artifacts": [{"id": value} for value in range(start, stop)],
            }

    artifacts = SameCountReplacementAPI().repository_artifacts("owner/repo")

    assert [artifact["id"] for artifact in artifacts] == list(range(2, 103))


def test_repository_artifact_inventory_rejects_persistent_concurrent_churn() -> None:
    class PersistentChurnAPI(GitHubAPI):
        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            page = 2 if "page=2" in path else 1
            return {
                "total_count": 101 if page == 1 else 102,
                "artifacts": [
                    {"id": value}
                    for value in range(101, 103)
                    if page == 2
                ]
                or [{"id": value} for value in range(1, 101)],
            }

    with pytest.raises(GitHubAPIError, match="did not stabilize"):
        PersistentChurnAPI(token="test").repository_artifacts("owner/repo")


@pytest.mark.parametrize("failure", ["changed-total", "missing", "duplicate"])
def test_repository_artifact_pagination_fails_closed_on_inexact_inventory(
    failure: str,
) -> None:
    class InexactAPI(GitHubAPI):
        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            if "page=2" not in path:
                return {
                    "total_count": 101,
                    "artifacts": [{"id": value} for value in range(1, 101)],
                }
            if failure == "changed-total":
                return {"total_count": 102, "artifacts": [{"id": 101}]}
            if failure == "missing":
                return {"total_count": 101, "artifacts": []}
            return {"total_count": 101, "artifacts": [{"id": 100}]}

    with pytest.raises(GitHubAPIError, match="changed|incomplete|ambiguous"):
        InexactAPI(token="test").repository_artifacts("owner/repo")


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"total_count": "1", "repositories": []},
        {"total_count": 1, "repositories": "invalid"},
        {"total_count": 1, "repositories": ["invalid"]},
    ],
)
def test_installation_repository_inventory_rejects_malformed_provider_response(
    response: object,
) -> None:
    class MalformedAPI(GitHubAPI):
        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            return response

    with pytest.raises(GitHubAPIError, match="exact object list"):
        MalformedAPI(token="test").installation_repositories()


def test_installation_repository_inventory_rejects_unhandled_pagination() -> None:
    class PaginatedAPI(GitHubAPI):
        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            return {"total_count": 2, "repositories": [{"id": 1}]}

    with pytest.raises(GitHubAPIError, match="exceeds one authenticated page"):
        PaginatedAPI(token="test").installation_repositories()
