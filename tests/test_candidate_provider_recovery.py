from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from bcf_governance.tooling.candidate_provider_recovery import (
    execute_candidate_provider_recovery,
    resolve_candidate_provider_recovery,
)
from bcf_governance.tooling.ci_authority_pins import compiled_workflow_job_names


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/governance.yml").read_bytes()
BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40


class Provider:
    def __init__(
        self,
        *,
        attempt: int = 1,
        terminal_truth_success: bool = True,
        complete_artifacts: bool = True,
        run_status: str = "completed",
        run_conclusion: str = "failure",
        annotation_message: str = (
            "Failed to CreateArtifact: Unable to make request: ETIMEDOUT"
        ),
    ) -> None:
        self.attempt = attempt
        self.terminal_truth_success = terminal_truth_success
        self.complete_artifacts = complete_artifacts
        self.run_status = run_status
        self.run_conclusion = run_conclusion
        self.annotation_message = annotation_message
        self.reruns: list[int] = []

    def repository(self, _repository: str):
        return {"id": 17, "default_branch": "main"}

    def workflow_runs(self, *_args, **_kwargs):
        return ({
            "id": 31,
            "run_attempt": self.attempt,
            "workflow_id": 23,
            "head_sha": HEAD,
            "event": "pull_request",
            "status": self.run_status,
            "conclusion": self.run_conclusion,
            "repository": {"id": 17},
            "pull_requests": [{
                "number": 7,
                "head": {"sha": HEAD},
                "base": {"sha": BASE},
            }],
        },)

    def workflow(self, _repository: str, _workflow_id):
        return {"id": 23, "path": ".github/workflows/governance.yml"}

    def content(self, _repository: str, _path: str, *, ref: str):
        assert ref == BASE
        return SimpleNamespace(content=WORKFLOW, blob_oid="4" * 40)

    def jobs(self, *_args, **_kwargs):
        values = []
        for index, name in enumerate(compiled_workflow_job_names(WORKFLOW), start=1):
            if name != "Verify exact-tree governance evidence":
                values.append({
                    "id": 100 + index,
                    "run_id": 31,
                    "run_attempt": self.attempt,
                    "name": name,
                    "status": "completed",
                    "conclusion": "success",
                    "steps": [],
                })
                continue
            truth_conclusion = "success" if self.terminal_truth_success else "failure"
            upload_conclusion = "failure" if self.terminal_truth_success else "skipped"
            values.append({
                "id": 199,
                "run_id": 31,
                "run_attempt": self.attempt,
                "name": name,
                "status": "completed",
                "conclusion": "failure",
                "steps": [
                    {"number": 1, "name": "Set up job", "conclusion": "success"},
                    {
                        "number": 8,
                        "name": "Verify exact-tree governance evidence",
                        "conclusion": truth_conclusion,
                    },
                    {
                        "number": 10,
                        "name": "Preserve a causal terminal result",
                        "conclusion": "success",
                    },
                    {
                        "number": 11,
                        "name": "Upload this attempt's terminal truth report",
                        "conclusion": upload_conclusion,
                    },
                ],
            })
        return tuple(values)

    def artifacts(self, *_args, **_kwargs):
        names = {
            f"bcf-session-31-{self.attempt}",
            *{
                f"bcf-evidence-31-{self.attempt}-shard-{index}"
                for index in range(4)
            },
        }
        if not self.complete_artifacts:
            names.pop()
        return tuple({"name": name, "expired": False} for name in sorted(names))

    def check_run_annotations(self, *_args, **_kwargs):
        return ({
            "annotation_level": "failure",
            "message": self.annotation_message,
        },)

    def rerun_workflow(self, _repository: str, run_id: object) -> None:
        self.reruns.append(int(str(run_id)))


def _resolve(provider: Provider):
    return resolve_candidate_provider_recovery(
        provider,
        repository="owner/repo",
        pull_request={"number": 7},
        base_sha=BASE,
        head_sha=HEAD,
        tree_sha=TREE,
    )


def test_transient_terminal_upload_selects_one_exact_provider_rerun() -> None:
    provider = Provider()
    frontier = _resolve(provider)
    assert frontier["state"] == "retryable_terminal_transport"
    assert frontier["action"]["kind"] == "rerun_exact_provider_workflow"
    assert frontier["identity"]["run_id"] == "31"
    assert frontier["identity"]["terminal_job_id"] == "199"
    assert execute_candidate_provider_recovery(
        provider, repository="owner/repo", frontier=frontier
    )
    assert provider.reruns == [31]


def test_semantic_failure_or_incomplete_artifacts_never_selects_retry() -> None:
    semantic_provider = Provider(terminal_truth_success=False)
    incomplete_provider = Provider(complete_artifacts=False)
    semantic = _resolve(semantic_provider)
    incomplete = _resolve(incomplete_provider)
    assert semantic["state"] == "terminal_failure"
    assert incomplete["state"] == "terminal_failure"
    assert semantic["action"]["kind"] == "stop"
    assert incomplete["action"]["kind"] == "stop"
    assert not execute_candidate_provider_recovery(
        semantic_provider, repository="owner/repo", frontier=semantic
    )
    assert not execute_candidate_provider_recovery(
        incomplete_provider, repository="owner/repo", frontier=incomplete
    )
    assert semantic_provider.reruns == []
    assert incomplete_provider.reruns == []


def test_second_identical_transport_failure_is_exhausted() -> None:
    frontier = _resolve(Provider(attempt=2))
    assert frontier["state"] == "retry_exhausted"
    assert frontier["action"]["kind"] == "stop"


def test_active_and_successful_provider_runs_select_observation_only() -> None:
    active = _resolve(Provider(run_status="in_progress", run_conclusion=""))
    successful_provider = Provider(run_conclusion="success")
    successful_provider.terminal_truth_success = True
    original_jobs = successful_provider.jobs

    def green_jobs(*args, **kwargs):
        return tuple(
            {**job, "conclusion": "success"}
            for job in original_jobs(*args, **kwargs)
        )

    successful_provider.jobs = green_jobs  # type: ignore[method-assign]
    succeeded = _resolve(successful_provider)
    assert active["action"]["kind"] == "observe_same_provider_run"
    assert succeeded["action"]["kind"] == "observe_pr_certification"


def test_nontransient_upload_annotation_fails_closed() -> None:
    frontier = _resolve(Provider(
        annotation_message="Failed to CreateArtifact: permission denied"
    ))
    assert frontier["state"] == "terminal_failure"
    assert frontier["action"]["kind"] == "stop"
