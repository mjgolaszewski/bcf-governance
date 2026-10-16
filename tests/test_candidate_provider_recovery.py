from __future__ import annotations

from pathlib import Path

import pytest
from types import SimpleNamespace

from bcf_governance.tooling.candidate_provider_recovery import (
    execute_candidate_provider_recovery,
    resolve_candidate_provider_recovery,
)
from bcf_governance.tooling.ci_authority_pins import compiled_workflow_job_names
from bcf_governance.tooling.ci_recovery_frontier import candidate_provider_frontier
from bcf_governance.tooling.local_pr import CandidateIdentity, LocalPRContext, ProspectiveValidationError


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

    def pull_request(self, _repository, number):
        return {"number": int(number), "node_id": "PR_exact7", "state": "open", "merged": False,
                "base": {"sha": BASE, "ref": "main", "repo": {"id": 17}},
                "head": {"sha": HEAD, "ref": "feature", "repo": {"id": 17}}}

    def commit(self, _repository, sha):
        return {"sha": sha, "tree": {"sha": TREE}}

    def run(self, _repository, run_id):
        return dict(self.workflow_runs()[0])

    def rerun_workflow(self, _repository: str, run_id: object) -> None:
        self.reruns.append(int(str(run_id)))
        self.attempt += 1
        self.run_status = "queued"


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
    assert _execute(provider, frontier)
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


CANDIDATE = CandidateIdentity(HEAD, TREE, BASE)
CONTEXT = LocalPRContext("origin", "main", BASE, HEAD, "feature")
PROVED_PR = {"number": 7, "node_id": "PR_exact7", "state": "open", "repository_id": 17,
             "base_sha": BASE, "head_sha": HEAD}


def _execute(provider, frontier, **overrides):
    values = dict(candidate=CANDIDATE, context=CONTEXT, pull_request=PROVED_PR)
    values.update(overrides)
    return execute_candidate_provider_recovery(provider, repository="owner/repo", frontier=frontier, **values)


@pytest.mark.parametrize("defect", ["bare", "hash", "context", "candidate", "pr", "run"])
def test_retry_executor_rejects_unbound_frontier_before_mutation(defect):
    provider = Provider()
    frontier = _resolve(provider)
    overrides = {}
    if defect == "bare":
        frontier = {"operation": "candidate_provider", "action": {"kind": "rerun_exact_provider_workflow"},
                    "identity": {"repository": "owner/repo", "run_id": "999"}}
    elif defect == "hash": frontier["frontier_sha256"] = "0" * 64
    elif defect == "context": overrides["context"] = None
    elif defect == "candidate": overrides["candidate"] = CandidateIdentity("5" * 40, TREE, BASE)
    elif defect == "pr": overrides["pull_request"] = {**PROVED_PR, "number": 8}
    else:
        # A valid self-consistent digest is not authenticated provider custody.
        frontier = candidate_provider_frontier(identity={**frontier["identity"], "run_id": "999"},
                                                state="retryable_terminal_transport")
    with pytest.raises(ProspectiveValidationError, match="candidate provider"):
        _execute(provider, frontier, **overrides)
    assert provider.reruns == []


@pytest.mark.parametrize("defect", ["head", "base", "branch", "base-branch", "node", "repository", "closed", "merged", "commit", "tree"])
def test_retry_executor_rejects_current_subject_movement(defect):
    provider = Provider()
    frontier = _resolve(provider)
    original_pr = provider.pull_request
    original_commit = provider.commit
    def moved_pr(*args):
        value = original_pr(*args)
        if defect == "head": value["head"]["sha"] = "5" * 40
        elif defect == "base": value["base"]["sha"] = "5" * 40
        elif defect == "branch": value["head"]["ref"] = "foreign"
        elif defect == "base-branch": value["base"]["ref"] = "foreign"
        elif defect == "node": value["node_id"] = "PR_foreign"
        elif defect == "repository": value["head"]["repo"]["id"] = 99
        elif defect == "closed": value["state"] = "closed"
        elif defect == "merged": value["merged"] = True
        return value
    def moved_commit(*args):
        value = original_commit(*args)
        if defect == "commit": value["sha"] = "5" * 40
        elif defect == "tree": value["tree"]["sha"] = "5" * 40
        return value
    provider.pull_request = moved_pr
    provider.commit = moved_commit
    with pytest.raises(ProspectiveValidationError, match="candidate provider|candidate pull request"):
        _execute(provider, frontier)
    assert provider.reruns == []


@pytest.mark.parametrize("defect", ["attempt", "active", "semantic", "artifacts", "last-attempt", "last-head"])
def test_retry_executor_reauthenticates_exact_attempt_at_consumption(defect):
    provider = Provider()
    frontier = _resolve(provider)
    if defect == "attempt": provider.attempt = 2
    elif defect == "active": provider.run_status = "in_progress"
    elif defect == "semantic": provider.terminal_truth_success = False
    elif defect == "artifacts": provider.complete_artifacts = False
    else:
        original = provider.run
        def moved(*args):
            value = original(*args)
            if defect == "last-attempt": value["run_attempt"] = 2
            else: value["head_sha"] = "5" * 40
            return value
        provider.run = moved
    with pytest.raises(ProspectiveValidationError, match="candidate provider"):
        _execute(provider, frontier)
    assert provider.reruns == []


@pytest.mark.parametrize("conclusion", ["cancelled", "timed_out", "action_required", "neutral", "skipped", None])
def test_nonfailure_terminal_state_never_selects_transport_retry(conclusion):
    provider = Provider(run_conclusion=conclusion)
    frontier = _resolve(provider)
    assert frontier["state"] == "terminal_failure"
    assert frontier["action"]["kind"] == "stop"
    assert provider.reruns == []


def test_exact_retry_is_not_repeated_after_provider_attempt_advances():
    provider = Provider()
    frontier = _resolve(provider)
    assert _execute(provider, frontier) is True
    with pytest.raises(ProspectiveValidationError, match="candidate provider"):
        _execute(provider, frontier)
    assert _execute(provider, _resolve(provider)) is False
    assert provider.reruns == [31]


def test_response_loss_never_blindly_repeats_rerun_mutation():
    provider = Provider()
    frontier = _resolve(provider)
    original = provider.rerun_workflow
    def response_lost(*args):
        original(*args)
        raise RuntimeError("provider response lost")
    provider.rerun_workflow = response_lost
    with pytest.raises(RuntimeError, match="response lost"):
        _execute(provider, frontier)
    assert _execute(provider, _resolve(provider)) is False
    assert provider.reruns == [31]


@pytest.mark.parametrize("status,conclusion,expected", [
    ("completed", "cancelled", "terminal_failure"),
    ("in_progress", None, "active"),
])
def test_observation_or_terminal_rejection_precedes_job_inventory(status, conclusion, expected):
    provider = Provider(run_status=status, run_conclusion=conclusion)
    def forbidden(*args, **kwargs):
        raise AssertionError("job inventory allocated before terminal eligibility")
    provider.jobs = forbidden
    assert _resolve(provider)["state"] == expected


@pytest.mark.parametrize("defect", ["hash", "context", "candidate", "pr", "exhausted"])
def test_invalid_retry_context_rejects_before_provider_reads(defect):
    provider = Provider()
    frontier = _resolve(provider)
    overrides = {}
    if defect == "hash": frontier["frontier_sha256"] = "0" * 64
    elif defect == "context": overrides["context"] = None
    elif defect == "candidate": overrides["candidate"] = CandidateIdentity(HEAD, "5" * 40, BASE)
    elif defect == "pr": overrides["pull_request"] = {**PROVED_PR, "number": 8}
    else:
        frontier = candidate_provider_frontier(identity={**frontier["identity"], "run_attempt": "2"},
                                                state="retryable_terminal_transport")
    def forbidden(*args, **kwargs):
        raise AssertionError("provider read before deterministic context rejection")
    provider.pull_request = forbidden
    with pytest.raises(ProspectiveValidationError, match="candidate provider"):
        _execute(provider, frontier, **overrides)
    assert provider.reruns == []


@pytest.mark.parametrize("port", ["pull_request", "commit", "repository", "workflow_runs", "workflow", "content", "jobs", "check_run_annotations", "artifacts", "run"])
def test_recovery_read_failure_never_falls_through_to_mutation(port):
    provider = Provider()
    frontier = _resolve(provider)
    def failed(*args, **kwargs):
        raise RuntimeError("provider observation unavailable")
    setattr(provider, port, failed)
    with pytest.raises(RuntimeError, match="observation unavailable"):
        _execute(provider, frontier)
    assert provider.reruns == []


@pytest.mark.parametrize("field", ["id", "workflow", "repository", "event", "status", "conclusion", "pr", "base"])
def test_latest_run_identity_is_closed_before_rerun_mutation(field):
    provider = Provider()
    frontier = _resolve(provider)
    original = provider.run
    def changed(*args):
        value = original(*args)
        if field == "id": value["id"] = 999
        elif field == "workflow": value["workflow_id"] = 999
        elif field == "repository": value["repository"] = {"id": 999}
        elif field == "event": value["event"] = "workflow_dispatch"
        elif field == "status": value["status"] = "queued"
        elif field == "conclusion": value["conclusion"] = "cancelled"
        elif field == "pr": value["pull_requests"][0]["number"] = 8
        else: value["pull_requests"][0]["base"]["sha"] = "5" * 40
        return value
    provider.run = changed
    with pytest.raises(ProspectiveValidationError, match="candidate provider"):
        _execute(provider, frontier)
    assert provider.reruns == []



def test_retry_plan_cannot_change_during_final_provider_observation():
    provider = Provider()
    frontier = _resolve(provider)
    original = provider.run
    class ConcurrentPlanChange(dict):
        def get(self, key, *args):
            value = super().get(key, *args)
            if key == "base":
                # Deterministically interleave an input update after the final
                # run identity checks, before the original executor reads its
                # mutation target again. This is not a real provider mutation.
                frontier["identity"]["run_id"] = "999"
            return value
    def observe(*args):
        value = original(*args)
        value["pull_requests"][0] = ConcurrentPlanChange(value["pull_requests"][0])
        return value
    provider.run = observe
    with pytest.raises(ProspectiveValidationError, match="plan changed during observation"):
        _execute(provider, frontier)
    assert provider.reruns == []


@pytest.mark.parametrize('field,value', [('base_sha', ' ' + BASE), ('head_sha', HEAD + ' '),
    ('default_branch', ' main '), ('head_ref', ' feature ')], ids=['base', 'head', 'default-branch', 'branch'])
def test_retry_executor_never_repairs_independently_proved_context(field, value):
    from dataclasses import replace
    provider = Provider()
    frontier = _resolve(provider)
    with pytest.raises(ProspectiveValidationError, match='candidate provider|candidate pull request'):
        _execute(provider, frontier, context=replace(CONTEXT, **{field: value}))
    assert provider.reruns == []


@pytest.mark.parametrize("cause", ["repository", "repository-id", "pull-number", "pull-node", "partial-binding", "noncanonical-head"])
def test_retry_rejects_inconsistent_bound_context_before_provider_reads(cause):
    from dataclasses import replace
    context = replace(CONTEXT, base_ref="main", repository="owner/repo", repository_id=17,
        pull_request_number=7, pull_request_node_id="PR_exact7", provider_head_sha=HEAD)
    changes = {"repository": {"repository": "other/repo"}, "repository-id": {"repository_id": 99},
               "pull-number": {"pull_request_number": 8}, "pull-node": {"pull_request_node_id": "PR_changed8"},
               "partial-binding": {"provider_head_sha": None}, "noncanonical-head": {"provider_head_sha": HEAD + " "}}
    provider = Provider(); frontier = _resolve(provider)
    provider.pull_request = lambda *_a, **_k: pytest.fail("provider read preceded invalid binding rejection")
    with pytest.raises(ProspectiveValidationError, match="bound context"):
        _execute(provider, frontier, context=replace(context, **changes[cause]))
    assert provider.reruns == []


def test_retry_preserves_exact_bound_default_context():
    from dataclasses import replace
    context = replace(CONTEXT, base_ref="main", repository="owner/repo", repository_id=17,
        pull_request_number=7, pull_request_node_id="PR_exact7", provider_head_sha=HEAD)
    provider = Provider(); frontier = _resolve(provider)
    assert _execute(provider, frontier, context=context) is True
    assert provider.reruns == [31]
