from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import ci_authority_submit as submit
from bcf_governance.tooling.ci_graph_post_merge import authored_candidate_title
from bcf_governance.tooling.local_pr import (
    CandidateIdentity,
    LocalPRContext,
    ProspectiveValidationError,
)


def _state(monkeypatch: pytest.MonkeyPatch) -> tuple[LocalPRContext, CandidateIdentity]:
    context = LocalPRContext("origin", "main", "1" * 40, "2" * 40, "feature")
    identity = CandidateIdentity("2" * 40, "3" * 40, "1" * 40)
    monkeypatch.setattr(submit, "resolve_local_pr_context", lambda *_a, **_k: context)
    monkeypatch.setattr(submit, "_candidate_identity", lambda *_a, **_k: identity)
    monkeypatch.setattr(
        submit,
        "_canonical_inputs",
        lambda *_a, **_k: submit.SubmissionAuthority(
            mode="workitem",
            target="P28-P0-04",
            lane="direct_protected_main",
            repository="owner/repo",
            repository_id=17,
            protection_sha256="9" * 64,
        ),
    )
    monkeypatch.setattr(
        submit, "authored_candidate_title", lambda *_a, **_k: "candidate"
    )
    monkeypatch.setattr(
        submit,
        "ensure_candidate_pull_request",
        lambda *_a, **_k: {
            "number": 7,
            "node_id": "PR_exact7",
            "state": "open",
            "repository_id": 17,
            "base_sha": identity.base_sha,
            "head_sha": identity.commit_sha,
        },
    )
    monkeypatch.setattr(
        submit,
        "_request_protected_auto_merge",
        lambda *_a, **_k: (
            {"status": "enabled", "pull_request": 7},
            {"action": {"kind": "request_provider_auto_merge"}},
        ),
    )
    monkeypatch.setattr(
        submit,
        "resolve_candidate_provider_recovery",
        lambda *_a, **_k: {
            "operation": "candidate_provider",
            "action": {"kind": "observe_exact_provider_run"},
        },
    )
    monkeypatch.setattr(
        submit,
        "execute_candidate_provider_recovery",
        lambda *_a, **_k: False,
    )
    return context, identity


def test_submit_owns_prospective_train_then_pushes_only_proved_sha(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context, identity = _state(monkeypatch)
    trace: list[str] = []
    monkeypatch.setattr(
        submit,
        "run_prospective_train",
        lambda *_a, **kwargs: trace.append(
            f"prove:{kwargs['subject_commit']}:{kwargs['evaluation_target']}"
        )
        or {"status": "prospectively_admissible_provider_proof_required"},
    )
    monkeypatch.setattr(
        submit,
        "_confirm_unchanged",
        lambda *_a, **_k: trace.append("stable"),
    )

    def runner(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        trace.append(":".join(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result = submit.submit_candidate(
        tmp_path,
        python_executable=Path("/python"),
        provider_api=object(),  # type: ignore[arg-type]
        runner=runner,
    )
    assert trace == [
        f"prove:{identity.commit_sha}:P28-P0-04",
        "stable",
        f"git:push:{context.remote}:{identity.commit_sha}:refs/heads/{context.head_ref}",
    ]
    assert result["status"] == "submitted"
    assert result["subject"] == identity.as_dict()
    assert result["recovery_frontier"]["action"]["kind"] == "push_exact_candidate"
    assert result["recovery_frontier"]["release_authority"] is False
    assert result["pull_request"]["number"] == 7
    assert result["provider_retry_submitted"] is False


def test_submit_executes_only_the_recovery_frontier_selected_provider_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _state(monkeypatch)
    monkeypatch.setattr(
        submit,
        "run_prospective_train",
        lambda *_a, **_k: {
            "status": "prospectively_admissible_provider_proof_required"
        },
    )
    monkeypatch.setattr(submit, "_confirm_unchanged", lambda *_a, **_k: None)
    frontier = {
        "operation": "candidate_provider",
        "action": {"kind": "rerun_exact_provider_workflow"},
    }
    monkeypatch.setattr(
        submit, "resolve_candidate_provider_recovery", lambda *_a, **_k: frontier
    )
    observed: list[dict[str, object]] = []
    monkeypatch.setattr(
        submit,
        "execute_candidate_provider_recovery",
        lambda *_a, **kwargs: observed.append(kwargs["frontier"]) or True,
    )

    result = submit.submit_candidate(
        tmp_path,
        python_executable=Path("/python"),
        provider_api=object(),  # type: ignore[arg-type]
        runner=lambda *_a, **_k: SimpleNamespace(
            returncode=0, stdout="", stderr=""
        ),
    )

    assert result["status"] == "provider_retry_submitted"
    assert result["provider_retry_submitted"] is True
    assert observed == [frontier]


def test_submit_rejects_wrong_intent_before_proof_or_push(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _state(monkeypatch)
    monkeypatch.setattr(
        submit,
        "run_prospective_train",
        lambda *_a, **_k: pytest.fail("train ran for a mismatched intent"),
    )
    with pytest.raises(ProspectiveValidationError, match="intent does not match"):
        submit.submit_candidate(
            tmp_path,
            semantic_intent="closure",
            python_executable=Path("/python"),
            provider_api=object(),  # type: ignore[arg-type]
        )


def test_submit_accepts_derived_pr_progress_without_terminal_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context, identity = _state(monkeypatch)
    monkeypatch.setattr(
        submit,
        "_canonical_inputs",
        lambda *_a, **_k: submit.SubmissionAuthority(
            mode="pr",
            target=None,
            lane="direct_protected_main",
            repository="owner/repo",
            repository_id=17,
            protection_sha256="9" * 64,
        ),
    )
    observed: list[tuple[str, object]] = []
    monkeypatch.setattr(
        submit,
        "run_prospective_train",
        lambda *_a, **kwargs: observed.append(
            (kwargs["semantic_intent"], kwargs["evaluation_target"])
        )
        or {"status": "prospectively_admissible_provider_proof_required"},
    )
    monkeypatch.setattr(submit, "_confirm_unchanged", lambda *_a, **_k: None)

    result = submit.submit_candidate(
        tmp_path,
        semantic_intent="pr",
        python_executable=Path("/python"),
        provider_api=object(),  # type: ignore[arg-type]
        runner=lambda *_a, **_k: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    assert observed == [("pr", None)]
    assert result["subject"] == identity.as_dict()
    assert result["branch"] == context.head_ref


def test_submit_derives_phase_title_for_parallel_todo_progress(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _state(monkeypatch)
    monkeypatch.setattr(
        submit,
        "_canonical_inputs",
        lambda *_a, **_k: submit.SubmissionAuthority(
            mode="pr",
            target=None,
            lane="direct_protected_main",
            repository="owner/repo",
            repository_id=17,
            protection_sha256="9" * 64,
        ),
    )
    monkeypatch.setattr(submit, "authored_candidate_title", authored_candidate_title)
    (tmp_path / "plans").mkdir()
    (tmp_path / "plans/phase-ledger.yml").write_text(
        "active_phase:\n"
        "  id: P01\n"
        "  workitems: plans/phase-01-workitems.yml\n",
        encoding="utf-8",
    )
    (tmp_path / "plans/phase-01-workitems.yml").write_text(
        "workitems:\n"
        "- {id: P01-P0-01, status: DONE, summary: foundation}\n"
        "- {id: P01-P0-02, status: TODO, summary: parallel alpha}\n"
        "- {id: P01-P0-03, status: TODO, summary: parallel beta}\n",
        encoding="utf-8",
    )
    observed: list[str] = []
    monkeypatch.setattr(
        submit,
        "ensure_candidate_pull_request",
        lambda *_a, **kwargs: observed.append(kwargs["title"])
        or {
            "number": 7,
            "node_id": "PR_exact7",
            "state": "open",
            "base_sha": "1" * 40,
            "head_sha": "2" * 40,
            "repository_id": 17,
        },
    )
    monkeypatch.setattr(
        submit,
        "run_prospective_train",
        lambda *_a, **_k: {
            "status": "prospectively_admissible_provider_proof_required"
        },
    )
    monkeypatch.setattr(submit, "_confirm_unchanged", lambda *_a, **_k: None)

    submit.submit_candidate(
        tmp_path,
        semantic_intent="pr",
        python_executable=Path("/python"),
        provider_api=object(),  # type: ignore[arg-type]
        runner=lambda *_a, **_k: SimpleNamespace(
            returncode=0, stdout="", stderr=""
        ),
    )

    assert observed == ["P01: advance governed PR progress"]


def test_direct_main_submit_authenticates_repository_without_self_protection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "governance").mkdir()
    (tmp_path / "governance/ci-graph.yml").write_text(
        "document: {id: adopter}\n", encoding="utf-8"
    )
    context = LocalPRContext("origin", "main", "1" * 40, "2" * 40, "feature")
    monkeypatch.setattr(
        submit,
        "validate_ci_graph",
        lambda *_a, **_k: SimpleNamespace(graph={"document": {"id": "adopter"}}),
    )
    monkeypatch.setattr(
        submit,
        "post_merge_evaluation",
        lambda *_a, **_k: SimpleNamespace(
            mode="workitem", target="P07-P0-03", lane="direct_protected_main"
        ),
    )
    monkeypatch.setattr(
        submit,
        "load_protection",
        lambda *_a, **_k: pytest.fail("ordinary adopter loaded self protection"),
    )

    class Provider:
        def repository(self, repository: str) -> dict[str, object]:
            assert repository == "owner/adopter"
            return {"id": 17, "full_name": repository}

    def runner(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        assert argv == ["git", "remote", "get-url", "origin"]
        return SimpleNamespace(
            returncode=0,
            stdout="ssh://git@ssh.github.com:443/owner/adopter.git\n",
            stderr="",
        )

    authority = submit._canonical_inputs(
        tmp_path,
        context=context,
        provider_api=Provider(),  # type: ignore[arg-type]
        runner=runner,
    )
    assert authority.mode == "workitem"
    assert authority.target == "P07-P0-03"
    assert authority.lane == "direct_protected_main"
    assert authority.repository == "owner/adopter"
    assert authority.repository_id == 17
    assert len(authority.protection_sha256) == 64


def test_direct_main_protection_identity_is_closed_before_provider_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context = LocalPRContext("origin", "main", "1" * 40, "2" * 40, "feature")
    monkeypatch.setattr(
        submit,
        "validate_ci_graph",
        lambda *_a, **_k: SimpleNamespace(graph={"document": {"id": "adopter"}}),
    )
    monkeypatch.setattr(
        submit,
        "post_merge_evaluation",
        lambda *_a, **_k: SimpleNamespace(
            mode="workitem", target="P07-P0-03", lane="direct_protected_main"
        ),
    )

    class Provider:
        def repository(self, repository: str) -> dict[str, object]:
            return {"id": 17, "full_name": repository}

    with pytest.raises(ProspectiveValidationError, match="canonical graph identity"):
        submit._canonical_inputs(
            tmp_path,
            context=context,
            provider_api=Provider(),  # type: ignore[arg-type]
            runner=lambda *_a, **_k: SimpleNamespace(
                returncode=0,
                stdout="git@github.com:owner/adopter.git\n",
                stderr="",
            ),
        )


def test_direct_main_auto_merge_consumes_precompiled_authority_without_self_file(
    tmp_path: Path,
) -> None:
    identity = CandidateIdentity("2" * 40, "3" * 40, "1" * 40)
    authority = submit.SubmissionAuthority(
        mode="workitem",
        target="P07-P0-03",
        lane="direct_protected_main",
        repository="owner/adopter",
        repository_id=17,
        protection_sha256="9" * 64,
    )

    class Provider:
        def enable_pull_request_auto_merge(
            self,
            repository: str,
            number: int,
            *,
            node_id: str,
            expected_base_sha: str,
            expected_head_sha: str,
        ) -> dict[str, object]:
            assert repository == authority.repository
            assert (number, node_id, expected_base_sha, expected_head_sha) == (
                7,
                "PR_exact7",
                identity.base_sha,
                identity.commit_sha,
            )
            return {"status": "enabled"}

    result, frontier = submit._request_protected_auto_merge(
        provider_api=Provider(),  # type: ignore[arg-type]
        authority=authority,
        identity=identity,
        pull_request={
            "number": 7,
            "node_id": "PR_exact7",
            "repository_id": 17,
        },
        prospective_frontier_sha256="8" * 64,
    )

    assert result == {"status": "enabled"}
    assert frontier["identity"]["protection_sha256"] == "9" * 64
    assert not (tmp_path / "governance/github-protection.yml").exists()


def test_provider_clean_pr_selects_certified_mergeable_frontier_before_merge() -> None:
    identity = CandidateIdentity("2" * 40, "3" * 40, "1" * 40)
    authority = submit.SubmissionAuthority(
        mode="workitem",
        target="P07-P0-03",
        lane="direct_protected_main",
        repository="owner/adopter",
        repository_id=17,
        protection_sha256="9" * 64,
    )
    calls: list[str] = []

    class Provider:
        def enable_pull_request_auto_merge(self, *_args, **kwargs):
            assert kwargs["expected_base_sha"] == identity.base_sha
            assert kwargs["expected_head_sha"] == identity.commit_sha
            calls.append("classify")
            return {"status": "certified_clean", "pull_request": 7}

        def merge_clean_pull_request(self, *_args, **kwargs):
            assert calls == ["classify"]
            assert kwargs["expected_base_sha"] == identity.base_sha
            assert kwargs["expected_head_sha"] == identity.commit_sha
            calls.append("merge")
            return {
                "status": "merged",
                "pull_request": 7,
                "merge_commit_sha": "4" * 40,
            }

    result, frontier = submit._request_protected_auto_merge(
        provider_api=Provider(),  # type: ignore[arg-type]
        authority=authority,
        identity=identity,
        pull_request={
            "number": 7,
            "node_id": "PR_exact7",
            "repository_id": 17,
        },
        prospective_frontier_sha256="8" * 64,
    )

    assert result["status"] == "merged"
    assert calls == ["classify", "merge"]
    assert frontier["state"] == "certified_mergeable"
    assert frontier["action"]["kind"] == "merge_commit"


def test_direct_main_submit_rejects_remote_provider_disagreement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context = LocalPRContext("origin", "main", "1" * 40, "2" * 40, "feature")
    monkeypatch.setattr(
        submit,
        "validate_ci_graph",
        lambda *_a, **_k: SimpleNamespace(graph={"document": {"id": "adopter"}}),
    )
    monkeypatch.setattr(
        submit,
        "post_merge_evaluation",
        lambda *_a, **_k: SimpleNamespace(
            mode="workitem", target="P07-P0-03", lane="direct_protected_main"
        ),
    )

    class Provider:
        def repository(self, _repository: str) -> dict[str, object]:
            return {"id": 17, "full_name": "other/adopter"}

    with pytest.raises(ProspectiveValidationError, match="provider repository"):
        submit._canonical_inputs(
            tmp_path,
            context=context,
            provider_api=Provider(),  # type: ignore[arg-type]
            runner=lambda *_a, **_k: SimpleNamespace(
                returncode=0,
                stdout="git@github.com:owner/adopter.git\n",
                stderr="",
            ),
        )


def test_submit_never_pushes_after_failed_or_mutated_proof(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _state(monkeypatch)
    monkeypatch.setattr(
        submit,
        "run_prospective_train",
        lambda *_a, **_k: {"status": "prospectively_admissible_provider_proof_required"},
    )
    monkeypatch.setattr(
        submit,
        "_confirm_unchanged",
        lambda *_a, **_k: (_ for _ in ()).throw(
            ProspectiveValidationError("candidate changed")
        ),
    )
    with pytest.raises(ProspectiveValidationError, match="candidate changed"):
        submit.submit_candidate(
            tmp_path,
            semantic_intent="workitem",
            python_executable=Path("/python"),
            provider_api=object(),  # type: ignore[arg-type]
            runner=lambda *_a, **_k: pytest.fail("push ran after candidate mutation"),
        )


def test_submit_rejects_incomplete_proof_before_push(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _state(monkeypatch)
    monkeypatch.setattr(
        submit,
        "run_prospective_train",
        lambda *_a, **_k: {"status": "deterministic_front_door_pass"},
    )
    with pytest.raises(ProspectiveValidationError, match="complete prospective proof"):
        submit.submit_candidate(
            tmp_path,
            semantic_intent="workitem",
            python_executable=Path("/python"),
            provider_api=object(),  # type: ignore[arg-type]
            runner=lambda *_a, **_k: pytest.fail("push ran after incomplete proof"),
        )
