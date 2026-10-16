from __future__ import annotations

from contextlib import contextmanager, nullcontext
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
    monkeypatch.setattr(submit, "_normalize_submission", lambda *_a, **_k: None, raising=False)
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
    context, identity = _state(monkeypatch)
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
        lambda *_a, **kwargs: observed.append(kwargs) or True,
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
    assert len(observed) == 1
    assert observed[0]["frontier"] is frontier
    assert observed[0]["candidate"] == identity
    assert observed[0]["context"] == context
    assert observed[0]["pull_request"] == result["pull_request"]


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


def _normalization_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(submit, 'validate_authored_test_reference_inventories', lambda *_a, **_k: None)
    monkeypatch.setattr(submit, 'local_gate_lease', lambda *_a: nullcontext(), raising=False)


def test_submit_normalizes_before_capturing_the_proved_subject(monkeypatch, tmp_path):
    context, old = _state(monkeypatch)
    fresh = CandidateIdentity('4' * 40, '5' * 40, context.base_sha)
    identities = iter([old, fresh])
    trace = []
    monkeypatch.setattr(submit, '_candidate_identity', lambda *_a, **_k: next(identities))
    monkeypatch.setattr(submit, '_normalize_submission', lambda *_a, **_k: trace.append('normalize'))
    monkeypatch.setattr(submit, '_confirm_unchanged', lambda *_a, **_k: None)
    monkeypatch.setattr(submit, 'run_prospective_train', lambda *_a, **kw: trace.append(('prove', kw['subject_commit'])) or {'status': 'prospectively_admissible_provider_proof_required'})
    def runner(argv, **_kwargs):
        trace.append(('push', argv[3]))
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    result = submit.submit_candidate(tmp_path, python_executable=Path('/python'), provider_api=object(), runner=runner)
    assert trace == ['normalize', ('prove', fresh.commit_sha), ('push', fresh.commit_sha + ':refs/heads/feature')]
    assert result['subject'] == fresh.as_dict()


def test_fixed_point_submit_normalization_does_not_generate(monkeypatch, tmp_path):
    _normalization_state(monkeypatch)
    trace = []
    def runner(argv, **_kwargs):
        trace.append(argv[-1])
        assert argv[-1] == '--check'
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None, runner=runner)
    assert trace == ['--check']


def test_dirty_submit_uses_canonical_normalization_then_rechecks(monkeypatch, tmp_path):
    _normalization_state(monkeypatch)
    trace = []
    def runner(argv, **_kwargs):
        assert 'reconcile' in argv and '-I' in argv
        assert ('--commit-derived' in argv) is (argv[-1] == '--apply')
        trace.append(argv[-1])
        return SimpleNamespace(returncode=1 if len(trace) == 1 else 0, stdout='', stderr='stale scope' if len(trace) == 1 else '')
    submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None, runner=runner)
    assert trace == ['--check', '--apply', '--check']


def test_normalization_failure_cannot_continue_to_proof_or_push(monkeypatch, tmp_path):
    _state(monkeypatch)
    def fail(*_args, **_kwargs):
        raise ProspectiveValidationError('normalization failed')
    monkeypatch.setattr(submit, '_normalize_submission', fail)
    monkeypatch.setattr(submit, 'run_prospective_train', lambda *_a, **_k: pytest.fail('unproved continuation'))
    with pytest.raises(ProspectiveValidationError, match='normalization failed'):
        submit.submit_candidate(tmp_path, python_executable=Path('/python'), provider_api=object(), runner=lambda *_a, **_k: pytest.fail('push after failed normalization'))


def test_authored_contradiction_rejects_before_any_normalization(monkeypatch, tmp_path):
    from bcf_governance.tooling.governance_validation.authored_phase_state import AuthoredPhaseStateError
    _normalization_state(monkeypatch)
    (tmp_path / 'plans').mkdir()
    (tmp_path / 'plans/phase-ledger.yml').write_text('{}')
    def reject(*_args):
        raise AuthoredPhaseStateError('authored contradiction')
    monkeypatch.setattr(submit, 'validate_authored_phase_state', reject, raising=False)
    with pytest.raises(ProspectiveValidationError, match='authored contradiction'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None, runner=lambda *_a, **_k: pytest.fail('mutated contradiction'))


def test_wrong_intent_assertion_cannot_generate(monkeypatch, tmp_path):
    _normalization_state(monkeypatch)
    monkeypatch.setattr(submit, 'authored_post_merge_scope', lambda *_a: ('pr', None), raising=False)
    with pytest.raises(ProspectiveValidationError, match='intent'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent='closure', runner=lambda *_a, **_k: pytest.fail('mutated wrong intent'))


def test_busy_submit_cannot_normalize_another_active_train(monkeypatch, tmp_path):
    from bcf_governance.tooling.local_execution_admission import LocalExecutionAdmissionError
    _normalization_state(monkeypatch)
    @contextmanager
    def busy(*_args):
        raise LocalExecutionAdmissionError('local_execution_busy_deferred')
        yield
    monkeypatch.setattr(submit, 'local_gate_lease', busy)
    with pytest.raises(LocalExecutionAdmissionError, match='busy_deferred'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None, runner=lambda *_a, **_k: pytest.fail('mutated busy train'))


def test_failed_canonical_apply_cannot_report_normalized(monkeypatch, tmp_path):
    _normalization_state(monkeypatch)
    trace = []
    def runner(argv, **_kwargs):
        trace.append(argv[-1])
        return SimpleNamespace(returncode=1, stdout='', stderr='partial normalization')
    with pytest.raises(ProspectiveValidationError, match='partial normalization'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None, runner=runner)
    assert trace == ['--check', '--apply']


def test_partial_canonical_apply_requires_a_verified_fixed_point(monkeypatch, tmp_path):
    _normalization_state(monkeypatch)
    trace = []
    def runner(argv, **_kwargs):
        trace.append(argv[-1])
        return SimpleNamespace(returncode=0 if argv[-1] == '--apply' else 1, stdout='', stderr='still dirty')
    with pytest.raises(ProspectiveValidationError, match='did not converge'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None, runner=runner)
    assert trace == ['--check', '--apply', '--check']


def test_submit_forwards_existing_progress_without_conferring_authority(monkeypatch, tmp_path):
    from bcf_governance.tooling.operational_observations import progress_event

    _, identity = _state(monkeypatch)
    event = progress_event(execution_id=identity.commit_sha, sequence=1, stage='evidence', state='started', monotonic_ms=0)
    received = []
    def incomplete_proof(*_args, **kwargs):
        kwargs['progress_sink'](event)
        return {'status': 'incomplete'}
    monkeypatch.setattr(submit, 'run_prospective_train', incomplete_proof)
    with pytest.raises(ProspectiveValidationError, match='complete prospective proof'):
        submit.submit_candidate(tmp_path, python_executable=Path('/python'), provider_api=object(), progress_sink=received.append,
                                runner=lambda *_a, **_k: pytest.fail('incomplete progress must not push'))
    assert received[-1] is event
    assert received[4:] == [event]
    assert [e for e in received if e["kind"] == "prospective_progress"] == [event]
    assert all(e["kind"] == "submission_progress" for e in received[:4])
    assert [(e['stage'], e['state']) for e in received[:4]] == [
        ('normalization', 'started'), ('normalization', 'complete'),
        ('submission_authority', 'started'), ('submission_authority', 'complete')]
    assert all(e['authority'] is False for e in received)

    assert received[0]['authority'] is False


def test_submit_cli_keeps_progress_on_stderr_and_result_on_stdout(monkeypatch, tmp_path, capsys):
    import json
    from bcf_governance.tooling import ci_commands, ci_github_controller
    from bcf_governance.tooling.operational_observations import progress_event

    event = progress_event(execution_id='a' * 40, sequence=1, stage='evidence', state='started', monotonic_ms=0)
    result = {'status': 'submitted', 'subject': {'commit_sha': 'a' * 40}}
    monkeypatch.setattr(ci_commands, 'ensure_local_project_python', lambda *_a, **_k: Path('/python'))
    monkeypatch.setattr(ci_github_controller, 'environment_api', lambda: object())
    def observed_submit(*_args, **kwargs):
        kwargs['progress_sink'](event)
        return result
    monkeypatch.setattr(ci_commands, 'submit_candidate', observed_submit)
    ci_commands.main(['submit', '--repo-root', str(tmp_path), '--format', 'json'])
    captured = capsys.readouterr()
    assert json.loads(captured.out) == result
    assert json.loads(captured.err) == event


@pytest.mark.parametrize('defect', ['missing_target', 'partial_owner'])
def test_submit_release_contradiction_rejects_before_lease_or_reconcile(monkeypatch, tmp_path, defect):
    (tmp_path / 'manifest.yml').write_text('document:\n  version: 2.5.0\n')
    if defect == 'missing_target':
        (tmp_path / 'governance').mkdir()
        (tmp_path / 'governance/public-contracts.yml').write_text('package:\n  version: 2.5.0\n')
        (tmp_path / 'CHANGELOG.md').write_text('# Changelog\n\n## [Unreleased]\n')
    monkeypatch.setattr(submit, 'local_gate_lease', lambda *_a: pytest.fail('authored contradiction acquired lease'))
    with pytest.raises(ProspectiveValidationError, match='release'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None,
                                     runner=lambda *_a, **_k: pytest.fail('authored contradiction reached reconciliation'))


def test_submit_invalid_runtime_version_rejects_before_admission(monkeypatch, tmp_path):
    def malformed():
        raise RuntimeError('BCF runtime version owner is malformed')
    monkeypatch.setattr(submit, 'executing_runtime_version', malformed, raising=False)
    monkeypatch.setattr(submit, 'local_gate_lease', lambda *_a: pytest.fail('invalid runtime acquired lease'))
    with pytest.raises(ProspectiveValidationError, match='runtime version'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None,
                                     runner=lambda *_a, **_k: pytest.fail('invalid runtime reached reconciliation'))


def test_submit_valid_release_target_uses_the_existing_fixed_point_check(monkeypatch, tmp_path):
    version = submit.executing_runtime_version()
    (tmp_path / 'manifest.yml').write_text(f'document:\n  version: {version}\n')
    (tmp_path / 'governance').mkdir()
    (tmp_path / 'governance/public-contracts.yml').write_text(f'package:\n  version: {version}\n')
    (tmp_path / 'CHANGELOG.md').write_text(f'# Changelog\n\n## [Unreleased]\n\nRelease target: `{version}`\n')
    _normalization_state(monkeypatch)
    calls = []
    def runner(argv, **_kwargs):
        calls.append(argv[-1])
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None, runner=runner)
    assert calls == ['--check']


def test_submit_authored_machine_rejects_before_lease_or_reconcile(monkeypatch, tmp_path):
    from bcf_governance.tooling.governance_validation.ci_state_matrix import CIStateMatrixError

    def reject(_root, **_kwargs):
        raise CIStateMatrixError("machine-readable authored contradiction")

    monkeypatch.setattr(submit, "validate_ci_state_matrix", reject, raising=False)
    monkeypatch.setattr(submit, "local_gate_lease", lambda *_a: pytest.fail("authored machine contradiction acquired lease"))
    with pytest.raises(ProspectiveValidationError, match="machine-readable authored contradiction"):
        submit._normalize_submission(tmp_path, python_executable=Path("/python"), execution_id="2" * 40, semantic_intent=None,
                                     runner=lambda *_a, **_k: pytest.fail("authored machine contradiction reached reconciliation"))



@pytest.mark.parametrize('defect', ['null_policy', 'null_timeout', 'dangling_symlink'])
def test_submit_timeout_policy_rejects_before_lease_or_reconcile(monkeypatch, tmp_path, defect):
    governance = tmp_path / 'governance'
    governance.mkdir()
    path = governance / 'gate-contracts.yml'
    if defect == 'dangling_symlink':
        path.symlink_to(tmp_path / 'absent-timeouts.yml')
    elif defect == 'null_policy':
        path.write_text('execution_policy: null\n')
    else:
        path.write_text('gates: {example: {invocation: {timeout_seconds: null}}}\n')
    monkeypatch.setattr(submit, 'local_gate_lease', lambda *_a: pytest.fail('invalid timeout acquired lease'))
    with pytest.raises(ProspectiveValidationError, match='timeout|regular nonsymlink'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None,
                                     runner=lambda *_a, **_k: pytest.fail('invalid timeout reached reconciliation'))


def test_submit_valid_timeout_policy_keeps_fixed_point_owner(monkeypatch, tmp_path):
    governance = tmp_path / 'governance'
    governance.mkdir()
    (governance / 'gate-contracts.yml').write_text('execution_policy: {default_timeout_seconds: 2400}\n')
    _normalization_state(monkeypatch)
    calls = []
    def runner(argv, **_kwargs):
        calls.append(argv[-1])
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2' * 40, semantic_intent=None, runner=runner)
    assert calls == ['--check']


@pytest.mark.parametrize('stage', ['normalization', 'submission_authority'])
@pytest.mark.parametrize('error_type', [ValueError, OSError])
def test_submission_progress_retains_failed_stage_and_identical_error(monkeypatch, tmp_path, stage, error_type):
    _, identity = _state(monkeypatch)
    events = []
    failure = error_type('exact submission cause')
    def fail(*_args, **_kwargs):
        raise failure
    monkeypatch.setattr(submit, '_normalize_submission' if stage == 'normalization' else '_canonical_inputs', fail)
    monkeypatch.setattr(submit, 'run_prospective_train', lambda *_a, **_k: pytest.fail('continued after failure'))
    with pytest.raises(error_type) as caught:
        submit.submit_candidate(tmp_path, python_executable=Path('/python'), provider_api=object(),
            progress_sink=events.append, runner=lambda *_a, **_k: pytest.fail('mutation after failed admission'))
    assert caught.value is failure
    expected = [] if stage == 'normalization' else [('normalization', 'started'), ('normalization', 'complete')]
    assert [(e['stage'], e['state']) for e in events] == expected + [(stage, 'started'), (stage, 'failed')]
    assert {e['execution_id'] for e in events} == {'submission:' + identity.commit_sha}
    from bcf_governance.tooling.operational_observations import validate_progress_stream
    validate_progress_stream(events)


def test_submission_progress_separates_initial_and_normalized_subject_streams(monkeypatch, tmp_path):
    from bcf_governance.tooling.operational_observations import progress_event, validate_progress_stream
    context, initial = _state(monkeypatch)
    fresh = CandidateIdentity('4' * 40, '5' * 40, context.base_sha)
    identities = iter([initial, fresh])
    events, trace = [], []
    monkeypatch.setattr(submit, '_candidate_identity', lambda *_a, **_k: next(identities))
    monkeypatch.setattr(submit, '_normalize_submission', lambda *_a, **_k: trace.append('normalize'))
    authority = submit._canonical_inputs
    def inputs(*args, **kwargs):
        trace.append('authority')
        return authority(*args, **kwargs)
    monkeypatch.setattr(submit, '_canonical_inputs', inputs)
    def prospective(*_args, **kwargs):
        trace.append('prospective')
        assert kwargs['subject_commit'] == fresh.commit_sha
        kwargs['progress_sink'](progress_event(execution_id=fresh.commit_sha, sequence=1,
            stage='fixed_point', state='started', monotonic_ms=0))
        return {'status': 'incomplete'}
    monkeypatch.setattr(submit, 'run_prospective_train', prospective)
    def sink(event):
        events.append(event)
        trace.append((event['stage'], event['state']))
    with pytest.raises(ProspectiveValidationError, match='complete prospective proof'):
        submit.submit_candidate(tmp_path, python_executable=Path('/python'), provider_api=object(),
            progress_sink=sink, runner=lambda *_a, **_k: pytest.fail('pushed incomplete proof'))
    assert trace == [('normalization', 'started'), 'normalize', ('normalization', 'complete'),
        ('submission_authority', 'started'), 'authority', ('submission_authority', 'complete'),
        'prospective', ('fixed_point', 'started')]
    assert {e['execution_id'] for e in events[:4]} == {'submission:' + initial.commit_sha}
    assert events[-1]['execution_id'] == fresh.commit_sha
    validate_progress_stream(events[:4])
    validate_progress_stream(events[4:])


@pytest.mark.parametrize('stage', ['normalization', 'submission_authority'])
def test_submission_progress_sink_failure_cannot_replace_operation_failure(monkeypatch, tmp_path, stage):
    _state(monkeypatch)
    failure, sink_failure = ValueError('original operation failure'), RuntimeError('failed diagnostic sink')
    def fail(*_args, **_kwargs):
        raise failure
    monkeypatch.setattr(submit, '_normalize_submission' if stage == 'normalization' else '_canonical_inputs', fail)
    def sink(event):
        if event['state'] == 'failed':
            raise sink_failure
    with pytest.raises(ValueError) as caught:
        submit.submit_candidate(tmp_path, python_executable=Path('/python'), provider_api=object(), progress_sink=sink)
    assert caught.value is failure
    assert caught.value.__cause__ is sink_failure


@pytest.mark.parametrize('stage', ['normalization', 'submission_authority'])
@pytest.mark.parametrize('state', ['started', 'complete'])
def test_submission_progress_sink_failure_stops_before_next_authority_boundary(monkeypatch, tmp_path, stage, state):
    _state(monkeypatch)
    trace = []
    original_authority = submit._canonical_inputs
    monkeypatch.setattr(submit, '_normalize_submission', lambda *_a, **_k: trace.append('normalization'))
    def authority(*args, **kwargs):
        trace.append('submission_authority')
        return original_authority(*args, **kwargs)
    monkeypatch.setattr(submit, '_canonical_inputs', authority)
    monkeypatch.setattr(submit, 'run_prospective_train', lambda *_a, **_k: pytest.fail('continued after sink error'))
    failure = OSError('diagnostic output unavailable')
    def sink(event):
        if (event['stage'], event['state']) == (stage, state):
            raise failure
    with pytest.raises(OSError) as caught:
        submit.submit_candidate(tmp_path, python_executable=Path('/python'), provider_api=object(),
            progress_sink=sink, runner=lambda *_a, **_k: pytest.fail('pushed after diagnostic error'))
    assert caught.value is failure
    expected = [] if stage == 'normalization' else ['normalization']
    if state == 'complete':
        expected.append(stage)
    assert trace == expected


def test_authored_coverage_rejects_before_lease_reconciliation_and_provider(monkeypatch, tmp_path):
    from bcf_governance.tooling.test_manifests import TestManifestError
    _normalization_state(monkeypatch)
    def reject(root, *, python_executable):
        assert root == tmp_path and python_executable == Path('/python')
        raise TestManifestError('reference inventory contains bare parameterized selector')
    monkeypatch.setattr(submit, 'validate_authored_test_reference_inventories', reject, raising=False)
    monkeypatch.setattr(submit, 'local_gate_lease', lambda *_a: pytest.fail('leased before coverage check'))
    with pytest.raises(ProspectiveValidationError, match='reference inventory contains bare'):
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2'*40,
            semantic_intent=None, runner=lambda *_a, **_k: pytest.fail('reconciled invalid inventory'))


def test_authored_semantic_ownership_rejects_before_lease_and_reconciliation(monkeypatch, tmp_path):
    from bcf_governance.tooling.semantic_ownership_registry import SemanticOwnershipRegistryError
    _normalization_state(monkeypatch)
    failure = SemanticOwnershipRegistryError('authored semantic ownership failed: downstream_normalization:retry')
    def reject(*_a, **_k):
        raise failure
    monkeypatch.setattr(submit, 'validate_authored_semantic_ownership', reject, raising=False)
    monkeypatch.setattr(submit, 'local_gate_lease', lambda *_a: pytest.fail('leased before source ownership rejection'))
    with pytest.raises(ProspectiveValidationError, match='downstream_normalization') as caught:
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2'*40,
            semantic_intent=None, runner=lambda *_a, **_k: pytest.fail('reconciled invalid source ownership'))
    assert caught.value.__cause__ is failure


def test_authored_source_distribution_rejects_before_lease_and_reconciliation(monkeypatch, tmp_path):
    _normalization_state(monkeypatch)
    failure = ValueError('source manifest omits governed audit collector')
    def reject(root, *, python_executable):
        assert root == tmp_path and python_executable == Path('/python')
        raise failure
    monkeypatch.setattr(submit, 'validate_source_distribution', reject)
    monkeypatch.setattr(submit, 'local_gate_lease', lambda *_a: pytest.fail('leased before source declaration rejection'))
    with pytest.raises(ProspectiveValidationError, match='source manifest omits') as caught:
        submit._normalize_submission(tmp_path, python_executable=Path('/python'), execution_id='2'*40,
            semantic_intent=None, runner=lambda *_a, **_k: pytest.fail('reconciled invalid source declaration'))
    assert caught.value.__cause__ is failure
