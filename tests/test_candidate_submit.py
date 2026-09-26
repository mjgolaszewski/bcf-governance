from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import ci_authority_submit as submit
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
        lambda *_a, **_k: ("workitem", "P28-P0-04", "owner/repo"),
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
        semantic_intent="workitem",
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
