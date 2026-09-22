"""Candidate reuse assertions need same-admission trusted recomputation."""

from __future__ import annotations

from copy import deepcopy

import pytest

from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.evidence_reuse_attestations import compose_reuse_attestations
from bcf_governance.tooling import ci_reuse_attestation_verifier as verifier
from tests.test_evidence_reuse_attestations import _fixture


EMITTED = "2026-09-22T00:01:00Z"


def _subject(tmp_path, monkeypatch):
    root, transport, main, contract, entries = _fixture(tmp_path)
    decisions, _ = compose_reuse_attestations(
        root, transport, main, contract, entries, ["app-valid"], emitted_at=EMITTED,
    )
    monkeypatch.setattr(verifier, "authenticate_prior_transport", lambda *_args, **_kwargs: transport)
    monkeypatch.setattr(
        verifier, "trusted_main_claim_context",
        lambda *_args, **_kwargs: (contract, entries, {}),
    )

    class API:
        def run(self, repository, run_id):
            assert (repository, run_id) == ("owner/repo", "1234")
            return {"id": 1234, "run_attempt": 1, "head_sha": main.checkout_sha,
                    "created_at": "2026-09-22T00:00:00Z",
                    "updated_at": "2026-09-22T00:10:00Z"}

    return root, main, decisions, API()


def test_trusted_verifier_accepts_only_recomputed_same_admission_claim(tmp_path, monkeypatch) -> None:
    root, main, decisions, api = _subject(tmp_path, monkeypatch)
    result = verifier.verify_same_admission_reuse(
        api, repository="owner/repo", main=main, authority={},
        run_id="1234", run_attempt=1,
        truth_report={"reuse_attestations": decisions, "advisory_metrics": {"reused_claims": 1}},
        repo_root=root,
    )
    assert result == ("app-valid",)


@pytest.mark.parametrize("mutation", [
    lambda values: values[0].update({"decision": "canonical_execution_required"}),
    lambda values: values[0]["main_subject"].update({"commit_sha": "0" * 40}),
    lambda values: values[0].update({"attestation_id": "0" * 64}),
    lambda values: values[0].update({"emitted_at": "2026-09-21T00:00:00Z"}),
])
def test_trusted_verifier_rejects_candidate_substitution(tmp_path, monkeypatch, mutation) -> None:
    root, main, decisions, api = _subject(tmp_path, monkeypatch)
    forged = deepcopy(decisions)
    mutation(forged)
    with pytest.raises(GitHubControllerError):
        verifier.verify_same_admission_reuse(
            api, repository="owner/repo", main=main, authority={},
            run_id="1234", run_attempt=1,
            truth_report={"reuse_attestations": forged, "advisory_metrics": {"reused_claims": 1}},
            repo_root=root,
        )


def test_trusted_verifier_rejects_plan_count_laundering(tmp_path, monkeypatch) -> None:
    root, main, decisions, api = _subject(tmp_path, monkeypatch)
    with pytest.raises(GitHubControllerError, match="claim count differs"):
        verifier.verify_same_admission_reuse(
            api, repository="owner/repo", main=main, authority={},
            run_id="1234", run_attempt=1,
            truth_report={"reuse_attestations": decisions,
                          "advisory_metrics": {"reused_claims": 0}}, repo_root=root,
        )


def test_dormant_finalizer_does_not_fetch_transport_without_reuse() -> None:
    class ForbiddenAPI:
        def run(self, *_args, **_kwargs):
            raise AssertionError("dormant reuse must not touch provider")

    assert verifier.verify_same_admission_reuse(
        ForbiddenAPI(), repository="owner/repo", main=None, authority={},
        run_id="1234", run_attempt=1, truth_report={}, repo_root=None,
    ) == ()
    with pytest.raises(GitHubControllerError, match="lacks a trusted attestation"):
        verifier.verify_same_admission_reuse(
            ForbiddenAPI(), repository="owner/repo", main=None, authority={},
            run_id="1234", run_attempt=1,
            truth_report={"advisory_metrics": {"reused_claims": 1}}, repo_root=None,
        )
