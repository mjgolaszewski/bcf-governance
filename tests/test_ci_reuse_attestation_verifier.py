"""Candidate reuse assertions need same-admission trusted recomputation."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from io import BytesIO
import json
from types import SimpleNamespace
import zipfile

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
    monkeypatch.setattr(
        verifier, "_same_admission_plan",
        lambda *_args, **_kwargs: ({
            "session_id": "a" * 32,
            "required_claims": ["app-valid"],
            "preflight_satisfied_claims": [],
            "reused_evidence": [{
                "claim_id": "app-valid",
                "evidence_id": decisions[0]["source_receipt"]["evidence_id"],
                "artifact_sha256": "b" * 64,
                "reason": "dependency fingerprints remain applicable",
            }],
        }, "c" * 64),
    )

    class API:
        def run(self, repository, run_id):
            assert (repository, run_id) == ("owner/repo", "1234")
            return {"id": 1234, "run_attempt": 1, "head_sha": main.checkout_sha,
                    "created_at": "2026-09-22T00:00:00Z",
                    "updated_at": "2026-09-22T00:10:00Z"}

    return root, main, decisions, API()


def _report(decisions):
    return {
        "reuse_attestations": decisions,
        "reuse_session_binding": {
            "session_id": "a" * 32, "manifest_sha256": "c" * 64,
        },
        "advisory_metrics": {"reused_claims": 1},
    }


def test_trusted_verifier_accepts_only_recomputed_same_admission_claim(tmp_path, monkeypatch) -> None:
    root, main, decisions, api = _subject(tmp_path, monkeypatch)
    result = verifier.verify_same_admission_reuse(
        api, repository="owner/repo", main=main, authority={},
        run_id="1234", run_attempt=1,
        truth_report=_report(decisions),
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
            truth_report=_report(forged),
            repo_root=root,
        )


def test_trusted_verifier_rejects_plan_count_laundering(tmp_path, monkeypatch) -> None:
    root, main, decisions, api = _subject(tmp_path, monkeypatch)
    with pytest.raises(GitHubControllerError, match="claim count differs"):
        verifier.verify_same_admission_reuse(
            api, repository="owner/repo", main=main, authority={},
            run_id="1234", run_attempt=1,
            truth_report={**_report(decisions), "advisory_metrics": {"reused_claims": 0}},
            repo_root=root,
        )


def test_trusted_verifier_rejects_missing_session_binding(tmp_path, monkeypatch) -> None:
    root, main, decisions, api = _subject(tmp_path, monkeypatch)
    report = _report(decisions)
    del report["reuse_session_binding"]
    with pytest.raises(GitHubControllerError, match="exact evidence session"):
        verifier.verify_same_admission_reuse(
            api, repository="owner/repo", main=main, authority={},
            run_id="1234", run_attempt=1, truth_report=report, repo_root=root,
        )


def test_trusted_verifier_rejects_skipped_claim_not_in_attestations(
    tmp_path, monkeypatch,
) -> None:
    root, main, decisions, api = _subject(tmp_path, monkeypatch)
    monkeypatch.setattr(
        verifier, "_same_admission_plan",
        lambda *_args, **_kwargs: ({
            "session_id": "a" * 32,
            "required_claims": ["app-valid", "other-claim"],
            "preflight_satisfied_claims": [],
            "reused_evidence": [
                {"claim_id": "app-valid", "evidence_id": decisions[0]["source_receipt"]["evidence_id"],
                 "artifact_sha256": "b" * 64, "reason": "dependency fingerprints remain applicable"},
                {"claim_id": "other-claim", "evidence_id": "source-other",
                 "artifact_sha256": "b" * 64, "reason": "dependency fingerprints remain applicable"},
            ],
        }, "c" * 64),
    )
    with pytest.raises(GitHubControllerError, match="complete skipped-claim plan"):
        verifier.verify_same_admission_reuse(
            api, repository="owner/repo", main=main, authority={},
            run_id="1234", run_attempt=1, truth_report=_report(decisions),
            repo_root=root,
        )


def test_trusted_session_plan_is_exact_provider_attempt_and_inventory(monkeypatch) -> None:
    session = {
        "schema_version": "2.0", "session_id": "a" * 32,
        "subject": {"commit_sha": "b" * 40, "tree_sha": "c" * 40},
        "profile": "standard", "profile_contract_version": "3.0",
        "producer": {
            "kind": "workflow", "provider": "github-actions",
            "repository": "owner/repo", "repository_id": "123",
            "run_id": "1234", "run_attempt": "1", "producer_id": "preflight",
        },
        "expected_gate_inventory": ["test"],
        "expected_producer_inventory": ["evidence"],
        "prior_subject": None, "changed_paths": [], "changed_domains": [],
        "required_claims": ["app-valid"], "preflight_satisfied_claims": [],
        "reused_evidence": [], "invalidated_evidence": [],
        "execution_dag": {"nodes": [{"producer": "test"}], "edges": []},
        "decision_explanations": [], "created_at": EMITTED,
        "session_root_policy": {
            "mode": "0700", "root_kind": "ignored_repository",
            "immutable_manifest": True,
        },
    }

    def archive(value, *, path=None):
        encoded = json.dumps(value, sort_keys=True).encode()
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as bundle:
            bundle.writestr(path or f"{value['session_id']}/evidence-session.json", encoded)
        return stream.getvalue(), hashlib.sha256(encoded).hexdigest()

    raw, manifest_digest = archive(session)
    artifact = SimpleNamespace(
        artifact_id="77", provider_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )
    monkeypatch.setattr(verifier, "resolve_role_artifact", lambda *_args, **_kwargs: artifact)

    class API:
        def artifact_bytes(self, repository, artifact_id, *, maximum_bytes):
            assert (repository, artifact_id) == ("owner/repo", "77")
            assert maximum_bytes <= 8_000_000
            return raw

    main = SimpleNamespace(checkout_sha="b" * 40, tree_sha="c" * 40,
                           repository_id="123")
    assert verifier._same_admission_plan(
        API(), repository="owner/repo", main=main, authority={},
        run_id="1234", run_attempt=1,
    ) == (session, manifest_digest)

    for mutation in ("wrong_subject", "wrong_attempt", "wrong_inventory", "wrong_path"):
        forged = deepcopy(session)
        if mutation == "wrong_subject":
            forged["subject"]["commit_sha"] = "d" * 40
        elif mutation == "wrong_attempt":
            forged["producer"]["run_attempt"] = "2"
        elif mutation == "wrong_inventory":
            forged["expected_gate_inventory"] = []
        raw, _ = archive(
            forged,
            path="other/evidence-session.json" if mutation == "wrong_path" else None,
        )
        artifact.provider_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        with pytest.raises(GitHubControllerError):
            verifier._same_admission_plan(
                API(), repository="owner/repo", main=main, authority={},
                run_id="1234", run_attempt=1,
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
