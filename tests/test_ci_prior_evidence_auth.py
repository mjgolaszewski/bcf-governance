"""Trusted finalizer accepts only exact same-admission transport custody."""

from __future__ import annotations

import hashlib
from io import BytesIO
import json
import zipfile

import pytest

from bcf_governance.tooling.ci_github_artifacts import ProviderArtifact
from bcf_governance.tooling.ci_github_bundle import canonical_json
from bcf_governance.tooling.ci_github_identity import GitHubControllerError, MainIdentity
from bcf_governance.tooling import ci_prior_evidence_auth as target


MAIN = MainIdentity(
    repository_id="1207503211", default_branch="main",
    checkout_sha="a" * 40, tree_sha="b" * 40,
)


def _transport(*, altered: str = "") -> tuple[bytes, dict]:
    receipt = b'{"evidence_id":"source"}'
    payload: dict[str, bytes] = {}
    artifacts = []
    for artifact_id, role in (("123", "evidence"), ("124", "session"),
                              ("125", "truth"), ("126", "certification")):
        archive = f"{role} archive".encode()
        member_path = "test/test.evidence.json" if role == "evidence" else f"{role}.json"
        member = receipt if role == "evidence" else b"{}"
        payload[f"archives/{artifact_id}.zip"] = archive
        payload[f"expanded/{artifact_id}/{member_path}"] = member
        artifacts.append({
            "artifact_id": artifact_id, "name": f"source-{role}", "role": role,
            "provider_digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "files": [{"path": member_path, "sha256": hashlib.sha256(member).hexdigest(),
                       "size": len(member)}],
        })
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in payload.items()}
    candidate = {"commit_sha": "c" * 40, "tree_sha": MAIN.tree_sha}
    main_subject = {"commit_sha": MAIN.checkout_sha, "tree_sha": MAIN.tree_sha}
    manifest = {
        "schema_version": "1.0", "kind": "prior_evidence_transport",
        "repository": {"provider": "github", "full_name": "owner/repo", "repository_id": MAIN.repository_id},
        "pull_request": 42, "candidate": candidate, "main": main_subject,
        "merge": {"commit_sha": MAIN.checkout_sha, "base_branch": "main",
                  "merged_at": "2026-09-22T00:00:00Z", "merged_by": "human",
                  "candidate_tree_equals_main_tree": True},
        "producer": {"run_id": "900", "run_attempt": 1,
                     "workflow": {"path": ".github/workflows/governance.yml",
                                  "workflow_id": "901", "definition_commit": "d" * 40,
                                  "definition_sha256": "e" * 64}},
        "certification": {"context": "bcf/pr-certification", "app_id": 15368,
                          "check_run_id": "902", "finalizer_run_id": "903",
                          "finalizer_run_attempt": 1, "completed_at": "2026-09-22T00:00:00Z"},
        "authority": {"controller_commit_sha": "f" * 40,
                      "controller_bundle_sha256": "1" * 64},
        "protection": {"provider_state": "clean", "bypass_actors": [],
                       "required_context": "bcf/pr-certification", "publisher_app_id": 15368,
                       "declaration_sha256": "2" * 64, "ruleset_id": "904"},
        "bundle_sha256": hashlib.sha256(canonical_json(hashes)).hexdigest(),
        "artifacts": artifacts,
        "receipts": [{"evidence_id": "source", "artifact_id": "123",
                      "artifact_name": "source-evidence", "path": "test/test.evidence.json",
                      "receipt_sha256": hashes["expanded/123/test/test.evidence.json"],
                      "immutable_reference": "github-actions://owner/repo/runs/900/attempts/1/artifacts/123/test/test.evidence.json"}],
        "authenticated_at": "2026-09-22T00:00:00Z",
    }
    if altered == "wrong_main":
        manifest["main"]["tree_sha"] = "0" * 40
    if altered == "bypass":
        manifest["protection"]["bypass_actors"] = [{"actor_id": 1}]
    if altered == "wrong_reference":
        manifest["receipts"][0]["immutable_reference"] = "github-actions://wrong"
    if altered == "wrong_evidence_id":
        manifest["receipts"][0]["evidence_id"] = "other"
    if altered == "archive_provider_digest":
        manifest["artifacts"][0]["provider_digest"] = "sha256:" + "0" * 64
    if altered == "missing_member":
        payload.pop("expanded/123/test/test.evidence.json")
    payload["prior-evidence-transport.json"] = canonical_json(manifest)
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, raw in sorted(payload.items()):
            archive.writestr(path, raw)
    return stream.getvalue(), manifest


def _provider(monkeypatch: pytest.MonkeyPatch, raw: bytes, *, wrong_digest: bool = False):
    expected_digest = "0" * 64 if wrong_digest else hashlib.sha256(raw).hexdigest()
    artifact = ProviderArtifact(
        run_id="1234", run_attempt=1, artifact_id="5678",
        artifact_name="bcf-prior-evidence-transport-1234-1",
        provider_digest="sha256:" + expected_digest, workflow={},
    )
    calls = []

    def resolve(_api, **kwargs):
        calls.append(kwargs)
        return artifact

    monkeypatch.setattr(target, "resolve_role_artifact", resolve)

    class API:
        def artifact_bytes(self, repository, artifact_id, *, maximum_bytes):
            assert (repository, artifact_id) == ("owner/repo", "5678")
            assert maximum_bytes == 104_857_600
            return raw

    return API(), calls


def test_trusted_transport_is_bound_to_admission_and_exact_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw, manifest = _transport()
    api, calls = _provider(monkeypatch, raw)
    result = target.authenticate_prior_transport(
        api, repository="owner/repo", main=MAIN, authority={},
        run_id="1234", run_attempt=1,
    )
    assert result.manifest == manifest
    assert calls[0]["role"] == "admission"
    assert calls[0]["artifact_name"] == "bcf-prior-evidence-transport-1234-1"
    assert calls[0]["run_attempt"] == 1


@pytest.mark.parametrize("altered", [
    "wrong_main", "bypass", "missing_member", "wrong_reference",
    "wrong_evidence_id", "archive_provider_digest",
])
def test_trusted_transport_rejects_subject_protection_or_inventory_mismatch(
    monkeypatch: pytest.MonkeyPatch, altered: str,
) -> None:
    raw, _ = _transport(altered=altered)
    api, _ = _provider(monkeypatch, raw)
    with pytest.raises(GitHubControllerError):
        target.authenticate_prior_transport(
            api, repository="owner/repo", main=MAIN, authority={},
            run_id="1234", run_attempt=1,
        )


def test_trusted_transport_rejects_provider_digest_substitution(monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _transport()
    api, _ = _provider(monkeypatch, raw, wrong_digest=True)
    with pytest.raises(GitHubControllerError, match="provider digest"):
        target.authenticate_prior_transport(
            api, repository="owner/repo", main=MAIN, authority={},
            run_id="1234", run_attempt=1,
        )
