"""Finalization consumes a real normalized parent bundle through provider custody."""

from copy import deepcopy
import hashlib
from io import BytesIO
import json
import zipfile

from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_exact_main import finalize_exact_main
from tests.test_phase_closure_population import protected_population, phase_input, SHA_A, SHA_B  # noqa: F401


def test_child_finalizer_requires_and_consumes_normalized_parent_certificate(tmp_path, monkeypatch, protected_population):
    api, policy, _ = protected_population
    policy["plans/phase-ledger.yml"]["active_phase"].update(
        workitems="plans/phase-02-workitems.yml", log="phases/phase-02-log.yml",
    )
    api.lifecycle_documents.update({
        "plans/phase-02-workitems.yml": {"workitems": [{
            "id": "P02-W01", "status": "DONE", "acceptance": ["requires-phase-closure:P01"],
            "acceptance_evidence": ["test"],
        }]},
        "phases/phase-02-log.yml": {"document": {"status": "completed"}, "phase": {"id": "P02"}},
    })
    api.runs["200"] = {**deepcopy(api.runs["100"]), "id": 200, "head_sha": SHA_B}
    for reference in api.runs["200"]["referenced_workflows"]:
        reference["sha"] = SHA_B
    api.runs["500"] = {**deepcopy(api.runs["400"]), "id": 500, "head_sha": SHA_B,
                       "status": "in_progress", "conclusion": None}
    api.run_job_names["200"] = api.run_job_names["100"]
    api.run_job_names["500"] = ("Finalize",)
    with zipfile.ZipFile(BytesIO(api._truth_archive())) as archive:
        report = json.loads(archive.read("truth-report.json"))
    report["subject"] = {"commit_sha": SHA_B, "tree_sha": api.tree}
    report["evaluation_scope"]["target"]["id"] = "P02"
    report["certified_proposition"].update(
        target={"kind": "phase", "id": "P02"}, subject=deepcopy(report["subject"]),
    )
    report["durable_ref"] = "github-actions://owner/repo/runs/200/attempts/1/bcf-governance-truth"
    api.truth_artifact_override = report
    raw = api._truth_archive()
    artifacts, artifact_bytes, content = api.artifacts, api.artifact_bytes, api.content
    def source(repository, path, *, ref):
        value = content(repository, path, ref=ref)
        if ref == SHA_B and path in policy:
            oid = hashlib.sha1(b"blob " + str(len(value.content)).encode() + b"\0" + value.content).hexdigest()
            return GitHubContent(path, oid, value.content)
        return value
    def inventory(repository, run_id):
        if str(run_id) == "200":
            return ({"id": 900, "name": "bcf-governance-truth-200-1", "expired": False,
                     "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                     "workflow_run": {"id": 200, "repository_id": 42, "head_repository_id": 42,
                                      "head_branch": "main", "head_sha": SHA_B}},)
        return artifacts(repository, run_id)
    def download(repository, artifact_id, *, maximum_bytes):
        if str(artifact_id) == "900":
            assert len(raw) <= maximum_bytes
            return raw
        return artifact_bytes(repository, artifact_id, maximum_bytes=maximum_bytes)
    monkeypatch.setattr(api, "content", source)
    monkeypatch.setattr(api, "artifacts", inventory)
    monkeypatch.setattr(api, "artifact_bytes", download)
    result = finalize_exact_main(
        api, repository="owner/repo", collector_run_id=500, collector_run_attempt=1,
        trigger_run_id=200, trigger_run_attempt=1, output_dir=tmp_path / "child",
    )
    assert result.computed_state == "certified"
    assert api.reads == 1
    certification = json.loads((tmp_path / "child/ci-certification.json").read_text())
    assert certification["evaluation_scope"] == {"intent": "closure", "target": {"kind": "phase", "id": "P02"}}
    assert certification["certified_proposition"]["subject"] == {"commit_sha": SHA_B, "tree_sha": api.tree}
