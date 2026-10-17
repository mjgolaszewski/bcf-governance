"""Independent exact-main certification cannot promote a claimed phase terminal."""

from copy import deepcopy
from io import BytesIO
import json
import zipfile

import pytest

from bcf_governance.tooling.ci_github_exact_main import finalize_exact_main
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from tests.test_ci_github_controller import (
    FakeAPI, SHA_A, TREE, _prepare_v11_run, _authenticated_controller_transport,  # noqa: F401
)


def _finalize(api, root):
    return finalize_exact_main(api, repository="owner/repo", collector_run_id=400,
                               collector_run_attempt=1, output_dir=root / "bundle")


def _report(api):
    with zipfile.ZipFile(BytesIO(api._truth_archive())) as archive:
        return json.loads(archive.read("truth-report.json"))


@pytest.mark.parametrize("defect", ["unfinished_phase", "unfinished_workitem", "unfinished_hotfix", "wrong_phase", "unknown_workitem", "bounded_unfinished"])
def test_finalizer_rejects_impossible_authored_terminal_before_certificate(tmp_path, defect):
    api = FakeAPI()
    _prepare_v11_run(api)
    docs = api.lifecycle_documents
    if defect == "unfinished_phase":
        docs["phases/phase-01-log.yml"]["document"]["status"] = "active"
    elif defect == "unfinished_workitem":
        docs["plans/phase-01-workitems.yml"]["workitems"][0]["status"] = "IN_PROGRESS"
    elif defect == "unfinished_hotfix":
        docs["phases/phase-01-hotfix01.yml"] = {"document": {"status": "active"}, "hotfix": {"id": "HF01", "related_phase_id": "P01"}}
    else:
        report = _report(api)
        if defect == "wrong_phase":
            report["evaluation_scope"]["target"]["id"] = "P99"
            report["certified_proposition"]["target"]["id"] = "P99"
        else:
            target = {"kind": "workitem", "id": "P01-W99" if defect == "unknown_workitem" else "P01-W01"}
            report["evaluation_scope"] = {"intent": "workitem", "target": target}
            report["certified_proposition"].update(predicate="workitem_closed", target=deepcopy(target),
                                                    authorizes=["declared_successor_workitem_eligibility"])
            if defect == "bounded_unfinished":
                docs["plans/phase-01-workitems.yml"]["workitems"][0]["status"] = "TODO"
        api.truth_artifact_override = report
    with pytest.raises(GitHubControllerError):
        _finalize(api, tmp_path)
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize("defect", ["missing_workitems", "duplicate_ledger", "wrong_blob", "unsafe_reference", "substituted_bytes", "wrong_content_path"])
def test_finalizer_rejects_uncertain_lifecycle_inventory(tmp_path, monkeypatch, defect):
    api = FakeAPI()
    _prepare_v11_run(api)
    original = api.complete_tree
    def inventory(repository, tree):
        rows = list(original(repository, tree))
        if defect == "missing_workitems":
            rows = [row for row in rows if row[0] != "plans/phase-01-workitems.yml"]
        elif defect == "duplicate_ledger":
            rows.append(next(row for row in rows if row[0] == "plans/phase-ledger.yml"))
        elif defect == "wrong_blob":
            rows = [(path, "0" * 40 if path == "plans/phase-01-workitems.yml" else oid) for path, oid in rows]
        return tuple(rows)
    monkeypatch.setattr(api, "complete_tree", inventory)
    if defect == "unsafe_reference":
        api.lifecycle_documents["plans/phase-ledger.yml"]["active_phase"]["workitems"] = "../escape.yml"
    if defect in {"substituted_bytes", "wrong_content_path"}:
        content = api.content
        def substituted(repository, path, *, ref):
            value = content(repository, path, ref=ref)
            if path == "plans/phase-01-workitems.yml":
                return type(value)("plans/other.yml" if defect == "wrong_content_path" else value.path,
                                   value.blob_oid, value.content if defect == "wrong_content_path"
                                   else value.content + b"\n# substituted\n")
            return value
        monkeypatch.setattr(api, "content", substituted)
    with pytest.raises(GitHubControllerError):
        _finalize(api, tmp_path)
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize("authored_closed", [False, True])
def test_finalizer_requires_independent_parent_certificate(tmp_path, monkeypatch, authored_closed):
    api = FakeAPI()
    _prepare_v11_run(api)
    api.lifecycle_documents["plans/build-plan.yml"]["phase_sequence"][0]["hard_dependencies"] = ["P00"]
    api.lifecycle_documents["plans/phase-history.yml"]["entries"] = [{
        "phase_id": "P00", "retention_ref": SHA_A,
        "status": "completed" if authored_closed else "planned",
        "derived_state_at_capture": "closed" if authored_closed else "unverified",
        "verification_snapshot": {"commit_sha": SHA_A, "tree_sha": TREE},
    }]
    original = api.workflow_runs
    def runs(repository, workflow_id, *, head_sha, event):
        if str(workflow_id) == "98":
            return ()
        return original(repository, workflow_id, head_sha=head_sha, event=event)
    monkeypatch.setattr(api, "workflow_runs", runs)
    with pytest.raises(GitHubControllerError):
        _finalize(api, tmp_path)
    assert not (tmp_path / "bundle").exists()


def test_finalizer_rejects_nonregular_lifecycle_blob_even_when_bytes_and_oid_match(tmp_path, monkeypatch):
    api = FakeAPI()
    _prepare_v11_run(api)
    original = api.complete_tree_with_modes
    def inventory(repository, tree):
        return tuple((path, oid, "120000" if path == "plans/phase-01-workitems.yml" else mode)
                     for path, oid, mode in original(repository, tree))
    monkeypatch.setattr(api, "complete_tree_with_modes", inventory)
    with pytest.raises(GitHubControllerError, match="regular"):
        _finalize(api, tmp_path)
    assert not (tmp_path / "bundle").exists()


def test_finalizer_uses_historical_admitted_phase_when_current_phase_differs(tmp_path, monkeypatch):
    import hashlib
    import yaml
    from bcf_governance.tooling.ci_github_api import GitHubContent
    from tests.test_ci_github_controller import SHA_B
    api = FakeAPI()
    _prepare_v11_run(api)
    api.main = SHA_B
    original_commit, original_content = api.commit, api.content
    def commit(repository, sha):
        if sha == SHA_B:
            return {"sha": SHA_B, "tree": {"sha": "d" * 40}}
        return original_commit(repository, sha)
    future = deepcopy(api.lifecycle_documents)
    future["plans/build-plan.yml"]["phase_sequence"] = [{"phase_id": "P99", "hard_dependencies": []}]
    future["plans/phase-ledger.yml"]["active_phase"] = {
        "id": "P99", "workitems": "plans/phase-99-workitems.yml", "log": "phases/phase-99-log.yml",
    }
    future["plans/phase-99-workitems.yml"] = {"workitems": [{"id": "P99-W01", "status": "TODO", "acceptance": []}]}
    future["phases/phase-99-log.yml"] = {"document": {"status": "active"}, "phase": {"id": "P99"}}
    def content(repository, path, *, ref):
        if ref == SHA_B and path in future:
            raw = yaml.safe_dump(future[path], sort_keys=False).encode()
            return GitHubContent(path, hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), raw)
        return original_content(repository, path, ref=ref)
    def inventory(repository, tree):
        assert tree == TREE
        return tuple(sorted((path, content(repository, path, ref=SHA_A).blob_oid, "100644")
                            for path in api.lifecycle_documents))
    monkeypatch.setattr(api, "commit", commit)
    monkeypatch.setattr(api, "content", content)
    monkeypatch.setattr(api, "complete_tree_with_modes", inventory)
    result = finalize_exact_main(
        api, repository="owner/repo", collector_run_id=400, collector_run_attempt=1,
        trigger_run_id=100, trigger_run_attempt=1, output_dir=tmp_path / "bundle",
    )
    assert result.computed_state == "certified"
    report = json.loads((tmp_path / "bundle/ci-certification.json").read_text())
    assert report["subject"]["checkout_sha"] == SHA_A
    assert report["evaluation_scope"]["target"] == {"kind": "phase", "id": "P01"}


def test_unfinished_authored_state_precedes_phase_proof_and_producer_collection(tmp_path, monkeypatch):
    from bcf_governance.tooling import trusted_inputs, ci_github_exact_main
    api = FakeAPI()
    _prepare_v11_run(api)
    api.lifecycle_documents["plans/phase-01-workitems.yml"]["workitems"][0]["status"] = "TODO"
    monkeypatch.setattr(trusted_inputs, "verify_required_phase_closure_inputs",
                        lambda *a, **kw: pytest.fail("unfinished authoring allocated phase proof"))
    monkeypatch.setattr(ci_github_exact_main, "collect_same_run_producers",
                        lambda *a, **kw: pytest.fail("unfinished authoring collected producer evidence"))
    with pytest.raises(GitHubControllerError, match="authored DONE"):
        _finalize(api, tmp_path)
    assert not (tmp_path / "bundle").exists()


def test_finalizer_preserves_declared_safe_yaml_data_path(tmp_path):
    api = FakeAPI()
    _prepare_v11_run(api)
    docs = api.lifecycle_documents
    docs["settings/items.yaml"] = docs.pop("plans/phase-01-workitems.yml")
    docs["plans/phase-ledger.yml"]["active_phase"]["workitems"] = "settings/items.yaml"
    result = _finalize(api, tmp_path)
    assert result.computed_state == "certified"
