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


@pytest.mark.parametrize("defect", ["missing_workitems", "duplicate_ledger", "wrong_blob", "unsafe_reference", "substituted_bytes"])
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
    if defect == "substituted_bytes":
        content = api.content
        def substituted(repository, path, *, ref):
            value = content(repository, path, ref=ref)
            if path == "plans/phase-01-workitems.yml":
                return type(value)(value.path, value.blob_oid, value.content + b"\n# substituted\n")
            return value
        monkeypatch.setattr(api, "content", substituted)
    with pytest.raises(GitHubControllerError):
        _finalize(api, tmp_path)
    assert not (tmp_path / "bundle").exists()
