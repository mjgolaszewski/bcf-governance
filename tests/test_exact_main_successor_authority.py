"""A bounded certificate cannot invent source-declared successor authority."""

from copy import deepcopy
from io import BytesIO
import json
import zipfile

import pytest

from bcf_governance.tooling.ci_github_exact_main import finalize_exact_main
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from tests.test_ci_github_controller import FakeAPI, _prepare_v11_run, _authenticated_controller_transport  # noqa: F401


@pytest.mark.parametrize("successors", [["P99-W01"], ["P01-W01"]])
def test_finalizer_rejects_undeclared_or_self_successor_authority(tmp_path, successors):
    api = FakeAPI()
    _prepare_v11_run(api)
    with zipfile.ZipFile(BytesIO(api._truth_archive())) as archive:
        report = json.loads(archive.read("truth-report.json"))
    target = {"kind": "workitem", "id": "P01-W01"}
    report["evaluation_scope"] = {"intent": "workitem", "target": target}
    report["certified_proposition"].update(
        predicate="workitem_closed", target=deepcopy(target),
        authorizes=["declared_successor_workitem_eligibility"], eligible_successors=successors,
    )
    api.truth_artifact_override = report
    with pytest.raises(GitHubControllerError):
        finalize_exact_main(api, repository="owner/repo", collector_run_id=400,
                            collector_run_attempt=1, output_dir=tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def _declared_next(api):
    api.lifecycle_documents["plans/phase-01-workitems.yml"]["workitems"].append({
        "id": "P01-W02", "status": "TODO", "acceptance": ["requires-workitem-closure:P01-W01"],
        "acceptance_evidence": ["test"],
    })
    api.lifecycle_documents["phases/phase-01-log.yml"]["document"]["status"] = "active"


def _bounded(api, successors):
    with zipfile.ZipFile(BytesIO(api._truth_archive())) as archive:
        report = json.loads(archive.read("truth-report.json"))
    target = {"kind": "workitem", "id": "P01-W01"}
    report["evaluation_scope"] = {"intent": "workitem", "target": target}
    report["certified_proposition"].update(
        predicate="workitem_closed", target=deepcopy(target),
        authorizes=["declared_successor_workitem_eligibility"], eligible_successors=successors,
    )
    api.truth_artifact_override = report


@pytest.mark.parametrize("successors", [["P01-W02", "P01-W02"], [True], [""]])
def test_invalid_projection_rejects_before_any_certificate_output(tmp_path, successors):
    api = FakeAPI()
    _prepare_v11_run(api)
    _declared_next(api)
    _bounded(api, successors)
    with pytest.raises(GitHubControllerError):
        finalize_exact_main(api, repository="owner/repo", collector_run_id=400,
                            collector_run_attempt=1, output_dir=tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize("successors", [["P01-W02"], []])
def test_declared_or_empty_projection_preserves_bounded_authority(tmp_path, successors):
    api = FakeAPI()
    _prepare_v11_run(api)
    _declared_next(api)
    _bounded(api, successors)
    result = finalize_exact_main(api, repository="owner/repo", collector_run_id=400,
                                 collector_run_attempt=1, output_dir=tmp_path / "bundle")
    assert result.computed_state == "certified"
    report = json.loads((tmp_path / "bundle/ci-certification.json").read_text())
    assert report["certified_proposition"]["eligible_successors"] == successors
    assert report["certified_proposition"]["predicate"] == "workitem_closed"
