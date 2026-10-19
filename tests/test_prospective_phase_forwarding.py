"""Preserve authenticated phase context at both local readiness boundaries."""

from pathlib import Path

import pytest

from bcf_governance.tooling import local_pr as prospective
from tests.test_prospective_validation import (
    TRAIN, HEAD, BASE, _authored_target_ready, _front_door, _runner,  # noqa: F401
)
from tests.test_phase_closure_population import protected_population, phase_input  # noqa: F401
from tests.test_workitem_phase_consumption import _repo
from bcf_governance.tooling.evidence_workitem_lifecycle import validate_evaluation_authored_ready


@pytest.mark.parametrize("boundary", ["public", "inner"])
def test_local_phase_authority_rejection_precedes_allocation(tmp_path, monkeypatch, boundary):
    _front_door(monkeypatch, [])
    api = object()
    error = prospective.WorkitemContractError("phase proof unavailable")
    def reject(root, **kwargs):
        assert kwargs.get("provider_api") is api
        assert kwargs.get("repository") == "owner/repo"
        raise error
    monkeypatch.setattr(prospective, "validate_evaluation_authored_ready", reject)
    monkeypatch.setattr(prospective, "local_gate_lease", lambda *a, **kw: pytest.fail("readiness allocated gate"))
    monkeypatch.setattr(prospective, "validate_local_toolchain", lambda *a, **kw: pytest.fail("readiness allocated toolchain"))
    operation = prospective.run_prospective_train if boundary == "public" else prospective._run_prospective_train
    with pytest.raises(prospective.ProspectiveValidationError) as caught:
        operation(tmp_path, **TRAIN, python_executable=Path("/python"),
                  repository="owner/repo", provider_api=api, runner=_runner)
    assert caught.value.__cause__ is error


def test_ordinary_inner_phase_identity_comes_from_authenticated_context(tmp_path, monkeypatch):
    _front_door(monkeypatch, [])
    api = object()
    context = prospective.LocalPRContext("origin", "main", BASE, HEAD, "feature",
                                         repository="owner/repo", repository_id=42)
    monkeypatch.setattr(prospective, "resolve_local_pr_context", lambda *a, **kw: context)
    error = prospective.WorkitemContractError("phase source observed")
    def reject(root, **kwargs):
        assert kwargs.get("provider_api") is api
        assert kwargs.get("repository") == context.repository
        raise error
    monkeypatch.setattr(prospective, "validate_evaluation_authored_ready", reject)
    with pytest.raises(prospective.ProspectiveValidationError) as caught:
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path("/python"),
                                          provider_api=api, runner=_runner)
    assert caught.value.__cause__ is error


def test_contradictory_repository_blocks_before_phase_acquisition(tmp_path, monkeypatch):
    _front_door(monkeypatch, [])
    context = prospective.LocalPRContext("origin", "main", BASE, HEAD, "feature",
                                         repository="owner/repo", repository_id=42)
    monkeypatch.setattr(prospective, "resolve_local_pr_context", lambda *a, **kw: context)
    monkeypatch.setattr(prospective, "validate_evaluation_authored_ready",
                        lambda *a, **kw: pytest.fail("contradictory repository reached phase acquisition"))
    with pytest.raises(prospective.ProspectiveValidationError, match="repository.*context"):
        prospective._run_prospective_train(tmp_path, **TRAIN, python_executable=Path("/python"),
                                          repository="other/repo", provider_api=object(), runner=_runner)


def test_public_readiness_consumes_real_authenticated_phase_before_gate(tmp_path, monkeypatch, protected_population):
    api, _, _ = protected_population
    _front_door(monkeypatch, [])
    _repo(tmp_path)
    monkeypatch.setattr(prospective, "validate_evaluation_authored_ready", validate_evaluation_authored_ready)
    stopped = RuntimeError("gate intentionally intercepted after authenticated readiness")
    def gate(subject, *, repo_root: Path):
        assert repo_root == tmp_path.resolve(), "prospective lease must bind the actual repository policy"
        assert api.reads == 1
        raise stopped
    monkeypatch.setattr(prospective, "local_gate_lease", gate)
    request = {**TRAIN, "evaluation_target": "P02-W01"}
    with pytest.raises(RuntimeError) as caught:
        prospective.run_prospective_train(tmp_path, **request, python_executable=Path("/python"),
                                         repository="owner/repo", provider_api=api, runner=_runner)
    assert caught.value is stopped


def test_public_readiness_without_real_phase_authority_cannot_allocate(tmp_path, monkeypatch):
    _front_door(monkeypatch, [])
    _repo(tmp_path)
    monkeypatch.setattr(prospective, "validate_evaluation_authored_ready", validate_evaluation_authored_ready)
    monkeypatch.setattr(prospective, "local_gate_lease", lambda *a, **kw: pytest.fail("missing phase proof allocated a gate"))
    request = {**TRAIN, "evaluation_target": "P02-W01"}
    with pytest.raises(prospective.ProspectiveValidationError, match="phase closure prerequisites"):
        prospective.run_prospective_train(tmp_path, **request, python_executable=Path("/python"),
                                         repository="owner/repo", runner=_runner)
