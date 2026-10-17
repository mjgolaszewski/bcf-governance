"""Preserve authenticated phase context at both local readiness boundaries."""

from pathlib import Path

import pytest

from bcf_governance.tooling import local_pr as prospective
from tests.test_prospective_validation import (
    TRAIN, HEAD, BASE, _authored_target_ready, _front_door, _runner,  # noqa: F401
)


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
    monkeypatch.setattr(prospective, "local_gate_lease", lambda *a: pytest.fail("readiness allocated gate"))
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
