"""Verify migrated production callers through injected, isolated capabilities."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from bcf_governance.tooling.bootstrap import environment as bootstrap
from bcf_governance.tooling.ci_github_cli_io import required_environment
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.evidence_execution import EvidenceError
from bcf_governance.tooling.evidence_sessions import _producer_identity
from bcf_governance.tooling.local_pr_context import LocalPRContext, _pr_environment
from bcf_governance.tooling.python_runtime_selection import interpreter_subprocess_environment
from bcf_governance.tooling.repository_comparison_context import local_push_environment


def test_evidence_producer_callers_keep_defaults_empty_failure_and_late_values() -> None:
    values: dict[str, str] = {}
    workflow = bootstrap.workflow_settings(values)
    identity = _producer_identity(Path("/test/project"), workflow_settings=workflow)
    assert identity == {
        "kind": "local", "provider": "local", "repository": "project",
        "repository_id": "local", "run_id": "local", "run_attempt": "1",
        "producer_id": "local",
    }
    values.update({"GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "42"})
    identity = _producer_identity(Path("/test/project"), workflow_settings=workflow)
    assert identity["kind"] == "workflow" and identity["provider"] == "github-actions"
    assert identity["run_id"] == "42"
    values["GITHUB_RUN_ID"] = ""
    with pytest.raises(EvidenceError, match="exact non-empty fields"):
        _producer_identity(Path("/test/project"), workflow_settings=workflow)


def test_cli_required_callers_keep_missing_empty_and_late_value_semantics() -> None:
    values: dict[str, str] = {}
    cli = bootstrap.cli_required_variables(values)
    for value in (None, "", "42", "43"):
        if value is not None:
            values["GITHUB_RUN_ID"] = value
        if not value:
            with pytest.raises(GitHubControllerError, match="missing GITHUB_RUN_ID"):
                required_environment("GITHUB_RUN_ID", cli_variables=cli)
        else:
            assert required_environment("GITHUB_RUN_ID", cli_variables=cli) == value


def test_real_pr_and_push_callers_restore_nested_comparison_on_failure() -> None:
    values = {"GITHUB_EVENT_NAME": "", "BCF_PR_BASE_SHA": "old", "UNCHANGED": "keep"}
    before = dict(values)
    scope = bootstrap.scoped_execution_environment(values)
    context = LocalPRContext("origin", "main", "base", "head", "feature")
    with pytest.raises(RuntimeError, match="test-only"):
        with _pr_environment(context, scoped_environment=scope):
            assert values["GITHUB_EVENT_NAME"] == "pull_request"
            assert values["BCF_PR_BASE_SHA"] == "base"
            assert values["GITHUB_HEAD_REF"] == "feature"
            with local_push_environment(base_sha="next-base", head_sha="next-head", scoped_environment=scope):
                assert values["GITHUB_EVENT_NAME"] == "push"
                assert values["GITHUB_SHA"] == "next-head"
                assert values["BCF_COMPARISON_BASE_SHA"] == "next-base"
                assert "BCF_PR_BASE_SHA" not in values
            assert values["GITHUB_EVENT_NAME"] == "pull_request"
            assert values["BCF_PR_BASE_SHA"] == "base"
            raise RuntimeError("test-only")
    assert values == before


@pytest.mark.parametrize("previous", [None, "", "/before"])
def test_real_interpreter_child_projection_does_not_mutate_parent(tmp_path: Path, previous: str | None) -> None:
    values = {"PYTHONPATH": "controller", "PYTHONHOME": "controller", "VIRTUAL_ENV": "controller", "KEEP": "value"}
    if previous is not None:
        values["PATH"] = previous
    before = dict(values)
    python = tmp_path / "runtime/bin/python"
    process = bootstrap.child_process_environment(values)
    environment = interpreter_subprocess_environment(python, process_environment=process)
    assert values == before
    assert environment["PATH"] == str(python.parent) + (os.pathsep + previous if previous else "")
    assert environment["KEEP"] == "value"
    assert not {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"} & environment.keys()
    values["KEEP"] = "changed"
    assert interpreter_subprocess_environment(python, process_environment=process)["KEEP"] == "changed"
    assert environment["KEEP"] == "value"
