"""Characterize environment defaults, observation time and mutation ownership."""

from __future__ import annotations

import operator
import os
from pathlib import Path

import pytest

from bcf_governance.tooling.bootstrap import environment as bootstrap


def test_typed_settings_preserve_defaults_empty_values_and_late_changes() -> None:
    values: dict[str, str] = {}
    cases = [
        (bootstrap.github_provider_settings, "token", "GITHUB_TOKEN", (), ""),
        (bootstrap.github_provider_settings, "api_url", "GITHUB_API_URL", (), "https://api.github.com"),
        (bootstrap.workflow_settings, "actions", "GITHUB_ACTIONS", (), None),
        (bootstrap.workflow_settings, "job", "GITHUB_JOB", ("local",), "local"),
        (bootstrap.workflow_settings, "repository", "GITHUB_REPOSITORY", ("repo",), "repo"),
        (bootstrap.workflow_settings, "run_attempt", "GITHUB_RUN_ATTEMPT", ("1",), "1"),
        (bootstrap.comparison_settings, "base_sha", "BCF_COMPARISON_BASE_SHA", (), ""),
        (bootstrap.comparison_settings, "optional_pr_base_sha", "BCF_PR_BASE_SHA", (), None),
        (bootstrap.evidence_settings, "producer_kind", "BCF_EVIDENCE_PRODUCER_KIND", ("service",), "service"),
        (bootstrap.runtime_settings, "virtual_env", "VIRTUAL_ENV", (), None),
        (bootstrap.custody_settings, "controller_custody_path", "BCF_CONTROLLER_CUSTODY_PATH", (), ""),
    ]
    for factory, method_name, key, arguments, default in cases:
        settings = factory(values)
        method = getattr(settings, method_name)
        assert method(*arguments) == values.get(key, default)
        values[key] = "before"
        assert method(*arguments) == "before"
        values[key] = "after"
        assert method(*arguments) == "after", "settings must observe at point of use"
        values[key] = ""
        assert method(*arguments) == "", "missing defaults must not replace explicit empty values"
        del values[key]
        assert method(*arguments) == default


def test_default_settings_observe_current_environment_without_import_cache(monkeypatch) -> None:
    settings = bootstrap.github_provider_settings()
    monkeypatch.setenv("GITHUB_TOKEN", "first-test-token")
    assert settings.token() == "first-test-token"
    monkeypatch.setenv("GITHUB_TOKEN", "second-test-token")
    assert settings.token() == "second-test-token"
    monkeypatch.delenv("GITHUB_TOKEN")
    assert settings.token() == ""


def test_narrow_settings_have_no_unknown_or_credential_accessor() -> None:
    workflow = bootstrap.workflow_settings({"GITHUB_TOKEN": "not-a-workflow-capability"})
    with pytest.raises(AttributeError):
        getattr(workflow, "token")
    with pytest.raises(AttributeError):
        getattr(workflow, "get")
    with pytest.raises(AttributeError):
        getattr(workflow, "unknown_setting")


def test_process_snapshot_and_live_view_preserve_distinct_semantics() -> None:
    values = {"PATH": "/before", "DECLARED": "one", "UNDECLARED": "two"}
    capability = bootstrap.child_process_environment(values)
    snapshot = capability.snapshot()
    live = capability.live()
    declared = capability.required_values(["DECLARED"])
    values["PATH"] = "/after"
    values["DECLARED"] = "changed"
    assert snapshot["PATH"] == "/before"
    assert live["PATH"] == "/after"
    assert declared["DECLARED"] == "changed"
    with pytest.raises(TypeError):
        operator.setitem(live, "PATH", "must-not-mutate")
    with pytest.raises(KeyError):
        operator.getitem(declared, "UNDECLARED")
    assert declared.get("UNDECLARED") is None
    assert values["UNDECLARED"] == "two"


def test_custody_view_cannot_read_an_undeclared_key() -> None:
    values = {"BCF_EXECUTION_STATE_NAMESPACE": "namespace", "GITHUB_TOKEN": "test-only"}
    view = bootstrap.custody_settings(values).execution_inputs()
    assert view["BCF_EXECUTION_STATE_NAMESPACE"] == "namespace"
    with pytest.raises(KeyError):
        operator.getitem(view, "GITHUB_TOKEN")
    values["BCF_EXECUTION_STATE_ROOT"] = "/owned"
    assert view["BCF_EXECUTION_STATE_ROOT"] == "/owned"


def test_comparison_scope_restores_missing_empty_nested_and_exception_state() -> None:
    values = {"GITHUB_EVENT_NAME": "", "UNCHANGED": "keep"}
    original = dict(values)
    scope = bootstrap.scoped_execution_environment(values)
    with scope.comparison({"GITHUB_EVENT_NAME": "push", "BCF_PR_BASE_SHA": "base"}):
        assert values["GITHUB_EVENT_NAME"] == "push"
        with pytest.raises(RuntimeError):
            with scope.comparison({"GITHUB_EVENT_NAME": None, "BCF_PR_BASE_SHA": "nested"}):
                assert "GITHUB_EVENT_NAME" not in values
                raise RuntimeError("test-only failure")
        assert values["GITHUB_EVENT_NAME"] == "push"
        assert values["BCF_PR_BASE_SHA"] == "base"
    assert values == original


def test_comparison_scope_rejects_unknown_keys_before_mutation() -> None:
    values = {"UNCHANGED": "keep"}
    scope = bootstrap.scoped_execution_environment(values)
    with pytest.raises(ValueError):
        with scope.comparison({"ARBITRARY_APPLICATION_SETTING": "blocked"}):
            pytest.fail("unknown key scope entered")
    assert values == {"UNCHANGED": "keep"}


@pytest.mark.parametrize("previous", [None, "", "/before"])
def test_selected_toolchain_path_preserves_original_restore_behavior(previous: str | None) -> None:
    values = {} if previous is None else {"PATH": previous}
    original = dict(values)
    with bootstrap.scoped_execution_environment(values).toolchain_path("/node/bin/node"):
        assert values["PATH"] == str(Path("/node/bin/node").parent) + (os.pathsep + previous if previous else "")
    assert values == original


def test_invocation_markers_preserve_existing_persistent_lifetime() -> None:
    values = {"UNCHANGED": "keep"}
    markers = bootstrap.invocation_environment(values)
    markers.prior_splinter_root("/owned/proof")
    markers.evidence_shard("3")
    assert values == {
        "UNCHANGED": "keep", "BCF_PRIOR_SPLINTER_PROOF_ROOT": "/owned/proof",
        "BCF_EVIDENCE_SHARD": "3",
    }


def test_legacy_cli_required_variable_keeps_existing_empty_default() -> None:
    values = {"GITHUB_RUN_ID": "42"}
    compatibility = bootstrap.cli_required_variables(values)
    assert compatibility.value("GITHUB_RUN_ID") == "42"
    assert compatibility.value("MISSING") == ""
    values["GITHUB_RUN_ID"] = "changed"
    assert compatibility.value("GITHUB_RUN_ID") == "changed"


@pytest.mark.parametrize("source", [
    "import os\nvalue = os.environ.get('SETTING')\n",
    "import os as system\nvalue = system.getenv('SETTING')\n",
    "from os import environ as state\nvalue = state['SETTING']\n",
    "import os\nstate = os.environ\nother = state\nvalue = other.copy()\n",
    "import os\nreader = getattr(os, 'getenv')\nvalue = reader('SETTING')\n",
    "import os\nreader = getattr(os, setting_name)\n",
    "value = __import__('os').environ.get('SETTING')\n",
    "import os\nvalue = os.__dict__['environ']['SETTING']\n",
    "import os\nvalue = vars(os)['environ']['SETTING']\n",
])
def test_environment_guard_rejects_original_and_hidden_raw_aliases(source: str) -> None:
    from bcf_governance.tooling.governance_validation.environment_boundaries import inspect_environment_source
    assert inspect_environment_source(source, "contexts.application.unapproved")


@pytest.mark.parametrize("source", [
    "from bcf_governance.tooling.bootstrap.environment import workflow_settings\n",
    "import bcf_governance.tooling.bootstrap.environment as settings\n",
    "from bcf_governance.tooling.ci_github_cli_io import required_environment as read\nread('GITHUB_TOKEN')\n",
    "import importlib\nm = importlib.import_module('bcf_governance.tooling.bootstrap.environment')\nfactory = getattr(m, 'cli_required_variables')\nfactory().value('GITHUB_TOKEN')\n",
])
def test_environment_guard_rejects_inward_import_and_cli_facade_bypass(source: str) -> None:
    from bcf_governance.tooling.governance_validation.environment_boundaries import inspect_environment_imports
    assert inspect_environment_imports(source, "contexts.application.unapproved")


def test_environment_guard_rejects_unknown_capability_through_protocol_alias() -> None:
    from bcf_governance.tooling.governance_validation.environment_boundaries import inspect_environment_source
    source = '''from .bootstrap.contracts import WorkflowSettings as Port

def _producer_identity(repo_root, *, workflow_settings: Port | None = None):
    alias = workflow_settings
    return getattr(alias, "token")()
'''
    assert any("unknown" in issue for issue in inspect_environment_source(source, "evidence_sessions"))


def test_environment_guard_causally_checks_adapter_key_and_pure_binding_contracts() -> None:
    from bcf_governance.tooling.governance_validation.environment_boundaries import inspect_environment_source
    root = Path(__file__).resolve().parents[1]
    source = (root / "bcf_governance/tooling/bootstrap/environment.py").read_text()
    assert not inspect_environment_source(source, "bootstrap.environment")
    wrong_key = source.replace("self._source.get('GITHUB_TOKEN',", "self._source.get('UNDECLARED_SECRET',")
    assert wrong_key != source
    assert any("key/default" in issue for issue in inspect_environment_source(wrong_key, "bootstrap.environment"))
    extra_read = source.replace("return os.environ if self._provided is None else self._provided",
                                "value = os.environ\n        return value if self._provided is None else self._provided", 1)
    assert any("pure point-of-use" in issue for issue in inspect_environment_source(extra_read, "bootstrap.environment"))


def test_entire_canonical_population_has_typed_environment_owners() -> None:
    from bcf_governance.tooling.governance_validation.environment_boundaries import validate_environment_boundaries
    root = Path(__file__).resolve().parents[1] / "bcf_governance/tooling"
    validate_environment_boundaries(root)


def test_native_lint_rejects_environment_boundary_failure_before_tool_success(monkeypatch) -> None:
    import runpy
    import subprocess
    from bcf_governance.tooling.governance_validation.environment_boundaries import EnvironmentBoundaryError

    root = Path(__file__).resolve().parents[1]
    namespace = runpy.run_path(str(root / ".github/scripts/run_self_governance_gate.py"))
    lint = namespace["_lint"]
    commands = []

    def violation(_root: Path) -> None:
        raise EnvironmentBoundaryError("test-only unowned environment read")

    def passing_tool(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setitem(lint.__globals__, "validate_environment_boundaries", violation)
    monkeypatch.setattr(subprocess, "run", passing_tool)
    with pytest.raises(SystemExit) as failure:
        lint("lint")
    assert failure.value.code == 1
    assert commands == []
