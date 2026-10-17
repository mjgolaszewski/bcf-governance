"""Reject mechanically impossible lifecycle work before discovery or allocation."""

import sys

import pytest
import yaml

from bcf_governance.tooling import preflight
from tests.test_phase_closure_population import protected_population, phase_input  # noqa: F401
from tests.test_workitem_phase_consumption import _repo, _phase_log


class DiscoveryReached(RuntimeError):
    pass


def _cheap_front(monkeypatch, events):
    monkeypatch.setattr(preflight, "_git_state", lambda _: {"commit_sha": "a" * 40, "tree_sha": "b" * 40})
    monkeypatch.setattr(preflight, "_pr_context", lambda *_: {"applicable": False})
    monkeypatch.setattr(preflight, "validate_authored_phase_state", lambda _: {})
    monkeypatch.setattr(preflight, "validate_ci_state_matrix", lambda _: {})
    monkeypatch.setattr(preflight, "validate_structural_limits", lambda _: {})
    def discovery(_):
        events.append("discovery")
        raise DiscoveryReached("later syntax/discovery frontier")
    monkeypatch.setattr(preflight, "_syntax_checks", discovery)
    monkeypatch.setattr(preflight, "allocate_session", lambda *a, **kw: pytest.fail("readiness allocated session"))


def _run(root, **kwargs):
    return preflight.run_preflight(
        root, mode="release", python_executable=sys.executable,
        artifact_root=root / "evidence", evaluation_mode=kwargs.pop("evaluation_mode", "workitem"),
        evaluation_target=kwargs.pop("evaluation_target", "P02-W01"), **kwargs,
    )


def test_missing_phase_authority_blocks_before_discovery_or_session(tmp_path, monkeypatch):
    _repo(tmp_path)
    events = []
    _cheap_front(monkeypatch, events)
    with pytest.raises(preflight.PreflightError, match="phase closure prerequisites"):
        _run(tmp_path)
    assert events == []
    assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("intent", ["workitem", "closure"])
def test_actual_phase_evidence_is_consumed_before_discovery(tmp_path, monkeypatch, protected_population, intent):
    api, _, _ = protected_population
    entries = _repo(tmp_path)
    if intent == "closure":
        _phase_log(tmp_path)
        for entry in entries:
            entry["status"] = "DONE"
        (tmp_path / "plans/items.yml").write_text(yaml.safe_dump({"workitems": entries}))
    events = []
    _cheap_front(monkeypatch, events)
    with pytest.raises(DiscoveryReached):
        _run(tmp_path, evaluation_mode=intent, evaluation_target="P02-W01" if intent == "workitem" else None,
             provider_api=api, repository="owner/repo")
    assert events == ["discovery"]
    assert api.reads == 1
    assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("intent", ["workitem", "closure"])
def test_unfinished_authored_work_blocks_before_provider_download(tmp_path, monkeypatch, protected_population, intent):
    api, _, _ = protected_population
    entries = _repo(tmp_path)
    _phase_log(tmp_path)
    if intent == "workitem":
        entries[0]["status"] = "IN_PROGRESS"
        (tmp_path / "plans/items.yml").write_text(yaml.safe_dump({"workitems": entries}))
    events = []
    _cheap_front(monkeypatch, events)
    with pytest.raises(preflight.PreflightError, match="not authored DONE"):
        _run(tmp_path, evaluation_mode=intent, evaluation_target="P02-W01" if intent == "workitem" else None,
             provider_api=api, repository="owner/repo")
    assert events == []
    assert api.reads == 0


def test_pure_preflight_preserves_unbound_workitem_without_context_discovery(tmp_path, monkeypatch):
    _repo(tmp_path, predicate=None)
    events = []
    _cheap_front(monkeypatch, events)
    monkeypatch.setattr(preflight, "provider_context_for_checkout", lambda _: pytest.fail("pure API discovered ambient credentials"), raising=False)
    with pytest.raises(DiscoveryReached):
        _run(tmp_path)
    assert events == ["discovery"]


def test_preflight_cli_forwards_context_before_running_checks(tmp_path, monkeypatch):
    api = object()
    monkeypatch.setattr(preflight, "provider_context_for_checkout", lambda _: (api, "owner/repo"), raising=False)
    def stop(*args, **kwargs):
        assert kwargs.get("provider_api") is api
        assert kwargs.get("repository") == "owner/repo"
        raise preflight.PreflightError("scoped check stop")
    monkeypatch.setattr(preflight, "run_preflight", stop)
    with pytest.raises(SystemExit, match="scoped check stop"):
        preflight.main(["--repo-root", str(tmp_path)])
