"""Ordinary truth CLI acquires authority only through its bound provider context."""

import json
import subprocess

import pytest
import yaml

from bcf_governance.tooling import ci_authority_preflight, governance_truth, governance_truth_cli
from tests.test_governance_truth import _commit, _make_repo, _write_complete_bundle
from tests.test_phase_closure_population import protected_population, phase_input  # noqa: F401
from tests.test_workitem_phase_consumption import _truth_repo


@pytest.fixture(autouse=True)
def clear_provider_assertions(monkeypatch):
    for name in ("GITHUB_REPOSITORY", "GITHUB_TOKEN", "GITHUB_API_URL"):
        monkeypatch.delenv(name, raising=False)


def _origin(repo, value="git@github.com:owner/repo.git"):
    subprocess.run(["git", "remote", "add", "origin", value], cwd=repo, check=True)


def _invoke(repo, evidence, output, *, target="P02-W01"):
    governance_truth_cli.main([
        "--repo-root", str(repo), "--evidence-dir", str(evidence),
        "--evaluation-mode", "workitem", "--evaluation-target", target,
        "--output", str(output), "--format", "json",
    ])
    return json.loads(output.read_text())


@pytest.mark.parametrize("remove_candidate_predicate", [False, True])
def test_cli_consumes_real_protected_phase_bundle(tmp_path, monkeypatch, protected_population,
                                                remove_candidate_predicate):
    api, _, _ = protected_population
    repo, evidence = _truth_repo(tmp_path)
    if remove_candidate_predicate:
        path = repo / "plans/phase-01-workitems.yml"
        payload = yaml.safe_load(path.read_text())
        payload["workitems"][0]["acceptance"] = []
        path.write_text(yaml.safe_dump(payload))
        _commit(repo, "remove candidate phase assertion")
        evidence = _write_complete_bundle(repo)
    _origin(repo)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_TOKEN", "fixture-token")
    constructed = []
    def client(**kwargs):
        constructed.append(kwargs)
        return api
    monkeypatch.setattr(ci_authority_preflight, "GitHubAPI", client)
    report = _invoke(repo, evidence, tmp_path / "truth.json")
    assert report["status"] == "pass", report["issues"]
    assert api.reads == 1
    assert len(constructed) == 1
    assert constructed[0]["token"] == "fixture-token"
    assert report["workitems"]["phase_prerequisites"]["verified_phases"] == ["P01"]


@pytest.mark.parametrize(("repository", "token", "remote"), [
    ("owner/repo", None, "git@github.com:owner/repo.git"),
    (None, "fixture-token", "git@github.com:owner/repo.git"),
    ("owner/repo", "fixture-token", "git@github.com:other/repo.git"),
    ("owner/repo", "fixture-token", "https://untrusted.example/owner/repo.git"),
    ("owner/repo", "fixture-token", None),
])
def test_cli_rejects_incomplete_or_contradictory_context_before_truth(
    tmp_path, monkeypatch, repository, token, remote,
):
    repo = _make_repo(tmp_path)
    if remote is not None:
        _origin(repo, remote)
    if repository is not None:
        monkeypatch.setenv("GITHUB_REPOSITORY", repository)
    if token is not None:
        monkeypatch.setenv("GITHUB_TOKEN", token)
    monkeypatch.setattr(governance_truth, "derive_truth", lambda *a, **kw: pytest.fail("truth consumed invalid context"))
    monkeypatch.setattr(ci_authority_preflight, "GitHubAPI", lambda **kw: pytest.fail("invalid context constructed API"))
    output = tmp_path / "truth.json"
    with pytest.raises(SystemExit) as caught:
        _invoke(repo, repo / ".artifacts", output)
    assert caught.value.code == 1
    assert not output.exists()


def test_cli_unbound_without_phase_requirement_preserves_actual_truth(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path)
    evidence = _write_complete_bundle(repo)
    monkeypatch.setattr(ci_authority_preflight, "GitHubAPI", lambda **kw: pytest.fail("unbound API discovery"))
    report = _invoke(repo, evidence, tmp_path / "truth.json", target="P01-P0-01")
    assert report["status"] == "pass", report["issues"]


def test_cli_unbound_phase_requirement_cannot_close(tmp_path):
    repo, evidence = _truth_repo(tmp_path)
    output = tmp_path / "truth.json"
    with pytest.raises(SystemExit) as caught:
        _invoke(repo, evidence, output)
    assert caught.value.code == 1
    assert json.loads(output.read_text())["status"] == "fail"
