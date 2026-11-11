"""Real source-comparison boundaries must ignore ambient Git repository selection."""
from __future__ import annotations

import os
import shutil

import pytest

from test_source_repository_environment import _git, _redirect, repositories
from bcf_governance.tooling.governance_validation import ci_state_matrix as matrix
from bcf_governance.tooling.governance_validation import preflight_repository_context as context

KINDS = ("none", "GIT_AUTHOR_NAME", "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE",
         "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "config-injection", "GIT_CONFIG_GLOBAL")
CONTEXT_KEYS = ("BCF_PROVIDER_EVENT", "GITHUB_EVENT_NAME", "BCF_INVOCATION_KIND",
                "BCF_COMPARISON_BASE_SHA", "BCF_ORIGIN_COMPARISON_BASE_SHA",
                "BCF_CALLER_COMPARISON_BASE_SHA", "BCF_PR_BASE_SHA")


def _comparison(monkeypatch, base):
    for name in CONTEXT_KEYS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BCF_PROVIDER_EVENT", "pull_request")
    monkeypatch.setenv("BCF_INVOCATION_KIND", "direct_event")
    for name in ("BCF_COMPARISON_BASE_SHA", "BCF_ORIGIN_COMPARISON_BASE_SHA", "BCF_PR_BASE_SHA"):
        monkeypatch.setenv(name, base)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("consumer", ("valid-pr", "foreign-pr", "local-matrix"))
def test_comparison_queries_bind_requested_repository(repositories, monkeypatch, kind, consumer):
    active, foreign, config, identity, _blobs, preserved = repositories
    own = identity["commit_sha"]
    other = _git(foreign, "rev-parse", "HEAD")
    for root in (active, foreign):
        _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    for name in CONTEXT_KEYS:
        monkeypatch.delenv(name, raising=False)
    if consumer != "local-matrix":
        _comparison(monkeypatch, own if consumer == "valid-pr" else other)
    _redirect(monkeypatch, kind, foreign, config)
    before = dict(os.environ)
    if consumer == "valid-pr":
        result = context.pr_context(active, "pr")
        assert result["base_sha"] == own, "comparison followed foreign Git state"
    elif consumer == "foreign-pr":
        with pytest.raises(ValueError, match=r"comparison base (commit is unavailable|SHA is not an ancestor of HEAD)"):
            context.pr_context(active, "pr")
    else:
        assert matrix._comparison_base(active) == own, "matrix comparison followed foreign Git state"
    assert dict(os.environ) == before
    assert {path: path.read_bytes() for path in preserved} == preserved


@pytest.mark.parametrize("consumer", ("valid-pr", "local-matrix"))
def test_comparison_queries_ignore_replaced_history(repositories, monkeypatch, consumer):
    active, foreign, _config, identity, _blobs, _preserved = repositories
    base = identity["commit_sha"]
    _git(active, "update-ref", "refs/remotes/origin/main", base)
    (active / "root.py").write_text("NEXT = True\n")
    _git(active, "add", "-f", "root.py")
    _git(active, "commit", "-qm", "descendant")
    head = _git(active, "rev-parse", "HEAD")
    shutil.copytree(foreign / ".git/objects", active / ".git/objects", dirs_exist_ok=True)
    _git(active, "replace", head, _git(foreign, "rev-parse", "HEAD"))
    for name in CONTEXT_KEYS:
        monkeypatch.delenv(name, raising=False)
    if consumer == "valid-pr":
        _comparison(monkeypatch, base)
    before = dict(os.environ)
    preserved = {active / ".git/index": (active / ".git/index").read_bytes(),
                 active / ".git/config": (active / ".git/config").read_bytes()}
    if consumer == "valid-pr":
        assert context.pr_context(active, "pr")["base_sha"] == base
    else:
        assert matrix._comparison_base(active) == base, "matrix followed replacement history"
    assert dict(os.environ) == before
    assert {path: path.read_bytes() for path in preserved} == preserved
