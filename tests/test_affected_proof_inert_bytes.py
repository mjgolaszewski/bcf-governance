"""Actual affected-proof consumers must use inert exact source populations."""
import os
import shlex

import pytest

from bcf_governance.tooling.evidence_execution import EvidenceError
from test_affected_proof_closure import _git, _repo, _subject
from test_affected_proof_subject import derive


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_index_flags_cannot_hide_changed_proof_source(tmp_path, flag):
    root, commit, tree, model = _repo(tmp_path)
    current = _subject(root)
    _git(root, "update-index", flag, "src/app.py")
    (root / "src/app.py").write_text("VALUE = 99\n")
    assert _git(root, "status", "--porcelain") == "", "native index witness did not hide bytes"
    with pytest.raises(EvidenceError, match="affected proof current subject"):
        derive(root, model, current, [(commit, tree)])


@pytest.mark.parametrize("destination", ["docs/archived.py", "docs/archived\ncopy.py"])
def test_rename_out_of_proof_scope_retains_removed_dependency(tmp_path, destination):
    root, commit, tree, model = _repo(tmp_path)
    _git(root, "config", "diff.renames", "true")
    _git(root, "mv", "src/app.py", destination)
    _git(root, "commit", "-qm", "move proof source to editorial path")
    result = derive(root, model, _subject(root), [(commit, tree)])
    assert result["classifications"][0]["classification"] == "required", "renamed source dependency falsely unaffected"
    assert result["raw_changed_paths"] == sorted(["src/app.py", destination]), "literal rename endpoints omitted or quoted"


def test_affected_query_does_not_execute_candidate_clean_filter(tmp_path):
    root, _, _, model = _repo(tmp_path)
    marker = tmp_path / "filter-fired"
    hook = tmp_path / "clean-filter"
    hook.write_text("#!/bin/sh\ntouch " + shlex.quote(str(marker)) + "\ncat\n")
    hook.chmod(0o700)
    _git(root, "config", "filter.observe.clean", shlex.quote(str(hook)))
    (root / ".gitattributes").write_text("src/*.py filter=observe\n")
    _git(root, "add", ".gitattributes", "src/app.py")
    _git(root, "commit", "-qm", "native filter setup")
    marker.unlink(missing_ok=True)
    path = root / "src/app.py"
    timestamp = path.stat().st_mtime + 5
    os.utime(path, (timestamp, timestamp))
    _git(root, "status", "--porcelain")
    assert marker.exists(), "native filter witness did not execute"
    marker.unlink()
    os.utime(path, (timestamp + 5, timestamp + 5))
    current = _subject(root)
    derive(root, model, current, [(current["commit_sha"], current["tree_sha"])])
    assert not marker.exists(), "affected-proof query executed candidate clean filter"


def test_affected_query_does_not_execute_candidate_fsmonitor(tmp_path):
    root, commit, tree, model = _repo(tmp_path)
    marker = tmp_path / "monitor-fired"
    hook = tmp_path / "monitor"
    hook.write_text("#!/bin/sh\ntouch " + shlex.quote(str(marker)) + '\nprintf "token\\0"\n')
    hook.chmod(0o700)
    _git(root, "config", "core.fsmonitor", str(hook))
    _git(root, "status", "--porcelain")
    assert marker.exists(), "native monitor witness did not execute"
    marker.unlink()
    derive(root, model, _subject(root), [(commit, tree)])
    assert not marker.exists(), "affected-proof query executed candidate monitor"


def test_affected_query_rejects_foreign_ambient_git_namespace(tmp_path, monkeypatch):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    left, commit, tree, _ = _repo(first)
    right, _, _, model = _repo(second)
    (right / "src/app.py").write_text("VALUE = 2\n")
    _git(right, "commit", "-qam", "different actual source")
    current = _subject(left)
    monkeypatch.setenv("GIT_DIR", str(left / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(left))
    with pytest.raises(EvidenceError, match="affected proof current subject"):
        derive(right, model, current, [(commit, tree)])


def test_affected_query_preserves_source_index_and_refs(tmp_path):
    root, commit, tree, model = _repo(tmp_path)
    before = (root / ".git/index").read_bytes()
    derive(root, model, _subject(root), [(commit, tree)])
    assert (root / ".git/index").read_bytes() == before
    assert _subject(root) == {"commit_sha": commit, "tree_sha": tree}
