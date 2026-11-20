"""Receipt verification cannot hide source changes or execute candidate Git code."""
import os
import shlex

import pytest

from bcf_governance.tooling import truth_receipts as owner
from test_affected_proof_closure import _git, _repo, _subject


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_receipt_paths_retain_hidden_changed_bytes(tmp_path, flag):
    root, commit, _, _ = _repo(tmp_path)
    _git(root, "update-index", flag, "src/app.py")
    (root / "src/app.py").write_text("VALUE = 99\n")
    assert _git(root, "status", "--porcelain") == ""
    assert owner._changed_paths(root, commit) == ["src/app.py"], "receipt hidden source omitted"


def test_receipt_paths_retain_both_rename_endpoints(tmp_path):
    root, commit, _, _ = _repo(tmp_path)
    _git(root, "mv", "src/app.py", "docs/archived.py")
    _git(root, "commit", "-qm", "rename source")
    assert owner._changed_paths(root, commit) == ["docs/archived.py", "src/app.py"], "receipt removed dependency omitted"


def test_receipt_query_does_not_execute_candidate_clean_filter(tmp_path):
    root, commit, _, _ = _repo(tmp_path)
    marker = tmp_path / "filter-fired"
    hook = tmp_path / "clean-filter"
    hook.write_text("#!/bin/sh\ntouch " + shlex.quote(str(marker)) + "\ncat\n")
    hook.chmod(0o700)
    _git(root, "config", "filter.observe.clean", shlex.quote(str(hook)))
    (root / ".gitattributes").write_text("src/*.py filter=observe\n")
    _git(root, "add", ".gitattributes")
    _git(root, "commit", "-qm", "native filter setup")
    marker.unlink(missing_ok=True)
    path = root / "src/app.py"
    path.write_text("VALUE = 2\n")
    timestamp = path.stat().st_mtime + 5
    os.utime(path, (timestamp, timestamp))
    _git(root, "status", "--porcelain")
    assert marker.exists(), "native filter witness did not execute"
    marker.unlink()
    os.utime(path, (timestamp + 5, timestamp + 5))
    paths = owner._changed_paths(root, commit)
    assert paths is not None and "src/app.py" in paths
    assert not marker.exists(), "receipt query executed candidate clean filter"


def test_receipt_query_does_not_execute_candidate_fsmonitor(tmp_path):
    root, commit, _, _ = _repo(tmp_path)
    marker = tmp_path / "monitor-fired"
    hook = tmp_path / "monitor"
    hook.write_text("#!/bin/sh\ntouch " + shlex.quote(str(marker)) + '\nprintf "token\\0"\n')
    hook.chmod(0o700)
    _git(root, "config", "core.fsmonitor", str(hook))
    _git(root, "status", "--porcelain")
    assert marker.exists(), "native monitor witness did not execute"
    marker.unlink()
    owner._changed_paths(root, commit)
    assert not marker.exists(), "receipt query executed candidate monitor"


def test_receipt_query_ignores_foreign_ambient_git_namespace(tmp_path, monkeypatch):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    left, commit, _, _ = _repo(first)
    right, _, _, _ = _repo(second)
    (right / "src/app.py").write_text("VALUE = 2\n")
    _git(right, "commit", "-qam", "actual changed source")
    monkeypatch.setenv("GIT_DIR", str(left / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(left))
    assert owner._changed_paths(right, commit) == ["src/app.py"], "receipt ambient namespace hid actual source"


def test_unknown_prior_history_is_explicit_at_receipt_subject_consumer(tmp_path):
    root, _, _, _ = _repo(tmp_path)
    current = _subject(root) | {"tracked_clean": True, "untracked_clean": True}
    subject = current | {"binding": "exact_tree", "commit_sha": "f" * 40,
                         "execution_tree_sha": current["tree_sha"]}
    issues, observation = owner._subject_issues(root, {"subject": subject, "kind": "gate"}, current, set())
    assert "source_change_population_unavailable" in issues, "unknown receipt history silently empty"
    assert observation["paths"] == []


def test_clean_matching_receipt_paths_remain_empty_without_index_changes(tmp_path):
    root, commit, _, _ = _repo(tmp_path)
    before = (root / ".git/index").read_bytes()
    assert owner._changed_paths(root, commit) == []
    assert (root / ".git/index").read_bytes() == before
