from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from bcf_governance.tooling import preflight


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


def _committed_repo(tmp_path: Path, relative: str, content: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "preflight@example.test")
    _git(repo, "config", "user.name", "Preflight Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fixture")
    return repo


def test_syntax_preflight_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "duplicate.yml", "owner: first\nowner: second\n")

    with pytest.raises(preflight.PreflightError, match="duplicate YAML key"):
        preflight._syntax_checks(repo)


def test_syntax_preflight_rejects_invalid_python(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "broken.py", "def broken(:\n    pass\n")

    with pytest.raises(preflight.PreflightError, match="syntax validation failed"):
        preflight._syntax_checks(repo)


def test_dirty_tree_fails_before_other_preflight_work(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "tracked.txt", "clean\n")
    (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(preflight.PreflightError, match="clean committed HEAD"):
        preflight._git_state(repo)


def test_preflight_allocates_session_only_after_all_deterministic_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    repo = tmp_path / "repo"
    repo.mkdir()

    monkeypatch.setattr(
        preflight, "_git_state", lambda _: {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
    )
    monkeypatch.setattr(preflight, "_syntax_checks", lambda _: {"python": 1})
    monkeypatch.setattr(preflight, "validate_repo_root", lambda _: None)
    monkeypatch.setattr(preflight, "_vendored_source_locks", lambda _: 0)
    monkeypatch.setattr(preflight, "check_all", lambda *_, **__: {"test": 1})
    monkeypatch.setattr(preflight, "_pr_context", lambda *_: {"applicable": False})
    monkeypatch.setattr(preflight, "_required_gates", lambda _: ["test"])

    class Session:
        manifest_path = tmp_path / "session.json"

    monkeypatch.setattr(
        preflight,
        "allocate_session",
        lambda *_, **__: (calls.append("allocated") or Session()),
    )

    report = preflight.run_preflight(
        repo,
        mode="release",
        python_executable=sys.executable,
        artifact_root=tmp_path / "evidence",
        trace=calls.append,
    )

    assert calls == [
        "git-state",
        "syntax",
        "governance",
        "source-locks",
        "test-manifests",
        "pr-context",
        "session",
        "allocated",
    ]
    assert report["session_manifest"] == (tmp_path / "session.json").as_posix()


def test_deterministic_failure_prevents_session_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(preflight, "_git_state", lambda _: {})
    monkeypatch.setattr(
        preflight,
        "_syntax_checks",
        lambda _: (_ for _ in ()).throw(preflight.PreflightError("syntax defect")),
    )
    monkeypatch.setattr(
        preflight, "allocate_session", lambda *_, **__: calls.append("allocated")
    )

    with pytest.raises(preflight.PreflightError, match="syntax defect"):
        preflight.run_preflight(
            repo,
            mode="release",
            python_executable=sys.executable,
            artifact_root=tmp_path / "evidence",
            trace=calls.append,
        )

    assert calls == ["git-state", "syntax"]
