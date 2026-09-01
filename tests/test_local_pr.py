from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from bcf_governance.tooling.ci_commands import _local_pr_command
from bcf_governance.tooling.local_pr import (
    LocalPRError,
    resolve_local_pr_context,
    run_local_pr_validation,
)


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    _git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
    repo = tmp_path / "repo"
    subprocess.run(["git", "clone", str(remote), str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "BCF Tests")
    (repo / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
    (repo / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "CHANGELOG.md", "source.py")
    _git(repo, "commit", "-m", "initial")
    _git(repo, "push", "-u", "origin", "main")
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-b", "feature")
    (repo / "source.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "source.py")
    _git(repo, "commit", "-m", "feature")
    return repo, base


def test_local_pr_cli_defaults_to_canonical_selected_interpreter_preflight() -> None:
    assert _local_pr_command(()) == (
        sys.executable,
        "scripts/preflight_governance.py",
        "--repo-root",
        ".",
        "--mode",
        "pr",
        "--python",
        sys.executable,
        "--format",
        "text",
    )
    assert _local_pr_command(("--", "python", "custom.py")) == (
        "python",
        "custom.py",
    )


def test_local_pr_context_fetches_default_branch_and_supplies_exact_event(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    context = resolve_local_pr_context(repo)
    assert context.default_branch == "main"
    assert context.base_sha == base
    script = (
        "import json,os,pathlib; "
        "event=json.loads(pathlib.Path(os.environ['GITHUB_EVENT_PATH']).read_text()); "
        "assert os.environ['BCF_ENFORCE_PR_CHANGELOG']=='true'; "
        "assert os.environ['GITHUB_EVENT_NAME']=='pull_request'; "
        "assert event['pull_request']['base']['sha']==os.environ['BCF_PR_BASE_SHA']; "
        "assert event['pull_request']['head']['sha']==os.environ['GITHUB_SHA']"
    )
    result = run_local_pr_validation(repo, command=(sys.executable, "-c", script))
    assert result.returncode == 0, result.stderr


def test_pr_only_changelog_rule_fails_locally_before_remote_ci(tmp_path: Path) -> None:
    repo, _base = _repository(tmp_path)
    script = (
        "import os,subprocess,sys; "
        "changed=subprocess.check_output(['git','diff','--name-only',os.environ['BCF_PR_BASE_SHA'],'HEAD'],text=True).splitlines(); "
        "sys.exit(0 if 'CHANGELOG.md' in changed else 19)"
    )
    red = run_local_pr_validation(repo, command=(sys.executable, "-c", script))
    assert red.returncode == 19
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n- feature\n", encoding="utf-8")
    _git(repo, "add", "CHANGELOG.md")
    _git(repo, "commit", "-m", "changelog")
    green = run_local_pr_validation(repo, command=(sys.executable, "-c", script))
    assert green.returncode == 0


def test_local_pr_rejects_head_without_default_branch_ancestry(tmp_path: Path) -> None:
    repo, _base = _repository(tmp_path)
    _git(repo, "checkout", "--orphan", "unrelated")
    _git(repo, "rm", "-rf", ".")
    (repo / "other.txt").write_text("unrelated\n", encoding="utf-8")
    _git(repo, "add", "other.txt")
    _git(repo, "commit", "-m", "unrelated")
    with pytest.raises(LocalPRError, match="does not descend"):
        resolve_local_pr_context(repo)


def test_local_pr_event_file_is_removed_after_execution(tmp_path: Path) -> None:
    repo, _base = _repository(tmp_path)
    script = "import os; print(os.environ['GITHUB_EVENT_PATH'])"
    result = run_local_pr_validation(repo, command=(sys.executable, "-c", script))
    assert result.returncode == 0
    assert not Path(result.stdout.strip()).exists()
