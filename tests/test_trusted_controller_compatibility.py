from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling.trusted_controller_compatibility import (
    TrustedControllerCompatibilityError,
    trusted_runtime_source_files,
    verify_trusted_controller_compatibility,
)


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write_runtime(root: Path) -> None:
    tooling = root / "bcf_governance/tooling"
    schemas = root / "bcf_governance/pack/template-repo/schemas"
    tooling.mkdir(parents=True)
    schemas.mkdir(parents=True)
    (root / "bcf_governance/__init__.py").write_text("", encoding="utf-8")
    (root / "bcf_governance/_version.py").write_text(
        '__version__ = "1.0.0rc1"\n', encoding="utf-8"
    )
    (root / "bcf_governance/cli.py").write_text(
        "from bcf_governance.tooling import ci_github_commands\n", encoding="utf-8"
    )
    (tooling / "__init__.py").write_text("", encoding="utf-8")
    (tooling / "ci_github_commands.py").write_text(
        "from .ci_github_api import GitHubAPI\n", encoding="utf-8"
    )
    (tooling / "ci_github_api.py").write_text(
        "class GitHubAPI: pass\n", encoding="utf-8"
    )
    (schemas / "ci-authority.schema.json").write_text("{}\n", encoding="utf-8")


def _repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "BCF Test")
    _git(root, "config", "user.email", "bcf-test@example.invalid")
    _write_runtime(root)
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "trusted runtime")
    return root, _git(root, "rev-parse", "HEAD")


def test_trusted_runtime_inventory_is_source_derived(tmp_path: Path) -> None:
    root, _ = _repository(tmp_path)

    assert trusted_runtime_source_files(root) == (
        "bcf_governance/__init__.py",
        "bcf_governance/_version.py",
        "bcf_governance/cli.py",
        "bcf_governance/pack/template-repo/schemas/ci-authority.schema.json",
        "bcf_governance/tooling/ci_github_api.py",
        "bcf_governance/tooling/ci_github_commands.py",
    )


def test_target_may_lag_unrelated_files_but_not_trusted_runtime(
    tmp_path: Path,
) -> None:
    root, target = _repository(tmp_path)
    (root / "README.md").write_text("documentation only\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-q", "-m", "unrelated change")

    report = verify_trusted_controller_compatibility(root, target_commit=target)
    assert report.target_commit == target
    assert report.as_dict()["source_file_count"] == 6

    api = root / "bcf_governance/tooling/ci_github_api.py"
    api.write_text("class GitHubAPI:\n    prerelease = True\n", encoding="utf-8")
    _git(root, "add", api.relative_to(root).as_posix())
    _git(root, "commit", "-q", "-m", "change trusted runtime")

    with pytest.raises(
        TrustedControllerCompatibilityError,
        match="target is stale.*ci_github_api.py",
    ):
        verify_trusted_controller_compatibility(root, target_commit=target)


def test_target_must_be_in_current_history(tmp_path: Path) -> None:
    root, _ = _repository(tmp_path)

    with pytest.raises(TrustedControllerCompatibilityError):
        verify_trusted_controller_compatibility(root, target_commit="f" * 40)
