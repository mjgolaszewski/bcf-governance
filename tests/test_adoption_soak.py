from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _module():
    path = REPO_ROOT / ".github/scripts/run_adoption_soak.py"
    spec = importlib.util.spec_from_file_location("run_adoption_soak", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "scripts").mkdir()
    (repo / "scripts/alpha.py").write_text("old\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "--quiet", "-m", "fixture"], check=True)
    return repo


def test_changed_path_parser_preserves_first_porcelain_path(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "scripts/alpha.py").write_text("new\n", encoding="utf-8")

    assert _module()._changed_paths(repo) == ("scripts/alpha.py",)


def test_changed_path_parser_rejects_rename_shape(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    subprocess.run(
        ["git", "-C", str(repo), "mv", "scripts/alpha.py", "scripts/beta.py"],
        check=True,
    )

    with pytest.raises(RuntimeError, match="renamed or copied"):
        _module()._changed_paths(repo)
