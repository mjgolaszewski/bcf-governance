from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / ".github/scripts/test_release_artifacts.py"
spec = importlib.util.spec_from_file_location("release_artifacts", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load release artifact verifier")
release_artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_artifacts)


def test_current_source_contains_complete_sdist_test_payload() -> None:
    release_artifacts.validate_sdist_payload(REPO_ROOT)


def test_missing_sdist_payload_mutant_is_rejected(tmp_path: Path) -> None:
    for relative in release_artifacts.REQUIRED_SDIST_PATHS:
        (tmp_path / relative).mkdir(parents=True, exist_ok=True)
    for relative in release_artifacts.REQUIRED_SDIST_FILES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    missing = tmp_path / "audits"
    missing.rmdir()

    with pytest.raises(RuntimeError, match="sdist payload missing: audits"):
        release_artifacts.validate_sdist_payload(tmp_path)


def test_sdist_source_custody_tracks_the_complete_extracted_tree(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "source.txt").write_text("source\n", encoding="utf-8")
    (tmp_path / "nested/evidence.txt").write_text("evidence\n", encoding="utf-8")

    release_artifacts.initialize_source_custody(tmp_path)

    assert release_artifacts.subprocess.run(
        ["git", "ls-files"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.splitlines() == ["nested/evidence.txt", "source.txt"]
    assert release_artifacts.subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""
