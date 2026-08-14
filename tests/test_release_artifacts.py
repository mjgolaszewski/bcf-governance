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
    missing = tmp_path / "template-repo/schemas"
    missing.rmdir()

    with pytest.raises(RuntimeError, match="sdist payload missing: template-repo/schemas"):
        release_artifacts.validate_sdist_payload(tmp_path)
