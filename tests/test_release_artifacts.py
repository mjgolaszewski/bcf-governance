from __future__ import annotations

import importlib.util
from pathlib import Path
from xml.etree import ElementTree
import zipfile

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


def test_pyproject_packages_every_discovered_runtime_asset() -> None:
    admitted = release_artifacts.validate_package_data_contract(REPO_ROOT)
    assert "bcf_governance/tooling/semantic_ownership_typescript.mjs" in admitted


def test_missing_runtime_asset_is_rejected_before_wheel_execution(tmp_path: Path) -> None:
    source = tmp_path / "source"
    asset = source / "bcf_governance/tooling/analyzer.mjs"
    asset.parent.mkdir(parents=True)
    asset.write_text("export {};\n", encoding="utf-8")
    (source / "pyproject.toml").write_text(
        '[tool.setuptools.package-data]\nbcf_governance = ["tooling/*.mjs"]\n',
        encoding="utf-8",
    )
    wheel = tmp_path / "bcf_governance-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("bcf_governance/__init__.py", "")

    with pytest.raises(RuntimeError, match="wheel missing runtime assets"):
        release_artifacts.validate_wheel_runtime_assets(wheel, source)

    with zipfile.ZipFile(wheel, "a") as archive:
        archive.write(asset, "bcf_governance/tooling/analyzer.mjs")
    release_artifacts.validate_wheel_runtime_assets(wheel, source)


def test_package_metadata_cannot_omit_discovered_runtime_assets(tmp_path: Path) -> None:
    asset = tmp_path / "bcf_governance/tooling/analyzer.mjs"
    asset.parent.mkdir(parents=True)
    asset.touch()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.setuptools.package-data]\nbcf_governance = []\n', encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="package data excludes runtime assets"):
        release_artifacts.validate_package_data_contract(tmp_path)


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

    suite = ElementTree.Element("testsuite")
    for classname, name in sorted(release_artifacts.ALLOWED_SDIST_CUSTODY_SKIPS):
        case = ElementTree.SubElement(
            suite, "testcase", {"classname": classname, "name": name}
        )
        ElementTree.SubElement(case, "skipped")
    junit = tmp_path / "sdist-tests.xml"
    ElementTree.ElementTree(suite).write(junit, encoding="utf-8")
    release_artifacts.validate_sdist_test_skips(junit)
    suite.remove(next(iter(suite)))
    ElementTree.ElementTree(suite).write(junit, encoding="utf-8")
    with pytest.raises(RuntimeError, match="sdist test skip contract mismatch"):
        release_artifacts.validate_sdist_test_skips(junit)
