from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
try:
    from scripts import doctor_governance_pack as doctor
    from scripts.governance_validation import phase_catalog
finally:
    sys.path.pop(0)


def test_hotfix_filename_helper_is_available_to_phase_catalog() -> None:
    assert phase_catalog._hotfix_stem("P11", 1) == "phase-11-hotfix01"


def test_placeholder_scan_skips_generated_dependency_directories(tmp_path: Path) -> None:
    dependency_doc = tmp_path / "node_modules/package/reference.md"
    dependency_doc.parent.mkdir(parents=True)
    dependency_doc.write_text("{{ generated_dependency_placeholder }}\n", encoding="utf-8")
    governed_doc = tmp_path / "plans/product-spec.yml"
    governed_doc.parent.mkdir(parents=True)
    governed_doc.write_text("value: concrete\n", encoding="utf-8")

    assert doctor._scan_placeholders(tmp_path) == []


def test_placeholder_scan_honors_gitignore_and_keeps_unignored_files(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("generated-docs/\n", encoding="utf-8")
    ignored = tmp_path / "generated-docs/reference.md"
    ignored.parent.mkdir()
    ignored.write_text("{{ ignored_placeholder }}\n", encoding="utf-8")
    governed = tmp_path / "plans/product-spec.yml"
    governed.parent.mkdir()
    governed.write_text("value: {{ real_placeholder }}\n", encoding="utf-8")

    assert doctor._scan_placeholders(tmp_path) == [
        "plans/product-spec.yml:1: {{ real_placeholder }}"
    ]


def test_doctor_reports_running_version_source_and_public_install(tmp_path: Path) -> None:
    report = doctor.doctor_repo(tmp_path)

    assert report["tooling"]["version"] == "0.5.0"
    assert report["tooling"]["package_source"]
    assert report["tooling"]["public_install"].endswith(
        "/v0.5.0/bcf_governance-0.5.0-py3-none-any.whl"
    )
