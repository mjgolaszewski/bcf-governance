from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from bcf_governance import __version__

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
try:
    from scripts import doctor_governance_pack as doctor
    from scripts.governance_validation import phase_catalog, release_gates
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


def test_placeholder_scan_excludes_only_declared_template_vendors(tmp_path: Path) -> None:
    manifest = tmp_path / "governance/artifact-manifest.yml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        "nested_governance:\n"
        "  declared_vendors:\n"
        "  - {path: templates/, refresh_policy: canonical_template_source}\n",
        encoding="utf-8",
    )
    template = tmp_path / "templates/README.md"
    template.parent.mkdir()
    template.write_text("# {{ PROJECT_NAME }}\n", encoding="utf-8")
    application = tmp_path / "plans/product-spec.yml"
    application.parent.mkdir()
    application.write_text("value: {{ real_placeholder }}\n", encoding="utf-8")

    assert doctor._scan_placeholders(tmp_path) == [
        "plans/product-spec.yml:1: {{ real_placeholder }}"
    ]


def test_doctor_reports_running_version_source_and_public_install(tmp_path: Path) -> None:
    report = doctor.doctor_repo(tmp_path)

    assert report["tooling"]["version"] == __version__
    assert report["tooling"]["package_source"]
    assert report["tooling"]["public_install"].endswith(
        f"/v{__version__}/bcf_governance-{__version__}-py3-none-any.whl"
    )


def _write_runtime_custody(
    repo: Path,
    *,
    version: str,
    overlap: bool = False,
) -> None:
    schema = repo / "schemas/bcf-runtime-lock.schema.json"
    schema.parent.mkdir(parents=True, exist_ok=True)
    schema.write_bytes((REPO_ROOT / "schemas/bcf-runtime-lock.schema.json").read_bytes())
    runtime = repo / "scripts/_bcf_runtime/tool.py"
    runtime.parent.mkdir(parents=True, exist_ok=True)
    runtime.write_text("runtime\n", encoding="utf-8")
    digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    lock = repo / "governance/bcf-runtime-lock.json"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "version": version,
                "source_repository": "mjgolaszewski/bcf-governance",
                "source_repository_id": 1207503211,
                "source_commit": "a" * 40,
                "release_id": 1,
                "release_url": (
                    "https://github.com/mjgolaszewski/bcf-governance/"
                    f"releases/tag/v{version}"
                ),
                "wheel_sha256": "b" * 64,
                "source_archive_sha256": "c" * 64,
                "checksum_manifest_sha256": "d" * 64,
                "official_installer_adaptations": {},
                "files": {"scripts/_bcf_runtime/tool.py": digest},
                "preserved_consumer_files": (
                    {"scripts/_bcf_runtime/tool.py": digest} if overlap else {}
                ),
            }
        ),
        encoding="utf-8",
    )


def test_doctor_uses_canonical_normalized_custody_classification(tmp_path: Path) -> None:
    _write_runtime_custody(tmp_path, version=__version__)

    report = doctor.doctor_repo(tmp_path)

    assert not any("runtime_custody" in value for value in report["blockers"])
    assert not any("legacy ownership overlap" in value for value in report["warnings"])


def test_doctor_reports_legacy_overlap_and_version_without_reinterpreting_it(
    tmp_path: Path,
) -> None:
    _write_runtime_custody(tmp_path, version="2.1.4", overlap=True)

    report = doctor.doctor_repo(tmp_path)

    assert "runtime_custody_version_mismatch: installed=2.1.4 executing=2.1.5" in report[
        "blockers"
    ]
    assert any("legacy ownership overlap" in value for value in report["warnings"])


def test_doctor_classifies_predecessor_lock_without_local_schema(tmp_path: Path) -> None:
    _write_runtime_custody(tmp_path, version="2.1.4", overlap=True)
    (tmp_path / "schemas/bcf-runtime-lock.schema.json").unlink()

    report = doctor.doctor_repo(tmp_path)

    assert not any("lock_unreadable" in value for value in report["blockers"])
    assert "runtime_custody_version_mismatch: installed=2.1.4 executing=2.1.5" in report[
        "blockers"
    ]
    assert any("legacy ownership overlap" in value for value in report["warnings"])


def _release_check_repo(tmp_path: Path, *, contract_version: str, capture: str) -> Path:
    (tmp_path / "governance-profile.yml").write_text(
        "profile_contract_version: '" + contract_version + "'\n"
        "release_gate_profile:\n"
        "  gates:\n"
        "    test: {target: test, status: required, command_policy: automated_tests}\n",
        encoding="utf-8",
    )
    (tmp_path / "Makefile.fragment").write_text(
        "release-check:\n"
        f"\t{capture}\n"
        "\tpython scripts/governance_truth.py\n"
        "test:\n"
        "\tpython -m pytest\n",
        encoding="utf-8",
    )
    return tmp_path


def test_doctor_accepts_canonical_selective_plan_capture_for_v3(tmp_path: Path) -> None:
    repo = _release_check_repo(
        tmp_path,
        contract_version="3.0",
        capture=(
            "python scripts/capture_governance_shard.py --all-planned "
            "--session-manifest evidence-session.json"
        ),
    )

    blockers, _, _ = doctor._release_gate_diagnostics(repo)

    assert "release-check does not capture typed gate evidence" not in blockers


def test_doctor_uses_generated_release_owner_when_consumer_makefile_is_preserved(
    tmp_path: Path,
) -> None:
    repo = _release_check_repo(
        tmp_path,
        contract_version="3.0",
        capture="python scripts/capture_governance_shard.py --all-planned",
    )
    (repo / "Makefile").write_text(
        "application:\n\t@echo application\n\n"
        "release-check:\n\t@for gate in test; do echo $$gate; done\n",
        encoding="utf-8",
    )

    blockers, _, _ = doctor._release_gate_diagnostics(repo)

    assert "release-check does not capture typed gate evidence" not in blockers
    assert release_gates.canonical_release_check_command(repo) == (
        "make -f Makefile.fragment release-check"
    )


def test_doctor_rejects_v3_shard_capture_that_ignores_selective_plan(
    tmp_path: Path,
) -> None:
    repo = _release_check_repo(
        tmp_path,
        contract_version="3.0",
        capture=(
            "python scripts/capture_governance_shard.py --shard-index 0 "
            "--shard-count 1"
        ),
    )

    blockers, _, actions = doctor._release_gate_diagnostics(repo)

    assert "release-check does not capture typed gate evidence" in blockers
    assert any("--all-planned" in action for action in actions)


def test_doctor_preserves_direct_typed_capture_for_v1(tmp_path: Path) -> None:
    repo = _release_check_repo(
        tmp_path,
        contract_version="1.0",
        capture="python scripts/governance_evidence.py run --gate test",
    )

    blockers, _, _ = doctor._release_gate_diagnostics(repo)

    assert "release-check does not capture typed gate evidence" not in blockers
