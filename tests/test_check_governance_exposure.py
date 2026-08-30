from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "scripts" / "check_governance_exposure.py"


def _load_scanner_module():
    spec = importlib.util.spec_from_file_location("check_governance_exposure", SCANNER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_exposure_scan_passes_clean_governed_artifacts(tmp_path: Path) -> None:
    scanner = _load_scanner_module()
    repo = tmp_path / "repo"
    (repo / "plans").mkdir(parents=True)
    (repo / "plans/phase-history.yml").write_text(
        "document:\n  path: plans/phase-history.yml\nentries: []\n",
        encoding="utf-8",
    )

    report = scanner.scan_exposures(repo, paths=["plans"])

    assert report.status == "pass"
    assert report.scanned_files == 1
    assert report.findings == []


def test_exposure_scan_does_not_treat_dotted_semantic_ids_as_hostnames(
    tmp_path: Path,
) -> None:
    scanner = _load_scanner_module()
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/semantic.yml").write_text(
        "semantic_id: governance.local-pr-context.v1\n",
        encoding="utf-8",
    )

    report = scanner.scan_exposures(repo, paths=["governance"])

    assert report.status == "pass"
    assert report.findings == []


def test_exposure_scan_flags_local_paths_and_private_infra(tmp_path: Path) -> None:
    scanner = _load_scanner_module()
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/notes.md").write_text(
        "workspace /docker/internal/repo\n"
        "host api.service.internal\n"
        "address 10.12.0.4\n",
        encoding="utf-8",
    )

    report = scanner.scan_exposures(repo, paths=["governance"])

    assert report.status == "fail"
    assert {finding.pattern for finding in report.findings} == {
        "local_workspace_path",
        "private_hostname",
        "private_ipv4",
    }


def test_exposure_scan_respects_inline_allow_markers(tmp_path: Path) -> None:
    scanner = _load_scanner_module()
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/notes.md").write_text(
        "example /docker/internal/repo # governance-exposure: allow\n",
        encoding="utf-8",
    )

    report = scanner.scan_exposures(repo, paths=["governance"])

    assert report.status == "pass"
