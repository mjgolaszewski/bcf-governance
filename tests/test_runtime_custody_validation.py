from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bcf_governance import __version__
from bcf_governance.tooling.governance_validation.common import GovernanceValidationError
from bcf_governance.tooling.governance_validation.runtime_custody import (
    validate_runtime_custody,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _repo_with_lock(tmp_path: Path, *, version: str, overlap: bool = False) -> Path:
    schema = tmp_path / "schemas/bcf-runtime-lock.schema.json"
    schema.parent.mkdir(parents=True)
    schema.write_bytes((REPO_ROOT / "schemas/bcf-runtime-lock.schema.json").read_bytes())
    runtime = tmp_path / "scripts/_bcf_runtime/tool.py"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("runtime\n", encoding="utf-8")
    digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    lock = tmp_path / "governance/bcf-runtime-lock.json"
    lock.parent.mkdir(parents=True)
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
    return tmp_path


def test_local_unreleased_repository_needs_no_release_custody(tmp_path: Path) -> None:
    validate_runtime_custody(tmp_path)


def test_exact_current_normalized_custody_passes(tmp_path: Path) -> None:
    validate_runtime_custody(_repo_with_lock(tmp_path, version=__version__))


def test_stale_custody_fails_before_broader_governance_validation(tmp_path: Path) -> None:
    repo = _repo_with_lock(tmp_path, version="2.1.4")

    with pytest.raises(GovernanceValidationError, match="runtime_custody_version_mismatch"):
        validate_runtime_custody(repo)


def test_predecessor_without_local_schema_reaches_typed_version_check(
    tmp_path: Path,
) -> None:
    repo = _repo_with_lock(tmp_path, version="2.1.4")
    (repo / "schemas/bcf-runtime-lock.schema.json").unlink()

    with pytest.raises(GovernanceValidationError, match="runtime_custody_version_mismatch"):
        validate_runtime_custody(repo)


def test_legacy_overlap_requires_normalization_before_prospective_proof(
    tmp_path: Path,
) -> None:
    repo = _repo_with_lock(tmp_path, version=__version__, overlap=True)

    with pytest.raises(GovernanceValidationError, match="runtime_custody_not_normalized"):
        validate_runtime_custody(repo)
