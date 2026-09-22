"""Provisional downloaded transport has byte custody, never provider authority."""

from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import zipfile

import pytest

from bcf_governance.tooling.evidence_execution import EvidenceError
from bcf_governance.tooling.prior_evidence_receipts import (
    load_provisional_transport,
    provisional_receipts,
)
from tests.test_ci_prior_evidence_auth import _transport


REPO_ROOT = Path(__file__).resolve().parents[1]


def _downloaded(tmp_path: Path) -> tuple[Path, dict]:
    raw, manifest = _transport()
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        for name in archive.namelist():
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))
    return tmp_path, manifest


def test_observed_transport_is_closed_but_not_authenticated(tmp_path: Path) -> None:
    root, manifest = _downloaded(tmp_path)
    material = load_provisional_transport(
        REPO_ROOT, root, current_subject=manifest["main"],
    )
    assert material.manifest == manifest
    assert len(material.manifest["receipts"]) == 1
    assert len(material.observed_digest) == 64
    assert not hasattr(material, "artifact")
    receipts = provisional_receipts(material)
    assert len(receipts) == 1
    assert receipts[0]["evidence_id"] == "source"
    assert receipts[0]["artifact_sha256"] == manifest["artifacts"][0]["archive_sha256"]
    with pytest.raises(EvidenceError, match="bundle digest mismatch"):
        load_provisional_transport(
            REPO_ROOT, root, current_subject=manifest["main"],
            expected_digest="0" * 64,
        )


def test_provisional_transport_rejects_wrong_subject_or_schema(tmp_path: Path) -> None:
    root, manifest = _downloaded(tmp_path)
    with pytest.raises(EvidenceError, match="main subject is not current"):
        load_provisional_transport(
            REPO_ROOT, root,
            current_subject={**manifest["main"], "tree_sha": "0" * 40},
        )
    manifest.pop("repository")
    (root / "prior-evidence-transport.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    with pytest.raises(EvidenceError, match="transport schema is invalid"):
        load_provisional_transport(
            REPO_ROOT, root, current_subject=manifest["main"],
        )
