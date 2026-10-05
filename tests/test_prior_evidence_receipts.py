"""Provisional downloaded transport has byte custody, never provider authority."""

from __future__ import annotations

from io import BytesIO
import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from bcf_governance.tooling.ci_github_bundle import canonical_json
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


def _archive_only_downloaded(tmp_path: Path) -> tuple[Path, dict]:
    root, manifest = _downloaded(tmp_path)
    for artifact in manifest["artifacts"]:
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for member in artifact["files"]:
                expanded = root / "expanded" / artifact["artifact_id"] / member["path"]
                archive.writestr(member["path"], expanded.read_bytes())
                expanded.unlink()
        raw = stream.getvalue()
        archive_path = root / "archives" / f"{artifact['artifact_id']}.zip"
        archive_path.write_bytes(raw)
        artifact["archive_sha256"] = hashlib.sha256(raw).hexdigest()
        artifact["provider_digest"] = "sha256:" + artifact["archive_sha256"]
    manifest["schema_version"] = "2.0"
    manifest["storage"] = "archive_only"
    stored = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name != "prior-evidence-transport.json"
    }
    manifest["bundle_sha256"] = hashlib.sha256(canonical_json(stored)).hexdigest()
    (root / "prior-evidence-transport.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    return root, manifest


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


def test_archive_only_receipts_are_verified_from_materialized_members(
    tmp_path: Path,
) -> None:
    root, manifest = _archive_only_downloaded(tmp_path)
    material = load_provisional_transport(
        REPO_ROOT, root, current_subject=manifest["main"],
    )
    assert [value["evidence_id"] for value in provisional_receipts(material)] == [
        "source"
    ]

    manifest["receipts"][0]["receipt_sha256"] = "0" * 64
    (root / "prior-evidence-transport.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    with pytest.raises(EvidenceError, match="receipt inventory differs"):
        load_provisional_transport(REPO_ROOT, root, current_subject=manifest["main"])


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
