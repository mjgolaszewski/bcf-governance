from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

from bcf_governance.tooling.local_proof_bundles import (
    identity_digest,
    proof_identity,
    restore_proof_bundle,
    store_proof_bundle,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "schemas").mkdir()
    shutil.copy2(
        REPO_ROOT / "schemas/proof-bundle.schema.json",
        root / "schemas/proof-bundle.schema.json",
    )
    return root


def _identity() -> dict:
    return proof_identity(
        repository="owner/repo",
        base_commit="1" * 40,
        base_tree="2" * 40,
        candidate_commit="3" * 40,
        candidate_tree="4" * 40,
        evaluation_mode="pr",
        evaluation_target=None,
        verification_plan={"execution_dag": {"nodes": [{"producer": "test"}]}},
        controller={"state": "current", "authority": {}, "custody": {}},
        policy={"source": "exact"},
        toolchain={"python_version": "3.12", "node_version": "22.23.2"},
        python_executable=Path(sys.executable),
    )


def test_exact_local_proof_bundle_is_created_and_reused(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    (source / "evidence-session.json").write_text("{}\n", encoding="utf-8")
    (source / "test").mkdir()
    (source / "test/test.evidence.json").write_text(
        json.dumps({"result": "passed"}) + "\n", encoding="utf-8"
    )
    identity = _identity()

    created = store_proof_bundle(root, identity=identity, source=source)
    destination = tmp_path / "restored"
    restored = restore_proof_bundle(root, identity=identity, destination=destination)

    assert restored == created
    assert restored["authority"] == {
        "class": "local_non_authoritative",
        "provider_authority_substituted": False,
    }
    assert (destination / "test/test.evidence.json").read_bytes() == (
        source / "test/test.evidence.json"
    ).read_bytes()


def test_corrupt_exact_cache_is_retired_and_recomputed(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    (source / "receipt.json").write_text("{}\n", encoding="utf-8")
    identity = _identity()
    store_proof_bundle(root, identity=identity, source=source)
    cache = Path(_git(root, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    receipt = cache / "bcf/proof-bundles" / identity_digest(identity) / "evidence/receipt.json"
    receipt.write_text("changed\n", encoding="utf-8")

    assert restore_proof_bundle(
        root, identity=identity, destination=tmp_path / "unused"
    ) is None
    assert not receipt.parent.parent.exists()


def test_different_identity_cannot_reuse_proof(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    (source / "receipt.json").write_text("{}\n", encoding="utf-8")
    identity = _identity()
    store_proof_bundle(root, identity=identity, source=source)
    changed = {**identity, "candidate": {**identity["candidate"], "tree_sha": "5" * 40}}

    assert restore_proof_bundle(
        root, identity=changed, destination=tmp_path / "unused"
    ) is None
