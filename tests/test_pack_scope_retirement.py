"""Ordinary-scope retirement is distinct from physical self-only pack presence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bcf_governance.tooling.governance_install.pack_manifest import load_pack_manifest
from bcf_governance.tooling.governance_install.upgrade import retire_self_authority_pack_surfaces


@pytest.mark.parametrize("scope,accepted", [("ordinary_adopter", False), ("self_authority", True)])
def test_retirement_overlap_requires_explicit_self_only_scope(
    tmp_path: Path, scope: str, accepted: bool,
) -> None:
    file = tmp_path / "helper.py"
    file.write_text("# authenticated producer source\n")
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    (tmp_path / ".bcf-pack-manifest.json").write_text(json.dumps({
        "schema_version": "2.0", "generated": [],
        "files": {"helper.py": {"sha256": digest, "operation": "copy",
                                 "installation_scope": scope}},
        "retired_files": {"helper.py": [digest]},
    }))

    def load():
        return load_pack_manifest(tmp_path, iter_template_files=lambda _root: [file],
                                  profile_choices=("lite",))

    if accepted:
        manifest = load()
        assert manifest.retired_files == {"helper.py": (digest,)}
        assert file.read_text() == "# authenticated producer source\n"
    else:
        with pytest.raises(ValueError, match="both active and retired"):
            load()


def test_successor_retires_previously_ordinary_prospective_module() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "template-repo/.bcf-pack-manifest.json").read_text())
    path = "scripts/_bcf_runtime/routine_controller_prospective.py"
    assert manifest["files"][path]["installation_scope"] == "self_authority"
    assert manifest["retired_files"][path]


def test_self_only_cleanup_preserves_authenticated_consumer_owned_bytes(tmp_path: Path) -> None:
    file = tmp_path / "helper.py"
    file.write_bytes(b"consumer-owned bytes\n")
    removed = retire_self_authority_pack_surfaces(
        target_root=tmp_path, entries={"helper.py": {"installation_scope": "self_authority"}},
        reject_destination=lambda *_: None, prune_empty_parents=lambda *_: None,
        excluded_paths=frozenset({"helper.py"}),
    )
    assert removed == []
    assert file.read_bytes() == b"consumer-owned bytes\n"
