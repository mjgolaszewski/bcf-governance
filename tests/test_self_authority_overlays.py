from __future__ import annotations

import json
import hashlib
import shutil
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.governance_validation.self_authority_overlays import (
    SelfAuthorityOverlayError,
    validate_self_authority_overlays,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _copy_contract(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in (
        "governance/self-overlays.yml",
        "governance/self-governance-policy.yml",
        "governance/ci-graph.yml",
        "template-repo/.bcf-pack-manifest.json",
        "governance/automation-producers.yml",
        "governance/ci-authority.yml",
        "governance/github-protection.yml",
        "governance/break-glass-recovery.yml",
        "governance/public-contracts.yml",
        "schemas/self-authority-overlays.schema.json",
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, target)
    graph = yaml.safe_load((root / "governance/ci-graph.yml").read_text(encoding="utf-8"))
    for ref in graph["extensions"]:
        source = REPO_ROOT / ref["path"]
        target = root / ref["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        extension = yaml.safe_load(source.read_text(encoding="utf-8"))
        for workflow in extension["workflows"]:
            rendered = root / workflow["path"]
            rendered.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / workflow["path"], rendered)
    return root


def _contract(root: Path) -> dict[str, object]:
    return yaml.safe_load((root / "governance/self-overlays.yml").read_text(encoding="utf-8"))


def _write_contract(root: Path, payload: dict[str, object]) -> None:
    (root / "governance/self-overlays.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )


def test_repository_self_overlays_have_exact_unique_non_leaking_ownership() -> None:
    generated = validate_self_authority_overlays(REPO_ROOT)

    assert set(generated) == {
        "self-controller-custody",
        "self-publication-authority",
        "self-recovery-authority",
        "self-repository-authority",
    }
    assert ".github/workflows/bcf-release-publisher.yml" in generated[
        "self-publication-authority"
    ]


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    [
        ("undeclared_extension", "every self CI graph extension"),
        ("duplicate_surface", "owned by multiple overlays"),
        ("pack_surface_leak", "leaks into the adopter pack"),
        ("workflow_leak", "generated self workflow"),
        ("wrong_proposition", "violates schema"),
        ("missing_surface", "is unavailable"),
    ],
)
def test_self_overlay_drift_and_leakage_fail_closed(
    tmp_path: Path, mutation: str, diagnostic: str
) -> None:
    root = _copy_contract(tmp_path)
    contract = _contract(root)
    overlays = contract["overlays"]
    assert isinstance(overlays, list)
    if mutation == "undeclared_extension":
        extension_path = root / "governance/ci-extensions/bcf-undeclared.yml"
        extension_path.write_text(
            yaml.safe_dump(
                {
                    "extension": {"id": "bcf-undeclared"},
                    "workflows": [],
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        graph_path = root / "governance/ci-graph.yml"
        graph = yaml.safe_load(graph_path.read_text(encoding="utf-8"))
        graph["extensions"].append(
            {
                "id": "bcf-undeclared",
                "path": "governance/ci-extensions/bcf-undeclared.yml",
                "sha256": hashlib.sha256(extension_path.read_bytes()).hexdigest(),
            }
        )
        graph_path.write_text(yaml.safe_dump(graph, sort_keys=False), encoding="utf-8")
    elif mutation == "duplicate_surface":
        overlays[1]["authority_surfaces"].append("governance/self-governance-policy.yml")
    elif mutation == "wrong_proposition":
        overlays[0]["proposition"] = "publish_pre_certified_immutable_release_bytes"
    elif mutation == "missing_surface":
        overlays[0]["authority_surfaces"].append("governance/missing-authority.yml")
    elif mutation in {"pack_surface_leak", "workflow_leak"}:
        manifest_path = root / "template-repo/.bcf-pack-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        leaked = (
            "governance/self-governance-policy.yml"
            if mutation == "pack_surface_leak"
            else ".github/workflows/bcf-release-publisher.yml"
        )
        manifest["files"][leaked] = {"operation": "copy", "sha256": "0" * 64}
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _write_contract(root, contract)

    with pytest.raises(SelfAuthorityOverlayError, match=diagnostic):
        validate_self_authority_overlays(root)


def test_canonical_opt_in_controller_path_is_product_not_self_overlay() -> None:
    contract = _contract(REPO_ROOT)
    surfaces = {
        path
        for overlay in contract["overlays"]
        for path in overlay["authority_surfaces"]
    }
    manifest = json.loads(
        (REPO_ROOT / "template-repo/.bcf-pack-manifest.json").read_text(encoding="utf-8")
    )

    assert "governance/ci-extensions/bcf-controller-rotation.yml" in manifest["files"]
    assert "governance/ci-extensions/bcf-controller-rotation.yml" not in surfaces
