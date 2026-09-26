"""Mechanical self/adopter parity ownership and proof inventory validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class ProductParityError(ValueError):
    """The canonical self/adopter parity proof is incomplete or drifted."""


REQUIRED_DOMAINS = {
    "closure",
    "reuse",
    "invalidation",
    "negative_controls",
    "planning",
    "timing",
    "fixed_point",
    "controller_transition",
    "scope_boundaries",
}


def _mapping(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProductParityError(f"{context} must be a mapping")
    return value


def _nodes(value: object, context: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        raise ProductParityError(f"{context} must contain exact test nodes")
    return value


def validate_product_parity(repo_root: Path, contract: dict[str, Any]) -> None:
    """Require exact packaged owners plus self, adopter, and attack proof nodes."""
    root = repo_root.resolve()
    raw_domains = contract.get("domains")
    if not isinstance(raw_domains, list):
        raise ProductParityError("product parity domains must be a list")
    domains: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_domains):
        domain = _mapping(raw, f"product parity domains[{index}]")
        domain_id = domain.get("id")
        if not isinstance(domain_id, str) or domain_id in domains:
            raise ProductParityError("product parity domain ids must be unique strings")
        domains[domain_id] = domain
    if set(domains) != REQUIRED_DOMAINS:
        raise ProductParityError("product parity must cover every required semantic domain exactly once")
    manifest_nodes = set(
        (root / "governance/test-manifests/test.txt").read_text(encoding="utf-8").splitlines()
    )
    representative = _mapping(contract.get("representative_adopter"), "representative_adopter")
    representative_node = representative.get("proof_node")
    if not isinstance(representative_node, str) or representative_node not in manifest_nodes:
        raise ProductParityError("representative adopter proof node is absent from the canonical manifest")
    for domain_id, domain in domains.items():
        owner = domain.get("canonical_owner")
        if not isinstance(owner, str) or not owner.startswith("bcf_governance/tooling/"):
            raise ProductParityError(f"{domain_id} canonical owner is invalid")
        source = root / owner
        relative = Path(owner).relative_to("bcf_governance/tooling")
        installed = root / "template-repo/scripts/_bcf_runtime" / relative
        packaged = root / "bcf_governance/pack/template-repo/scripts/_bcf_runtime" / relative
        if not source.is_file() or source.is_symlink():
            raise ProductParityError(f"{domain_id} canonical owner is unavailable")
        if not installed.is_file() or installed.read_bytes() != source.read_bytes():
            raise ProductParityError(f"{domain_id} installed runtime differs from its canonical owner")
        if not packaged.is_file() or packaged.read_bytes() != source.read_bytes():
            raise ProductParityError(f"{domain_id} packaged runtime differs from its canonical owner")
        adopter_nodes = _nodes(domain.get("adopter_proof"), f"{domain_id}.adopter_proof")
        if representative_node not in adopter_nodes and not any(
            node.startswith("tests.test_profile_flows::test_full_profile_install_evidence_truth_flow")
            for node in adopter_nodes
        ):
            raise ProductParityError(f"{domain_id} lacks real installed-adopter proof")
        for role in ("self_proof", "adopter_proof", "attack_proof"):
            for node in _nodes(domain.get(role), f"{domain_id}.{role}"):
                if node not in manifest_nodes:
                    raise ProductParityError(f"{domain_id} {role} node {node} is absent from the canonical manifest")
