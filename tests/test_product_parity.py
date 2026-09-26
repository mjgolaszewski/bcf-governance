from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.governance_validation.product_parity import (
    ProductParityError,
    validate_product_parity,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _contract() -> dict[str, object]:
    return yaml.safe_load(
        (REPO_ROOT / "governance/product-parity.yml").read_text(encoding="utf-8")
    )


def test_product_parity_binds_every_domain_to_canonical_installed_bytes_and_proofs() -> None:
    validate_product_parity(REPO_ROOT, _contract())


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    [
        ("missing_domain", "every required semantic domain"),
        ("missing_owner", "canonical owner is unavailable"),
        ("missing_self_proof", "self_proof node"),
        ("missing_adopter_proof", "lacks real installed-adopter proof"),
        ("missing_attack_proof", "attack_proof node"),
    ],
)
def test_product_parity_omission_drift_and_unproved_behavior_fail_closed(
    mutation: str, diagnostic: str
) -> None:
    contract = deepcopy(_contract())
    domains = contract["domains"]
    assert isinstance(domains, list)
    if mutation == "missing_domain":
        domains.pop()
    elif mutation == "missing_owner":
        domains[0]["canonical_owner"] = "bcf_governance/tooling/missing_owner.py"
    elif mutation == "missing_self_proof":
        domains[0]["self_proof"] = ["tests.missing::test_self"]
    elif mutation == "missing_adopter_proof":
        domains[0]["adopter_proof"] = [
            "tests.test_governance_truth::test_current_evidence_and_reconciliation_compute_closed"
        ]
    elif mutation == "missing_attack_proof":
        domains[0]["attack_proof"] = ["tests.missing::test_attack"]

    with pytest.raises(ProductParityError, match=diagnostic):
        validate_product_parity(REPO_ROOT, contract)
