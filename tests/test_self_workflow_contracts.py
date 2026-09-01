from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from bcf_governance.tooling.self_workflow_contracts import (
    SelfWorkflowContractError,
    validate_self_workflow_contracts,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path) -> Path:
    shutil.copytree(REPO_ROOT / ".github/workflows", tmp_path / ".github/workflows")
    for relative in (
        "governance/self-governance-policy.yml",
        "release/wheelhouse-manifest.yml",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, target)
    return tmp_path


def test_self_workflow_contracts_are_one_preflight_owned_mechanical_control() -> None:
    assert validate_self_workflow_contracts(REPO_ROOT) > 0


@pytest.mark.parametrize(
    ("relative", "search", "replacement", "diagnostic"),
    (
        (
            ".github/workflows/bcf-release-publisher.yml",
            "if: ${{ github.actor == 'mjgolaszewski' && github.ref == 'refs/heads/main' }}",
            "if: ${{ true }}",
            "activation",
        ),
        (
            ".github/workflows/bcf-release-publisher.yml",
            "ci-github release resolve-publication",
            "ci-github release inspect",
            "mechanical input resolution",
        ),
        (
            ".github/workflows/bcf-release-publisher.yml",
            "artifact-ids: ${{ steps.resolve.outputs.receipt_artifact_id }}",
            'artifact-ids: "71"',
            "resolver-owned",
        ),
        (
            ".github/workflows/bcf-release-publisher.yml",
            "receipt/assets/*",
            "receipt/assets/*.whl",
            "attestation inventory",
        ),
        (
            ".github/workflows/bcf-release-publisher.yml",
            '          "$control_root/bin/bcf" ci-github release resolve-publication \\',
            '          sleep 1\n          "$control_root/bin/bcf" ci-github release resolve-publication \\',
            "coordination",
        ),
        (
            ".github/workflows/governance.yml",
            "name: Validate governance front door\n    runs-on: ubuntu-latest",
            "name: Validate governance front door\n    runs-on: ubuntu-24.04",
            "runner drifted",
        ),
        (
            ".github/workflows/bcf-trusted-control-bootstrap.yml",
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "check out candidate",
        ),
        (
            ".github/workflows/bcf-release-publisher.yml",
            "name: Publish pre-certified immutable release bytes",
            "name: publish",
            "not descriptive",
        ),
        (
            "governance/self-governance-policy.yml",
            "hosted_fallback_allowed: false",
            "hosted_fallback_allowed: true",
            "undeclared fallback",
        ),
        (
            "governance/self-governance-policy.yml",
            "privileged_publication_enabled: true",
            "privileged_publication_enabled: false",
            "not mechanically activated",
        ),
        (
            ".github/workflows/bcf-release-publisher.yml",
            "GITHUB_TOKEN: ${{ secrets.BCF_RELEASE_ADMIN_TOKEN }}",
            "GITHUB_TOKEN: ${{ github.token }}",
            "administration authority",
        ),
    ),
    ids=(
        "owner-guard",
        "resolver",
        "provider-coordinate",
        "attestation-inventory",
        "idle-runner",
        "candidate-route",
        "trusted-checkout",
        "job-name",
        "hosted-fallback",
        "publication-policy",
        "publication-credential",
    ),
)
def test_self_workflow_contract_mutants_fail_at_the_canonical_owner(
    tmp_path: Path,
    relative: str,
    search: str,
    replacement: str,
    diagnostic: str,
) -> None:
    root = _fixture(tmp_path)
    path = root / relative
    raw = path.read_text(encoding="utf-8")
    assert raw.count(search) == 1
    path.write_text(raw.replace(search, replacement), encoding="utf-8")
    with pytest.raises(SelfWorkflowContractError, match=diagnostic):
        validate_self_workflow_contracts(root)
