from __future__ import annotations

from pathlib import Path

from bcf_governance.tooling.dependency_assurance import (
    InstalledDependencyInventory,
    audit_envelope,
    collect_installed_inventory,
    cyclonedx_sbom,
)


ROOT = Path(__file__).resolve().parents[1]


def _inventory() -> InstalledDependencyInventory:
    return InstalledDependencyInventory(
        roots=("example",),
        components=(
            {
                "type": "library",
                "name": "example",
                "version": "1.0",
                "bom-ref": "pkg:pypi/example@1.0",
            },
        ),
        dependencies=(({"ref": "pkg:pypi/example@1.0", "dependsOn": []}),),
        sha256="a" * 64,
    )


def test_known_vulnerability_and_scanner_failure_never_become_clean() -> None:
    vulnerable = audit_envelope(
        inventory=_inventory(),
        scanner_version="2.10.1",
        service="pypi",
        returncode=1,
        raw={
            "dependencies": [
                {
                    "name": "example",
                    "version": "1.0",
                    "vulns": [{"id": "PYSEC-EXAMPLE", "fix_versions": ["2.0"]}],
                }
            ]
        },
        diagnostic="known vulnerability",
    )
    unavailable = audit_envelope(
        inventory=_inventory(),
        scanner_version="2.10.1",
        service="pypi",
        returncode=2,
        raw=None,
        diagnostic="service unavailable",
    )
    assert vulnerable["status"] == "vulnerable"
    assert vulnerable["findings"][0]["name"] == "example"
    assert unavailable["status"] == "scanner_failure"


def test_exact_installed_inventory_drives_cyclonedx_sbom() -> None:
    inventory = collect_installed_inventory(ROOT)
    sbom = cyclonedx_sbom(inventory)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["metadata"]["properties"][0]["value"] == inventory.sha256
    assert all("version" in component for component in sbom["components"])
    assert all("version_constraint" not in component for component in sbom["components"])
    assert {component["name"] for component in sbom["components"]} >= {
        "build",
        "pip-audit",
        "pyyaml",
    }
