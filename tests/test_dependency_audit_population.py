"""Security audit completion requires the exact requested dependency population."""
from dataclasses import replace
import hashlib
import json

import pytest
from bcf_governance.tooling.dependency_assurance import InstalledDependencyInventory, audit_envelope


def _inventory():
    result = InstalledDependencyInventory(roots=("example-package",), components=(
        {"name": "example-package", "version": "1.0"},), dependencies=(), sha256="a" * 64)

    return replace(result, sha256=hashlib.sha256(json.dumps(result.payload(), sort_keys=True, separators=(",", ":")).encode()).hexdigest())


def _row(**changes):
    return {"name": "example-package", "version": "1.0", "vulns": []} | changes


def _audit(rows, returncode=0, **extra):
    return audit_envelope(inventory=_inventory(), scanner_version="2.10.1", service="pypi",
                          returncode=returncode, raw={"dependencies": rows} | extra, diagnostic="")


def test_exact_complete_dependency_population_can_be_clean():
    assert _audit([_row()])["status"] == "clean"


def test_canonical_package_name_spelling_preserves_exact_identity():
    assert _audit([_row(name="Example_Package")])["status"] == "clean"


@pytest.mark.parametrize("rows,returncode", [
    ([], 0),
    ([_row(name="other")], 0),
    ([_row(version="2.0")], 0),
    ([_row(), _row(name="unexpected")], 0),
    ([_row(), _row(name="Example_Package")], 0),
    ([None], 0),
    (["example-package"], 0),
    ([_row(vulns=None)], 0),
    ([{"name": "example-package", "version": "1.0"}], 0),
    ([_row(vulns=[{}])], 1),
    ([_row(vulns=["CVE-EXAMPLE"])], 1),
    ([_row(vulns=[{"id": ""}])], 1),
    ([_row(skip_reason="not audited")], 0),
    ([_row(name="")], 0),
    ([_row(name="not a package")], 0),
    ([_row(version=True)], 0),
])
def test_incomplete_substituted_or_malformed_population_is_scanner_failure(rows, returncode):
    result = _audit(rows, returncode=returncode)
    assert result["status"] == "scanner_failure", "unqualified scanner population accepted"


def test_unexplained_nonzero_result_is_scanner_failure():
    assert _audit([_row()], returncode=1)["status"] == "scanner_failure"


def test_unsolicited_repair_cannot_claim_the_original_inventory_is_clean():
    assert _audit([_row()], fixes=[{"name": "example-package"}])["status"] == "scanner_failure"


@pytest.mark.parametrize("identifier", ["CVE-EXAMPLE", "GHSA-example"])
def test_any_reported_known_vulnerability_blocks_without_severity_filter(identifier):
    row = _row(vulns=[{"id": identifier, "fix_versions": []}])
    assert _audit([row], returncode=1)["status"] == "vulnerable"


def test_inconsistent_success_and_vulnerability_output_is_scanner_failure():
    assert _audit([_row(vulns=[{"id": "CVE-EXAMPLE"}])])["status"] == "scanner_failure"
