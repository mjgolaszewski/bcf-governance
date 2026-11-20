"""Isolated private audit consumers cannot accept a missing dependency population."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment
installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = 'import importlib.util,sys\nfrom pathlib import Path\nassert importlib.util.find_spec("bcf_governance") is None\nsys.path.insert(0,str(Path("scripts").resolve()))\nfrom _bcf_runtime.dependency_assurance import InstalledDependencyInventory,audit_envelope\ninventory=InstalledDependencyInventory(roots=("example",),components=({"name":"example","version":"1.0"},),dependencies=(),sha256="a"*64)\ndef audit(rows,code=0):\n return audit_envelope(inventory=inventory,scanner_version="2.10.1",service="pypi",returncode=code,raw={"dependencies":rows},diagnostic="")\nassert audit([])["status"]=="scanner_failure","installed empty scan falsely clean"\nrow={"name":"example","version":"1.0","vulns":[]}\nassert audit([row])["status"]=="clean"\nassert audit([dict(row,version="2.0")])["status"]=="scanner_failure"\nassert audit([row,row])["status"]=="scanner_failure"\nassert audit([dict(row,vulns=[{"id":"CVE-EXAMPLE","fix_versions":[]}])],1)["status"]=="vulnerable"\nprint("installed-exact-audit-population-qualified")\n'

def test_installed_exact_audit_population(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE], cwd=installed_consumer,
                            env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-exact-audit-population-qualified"


def test_installed_removed_population_guard_fails_named_control(installed_consumer, isolated_python):
    owner = installed_consumer / "scripts/_bcf_runtime/dependency_assurance.py"
    source = owner.read_text()
    guard = "complete = complete and observed == set(selected)"
    assert source.count(guard) == 1
    owner.write_text(source.replace(guard, "complete = complete"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE], cwd=installed_consumer,
                            env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed empty scan falsely clean" in result.stderr
