"""Installed audit subjects cannot reuse a digest after in-memory mutation."""
import subprocess

import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = '''import importlib.util,hashlib,json,sys,tempfile
from dataclasses import replace
from pathlib import Path
assert importlib.util.find_spec("bcf_governance") is None
sys.path.insert(0,str(Path("scripts").resolve()))
from _bcf_runtime import dependency_assurance as owner
def inventory():
 value=owner.InstalledDependencyInventory(roots=("example",),components=({"name":"example","version":"1.0"},),dependencies=({"ref":"example","dependsOn":[]},),sha256="")
 return replace(value,sha256=hashlib.sha256(json.dumps(value.payload(),sort_keys=True,separators=(",",":")).encode()).hexdigest())
def audit(value,raw=None):
 if raw is None:raw={"dependencies":[{"name":"example","version":value.components[0]["version"],"vulns":[]}]}
 return owner.audit_envelope(inventory=value,scanner_version="2.10.1",service="pypi",returncode=0,raw=raw,diagnostic="")
subject=inventory()
assert audit(subject)["status"]=="clean"
subject.components[0]["version"]="2.0"
assert audit(subject)["status"]=="scanner_failure","installed stale inventory was accepted under its old digest"
with tempfile.TemporaryDirectory() as directory:
 target=Path(directory)/"not-allocated/input.txt"
 try:owner.write_frozen_requirements(subject,target)
 except owner.DependencyAssuranceError:pass
 else:raise AssertionError("installed stale requirements were exported")
 assert not target.parent.exists()
 try:owner.cyclonedx_sbom(subject)
 except owner.DependencyAssuranceError:pass
 else:raise AssertionError("installed stale SBOM was published")
 subject=inventory();payload=subject.payload();payload["components"][0]["version"]="changed"
 assert subject.components[0]["version"]=="1.0","installed payload aliases inventory"
 report=owner.cyclonedx_sbom(subject);report["dependencies"][0]["dependsOn"].append("changed")
 assert subject.dependencies[0]["dependsOn"]==[],"installed SBOM aliases inventory"
 raw={"dependencies":[{"name":"example","version":"1.0","vulns":[]}]}
 report=audit(subject,raw);raw["dependencies"][0]["vulns"].append({"id":"CVE-EXAMPLE"})
 assert report["raw_result"]["dependencies"][0]["vulns"]==[],"installed audit aliases scanner input"
print("installed-dependency-snapshot-qualified")
'''


def test_installed_owned_snapshot_consumers(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-dependency-snapshot-qualified"


def test_installed_removed_digest_predicate_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/dependency_assurance.py"
    source = path.read_text()
    guard = "hashlib.sha256(canonical).hexdigest() != inventory.sha256"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "False"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed stale inventory was accepted under its old digest" in result.stderr
