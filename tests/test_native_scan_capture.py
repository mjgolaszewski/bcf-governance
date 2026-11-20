"""Native advisory observations bind actual child stdin and independent inputs."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import sys

import pytest

from bcf_governance.tooling import dependency_assurance as owner
from bcf_governance.tooling.evidence_process_supervisor import native_lease_custody


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Case:
    def __init__(self, root):
        self.root = root
        self.database = root / "database"
        self.database.mkdir()
        (self.database / "data").write_bytes(b"test database bytes")
        self.response = root / "response.json"
        self.response.write_text("{}")
        self.seen = root / "seen.bin"
        self.scanner = root / "scanner"
        self.image = {"manifestDigest": "sha256:" + "a" * 64, "imageID": "sha256:" + "b" * 64,
                      "architecture": "amd64", "os": "linux"}
        self.artifact = {"id": "package-one", "purl": "pkg:rpm/example/libstdc%2B%2B@1:2.0-1", "name": "libstdc++", "version": "1:2.0-1"}
        self.sbom = {"schema": {"version": "16.1.13"}, "source": {"type": "image", "id": "a" * 64, "metadata": self.image}, "artifacts": [self.artifact]}
        self.status = {"schemaVersion": "v6.1.10", "from": "https://example.invalid/test-db", "valid": True,
                       "built": (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()}
        self.scanner.write_text("#!" + sys.executable + " -I\n" + '''import json,sys
from pathlib import Path
raw=sys.stdin.buffer.read()
Path(SEEN).write_bytes(raw)
sbom=json.loads(raw);configuration=json.loads(Path(sys.argv[sys.argv.index('--config')+1]).read_text())
response=json.loads(Path(RESPONSE).read_text())
scan={'matches':[],'ignoredMatches':[],'source':{'type':'image','target':sbom['source']['metadata']},'descriptor':{'name':'grype','version':'0.122.1','configuration':configuration,'db':{'status':STATUS}}}
for key in ['matches','ignoredMatches','source']:
 if key in response:scan[key]=response[key]
scan['descriptor']['configuration'].update(response.get('configuration',{}))
if response.get('change_database'):(Path(configuration['db']['cache-dir'])/'data').write_bytes(b'changed')
if response.get('change_scanner'):Path(sys.argv[0]).write_text('changed')
for key in ['name','version','db']:
 if key in response:scan['descriptor'][key]=response[key]
if response.get('malformed'):print('not-json')
elif response.get('duplicate'):print('{"matches":[],"matches":[]}')
else:print(json.dumps(scan))
sys.exit(response.get('exit_code',0))
'''.replace("SEEN", repr(str(self.seen))).replace("RESPONSE", repr(str(self.response))).replace("STATUS", repr(self.status)))
        self.scanner.chmod(0o700)
        self.refresh()

    def refresh(self):
        raw = json.dumps(self.sbom).encode()
        self.arguments = dict(sbom_bytes=raw, expected_sbom_sha256=digest(raw), expected_image=dict(self.image),
            expected_inventory=tuple((row["purl"], row["name"], row["version"]) for row in self.sbom["artifacts"]),
            scanner=self.scanner, expected_scanner_sha256=digest(self.scanner.read_bytes()),
            database_root=self.database, expected_database_files={"data": digest(b"test database bytes")},
            expected_database_status=dict(self.status), max_database_age_seconds=3600,
            command_seconds=15, output_dir=self.root / "output")

    @contextmanager
    def lease(self):
        with (self.root / "lease").open("w+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with native_lease_custody(stream.fileno(), timeout_seconds=20, cleanup_seconds=3):
                yield

    def invoke(self):
        function = getattr(owner, "capture_native_dependency_audit", None)
        assert callable(function)
        with self.lease():
            return function(**self.arguments)


def test_real_child_consumes_exact_owned_stdin_without_native_version_coercion(tmp_path):
    case = Case(tmp_path)
    result = case.invoke()
    assert case.seen.read_bytes() == case.arguments["sbom_bytes"]
    assert result["status"] == "no_findings", result
    assert result["inventory_component_count"] == 1
    assert result["authority"] is result["execution_qualified"] is result["security_qualified"] is False
    assert "libstdc++" in (tmp_path / "output/scanner-input.json").read_text()


def test_missing_execution_owner_refuses_before_allocation(tmp_path):
    case = Case(tmp_path)
    function = getattr(owner, "capture_native_dependency_audit", None)
    assert callable(function)
    with pytest.raises(owner.DependencyAssuranceError, match="execution owner"):
        function(**case.arguments)
    assert not case.seen.exists() and not case.arguments["output_dir"].exists()


@pytest.mark.parametrize("mutation", ["sbom-hash", "image-manifest", "image-config", "inventory-omitted", "inventory-duplicate",
    "scanner-missing", "sbom-schema", "sbom-duplicate", "scanner-hash", "database-hash", "database-extra", "database-link", "stale", "future", "invalid-status", "zero-budget", "boolean-budget"])
def test_native_admission_refuses_before_scanner_or_output_allocation(tmp_path, mutation):
    case = Case(tmp_path)
    a = case.arguments
    if mutation == "sbom-hash":a["expected_sbom_sha256"] = "c" * 64
    elif mutation == "image-manifest":a["expected_image"]["manifestDigest"] = "sha256:" + "c" * 64
    elif mutation == "image-config":a["expected_image"]["imageID"] = "sha256:" + "c" * 64
    elif mutation == "inventory-omitted":a["expected_inventory"] = ()
    elif mutation == "inventory-duplicate":a["expected_inventory"] *= 2
    elif mutation == "scanner-missing":case.scanner.unlink()
    elif mutation == "sbom-schema":
        case.sbom["schema"]["version"] = "0.0.0"
        case.refresh()
    elif mutation == "sbom-duplicate":
        a["sbom_bytes"] = b'{"source":{},"source":{}}'
        a["expected_sbom_sha256"] = digest(a["sbom_bytes"])
    elif mutation == "scanner-hash":a["expected_scanner_sha256"] = "c" * 64
    elif mutation == "database-hash":a["expected_database_files"]["data"] = "c" * 64
    elif mutation == "database-extra":(case.database / "extra").write_text("unselected")
    elif mutation == "database-link":(case.database / "linked").symlink_to(case.database / "data")
    elif mutation == "stale":a["expected_database_status"]["built"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    elif mutation == "future":a["expected_database_status"]["built"] = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    elif mutation == "invalid-status":a["expected_database_status"]["valid"] = 1
    elif mutation == "zero-budget":a["command_seconds"] = 0
    else:a["command_seconds"] = True
    with pytest.raises(owner.DependencyAssuranceError):case.invoke()
    assert not case.seen.exists(), "unmatched native input reached scanner"
    assert not a["output_dir"].exists(), "unmatched native inventory allocated scanner"


@pytest.mark.parametrize("suppressed", [False, True])
def test_all_actual_and_suppressed_findings_remain_blocking_observations(tmp_path, suppressed):
    case = Case(tmp_path)
    finding = {"artifact": case.artifact, "vulnerability": {"id": "CVE-EXAMPLE", "severity": "Low", "fix": {"versions": []}}}
    case.response.write_text(json.dumps({"ignoredMatches" if suppressed else "matches": [finding]}))
    result = case.invoke()
    assert result["status"] == "findings_present"
    assert result["findings"][0]["suppressed"] is suppressed


@pytest.mark.parametrize("change", ["malformed", "duplicate", "nonzero", "source", "version", "database", "filter", "suppression", "artifact", "database-bytes", "scanner-bytes"])
def test_contradictory_or_incomplete_native_result_never_becomes_no_findings(tmp_path, change):
    case = Case(tmp_path)
    if change in {"malformed", "duplicate"}:response = {change: True}
    elif change == "nonzero":response = {"exit_code": 1}
    elif change == "source":response = {"source": {"type": "image", "target": dict(case.image, imageID="sha256:" + "c" * 64)}}
    elif change == "version":response = {"version": "0.0.0"}
    elif change == "database":response = {"db": {"status": dict(case.status, valid=False)}}
    elif change == "filter":response = {"configuration": {"only-fixed": True}}
    elif change == "database-bytes":response = {"change_database": True}
    elif change == "scanner-bytes":response = {"change_scanner": True}
    elif change == "suppression":response = {"configuration": {"include-matcher-suppressions": False}}
    else:response = {"matches": [{"artifact": dict(case.artifact, id="forged"), "vulnerability": {"id": "CVE-EXAMPLE"}}]}
    case.response.write_text(json.dumps(response))
    result = case.invoke()
    assert case.seen.exists()
    assert result["status"] == "scanner_failure", result
    assert (case.arguments["output_dir"] / "scanner.stdout").is_file()


def test_removed_inventory_equality_fails_named_no_allocation_control(tmp_path, monkeypatch):
    case = Case(tmp_path)
    function = getattr(owner, "capture_native_dependency_audit", None)
    assert callable(function)
    import inspect
    case.arguments["expected_inventory"] = (("pkg:rpm/example/other@1", "other", "1"),)
    with pytest.raises(owner.DependencyAssuranceError, match="inventory differs"):
        case.invoke()
    assert not case.arguments["output_dir"].exists()
    source = inspect.getsource(function)
    guard = "if sorted(observed) != sorted(wanted):"
    assert source.count(guard) == 1
    namespace = dict(owner.__dict__)
    exec(compile(source.replace(guard, "if False:"), "<removed-native-inventory-equality>", "exec"), namespace)
    monkeypatch.setattr(owner, "capture_native_dependency_audit", namespace[function.__name__])
    case.arguments["expected_inventory"] = (("pkg:rpm/example/other@1", "other", "1"),)
    with case.lease():
        result = owner.capture_native_dependency_audit(**case.arguments)
    assert result["status"] == "no_findings"
    with pytest.raises(AssertionError, match="unmatched native inventory allocated scanner"):
        assert not case.arguments["output_dir"].exists(), "unmatched native inventory allocated scanner"


def test_removed_suppression_retention_predicate_fails_named_control(tmp_path, monkeypatch):
    import inspect
    case = Case(tmp_path)
    function = getattr(owner, "capture_native_dependency_audit", None)
    assert callable(function)
    source = inspect.getsource(function)
    guard = 'options.get("include-matcher-suppressions") is not True'
    assert source.count(guard) == 1
    namespace = dict(owner.__dict__)
    exec(compile(source.replace(guard, "False"), "<removed-suppression-retention>", "exec"), namespace)
    monkeypatch.setattr(owner, "capture_native_dependency_audit", namespace[function.__name__])
    case.response.write_text(json.dumps({"configuration": {"include-matcher-suppressions": False}}))
    result = case.invoke()
    with pytest.raises(AssertionError, match="filtered native report accepted"):
        assert result["status"] == "scanner_failure", "filtered native report accepted"


def test_unknown_child_custody_preserves_namespace_and_propagates(tmp_path, monkeypatch):
    from bcf_governance.tooling import evidence_process_supervisor as commands
    case = Case(tmp_path)
    def unknown(*args, **kwargs):
        raise commands.OwnedProcessError("test unknown custody")
    monkeypatch.setattr(commands, "run_admitted_command", unknown)
    with pytest.raises(commands.OwnedProcessError, match="unknown custody"):
        case.invoke()
    assert (case.arguments["output_dir"] / "scanner-input.json").read_bytes() == case.arguments["sbom_bytes"]
    assert not (case.arguments["output_dir"] / "native-audit.json").exists()


def test_finding_cannot_pair_one_artifact_id_with_another_package(tmp_path):
    case = Case(tmp_path)
    second = dict(case.artifact, id="package-two", purl="pkg:rpm/example/other@1", name="other", version="1")
    case.sbom["artifacts"].append(second)
    case.refresh()
    finding = {"artifact": dict(second, id=case.artifact["id"]), "vulnerability": {"id": "CVE-EXAMPLE"}}
    case.response.write_text(json.dumps({"matches": [finding]}))
    assert case.invoke()["status"] == "scanner_failure"


def test_existing_output_is_preserved_without_execution(tmp_path):
    case = Case(tmp_path)
    output = case.arguments["output_dir"]
    output.mkdir()
    (output / "prior").write_bytes(b"preserve")
    with pytest.raises(owner.DependencyAssuranceError, match="fresh"):
        case.invoke()
    assert (output / "prior").read_bytes() == b"preserve"
    assert not case.seen.exists()
