"""Exercise the installed evidence CLI with no BCF distribution or source import."""

from __future__ import annotations

import contextlib
import importlib.metadata
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
import venv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
import yaml
from packaging.requirements import Requirement

from bcf_governance.tooling.evidence_storage_manifests import verify_input_bundle
from test_evidence_storage import _durable_graph_repo, _published_reference, _storage_repo
from test_install_governance_pack import _run_installer


ROOT = Path(__file__).resolve().parents[1]


def create_isolated_python(root: Path) -> Path:
    """Copy only declared consumer dependencies into a fresh offline interpreter."""
    venv.EnvBuilder(with_pip=False).create(root)
    interpreter = root / "bin/python"
    site = root / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    pending = ["PyYAML", "jsonschema", "packaging"]
    seen = set()
    while pending:
        name = pending.pop()
        distribution = importlib.metadata.distribution(name)
        identity = distribution.metadata["Name"].lower()
        if identity in seen:
            continue
        seen.add(identity)
        assert identity != "bcf-governance"
        for raw in distribution.requires or ():
            requirement = Requirement(raw)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(requirement.name)
        for relative in distribution.files or ():
            if ".." in relative.parts or relative.suffix in {".pth", ".pyc"}:
                continue
            source = Path(distribution.locate_file(relative))
            if source.is_file():
                destination = site / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
    return interpreter


@pytest.fixture(scope="module")
def isolated_python(tmp_path_factory):
    return create_isolated_python(tmp_path_factory.mktemp("evidence-consumer-python"))


def _environment(**extra: str) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("PYTHON", "GITHUB_", "BCF_"))}
    environment.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", **extra)
    return environment


@pytest.fixture(params=["fresh", "upgrade"])
def installed_consumer(tmp_path, isolated_python, request):
    consumer = tmp_path / "installed"
    result = _run_installer(consumer, "--profile", "lite", "--skip-validation", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    if request.param == "upgrade":
        wrapper = consumer / "scripts/evidence_storage.py"
        wrapper.write_bytes(wrapper.read_bytes().replace(
            b"from _bcf_runtime.evidence_storage_commands",
            b"from bcf_governance.tooling.evidence_storage_commands",
        ))
        broken = _cli(isolated_python, consumer, "--help")
        assert broken.returncode == 1 and "No module named 'bcf_governance'" in broken.stderr
        owned = consumer / "product-owned.txt"
        owned.write_bytes(b"project-owned bytes\n")
        owned.chmod(0o640)
        before = owned.read_bytes(), owned.stat().st_mode
        result = _run_installer(consumer, "--upgrade", "--skip-validation", check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        assert (owned.read_bytes(), owned.stat().st_mode) == before
    assert (consumer / "scripts/evidence_storage.py").read_bytes() == (
        ROOT / "template-repo/scripts/evidence_storage.py"
    ).read_bytes()
    result = subprocess.run(
        [str(isolated_python), "-c", "import importlib.util; assert importlib.util.find_spec('bcf_governance') is None"],
        cwd=consumer, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    return consumer


def _cli(python: Path, consumer: Path, *args: str, environment=None):
    return subprocess.run(
        [str(python), "scripts/evidence_storage.py", *args], cwd=consumer,
        env=_environment(**(environment or {})), capture_output=True, text=True,
    )


def test_installed_evidence_cli_help_needs_only_the_vendored_runtime(installed_consumer, isolated_python):
    result = _cli(isolated_python, installed_consumer, "--help")
    assert result.returncode == 0, result.stderr
    assert "prepare" in result.stdout and "resolve-github" in result.stdout


def test_canonical_installed_wrapper_has_no_source_package_dependency(tmp_path, isolated_python):
    result = subprocess.run(
        [str(isolated_python), str(ROOT / "template-repo/scripts/evidence_storage.py"), "--help"],
        cwd=tmp_path, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "prepare" in result.stdout and "resolve-github" in result.stdout


@pytest.mark.parametrize("binding_enabled", [False, True])
def test_installed_dependent_gate_reads_only_current_session(
    tmp_path, installed_consumer, isolated_python, binding_enabled
):
    from test_governance_evidence import _make_session_input_consumer_repo

    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    repo = _make_session_input_consumer_repo(fixture_root)
    wrapper = installed_consumer / "scripts/governance_evidence.py"
    if not binding_enabled:
        runtime = installed_consumer / "scripts/_bcf_runtime/governance_evidence.py"
        source = runtime.read_text()
        binding = ('    job_environment = bind_current_session_inputs(\n'
                   '        repo_root, session, contract["invocation"].get("required_env", []), job_environment\n'
                   '    )\n')
        assert source.count(binding) == 1
        runtime.write_text(source.replace(binding, ""))

    def evidence(*arguments, expected_exit=0, **environment):
        result = subprocess.run(
            [str(isolated_python), str(wrapper), "--repo-root", str(repo), *arguments],
            cwd=tmp_path, env=_environment(**environment), capture_output=True, text=True,
        )
        assert result.returncode == expected_exit, result.stdout + result.stderr
        return Path(result.stdout.strip())

    sessions = []
    for artifact_root in (repo / ".artifacts/bcf/sessions", tmp_path / "external"):
        manifest = evidence("session", "--artifact-root", str(artifact_root),
                            "--expected-gate", "gate", "--expected-gate", "dependent",
                            "--expected-producer", "local", "--local-producer-id", "local")
        evidence("run", "--gate", "gate", "--output", str(manifest.parent / "gate"),
                 "--session-manifest", str(manifest), "--python", str(isolated_python))
        sessions.append(manifest)
    current = sessions[1]
    receipt = evidence(
        "run", "--gate", "dependent", "--output", str(current.parent / "dependent"),
        "--session-manifest", str(current), "--python", str(isolated_python),
        DEPENDENCY_RECEIPTS=str(repo / ".artifacts/bcf/sessions"),
        EXPECTED_SESSION_ID=json.loads(current.read_text())["session_id"],
        expected_exit=0 if binding_enabled else 1,
    )
    assert json.loads(receipt.read_text())["result"] == ("passed" if binding_enabled else "failed")
    if not binding_enabled:
        assert "foreign session input" in (receipt.parent / "dependent.stderr.txt").read_text()


def _install_contract_fixture(source: Path, consumer: Path) -> None:
    for name in ("governance", ".github"):
        shutil.copytree(source / name, consumer / name, dirs_exist_ok=True)


def _exercise_prepare(consumer: Path, python: Path, fixture_root: Path) -> list[dict]:
    source = _durable_graph_repo(fixture_root)
    graph_path = source / "governance/ci-graph.yml"
    graph = yaml.safe_load(graph_path.read_text())
    storage = yaml.safe_load((source / "governance/evidence-storage.yml").read_text())
    graph["resource_classes"]["candidate-python"]["routing"] = {
        "kind": "private_local_candidate", "repository_id": str(storage["provider"]["repository_id"]),
        "local_runner": ["self-hosted", "Linux", "X64", "fixture-local-candidate"],
        "local_cases": ["same_repository_pull_request", "protected_push", "protected_schedule", "protected_dispatch"],
        "allowed_refs": ["refs/heads/main"],
    }
    graph_path.write_text(yaml.safe_dump(graph, sort_keys=False))
    _install_contract_fixture(source, consumer)
    # Generate and inspect through the actual installed runtime, with no BCF package.
    code = """import importlib.util, json, sys
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0, str(Path('scripts').resolve()))
from _bcf_runtime.ci_graph_contracts import validate_ci_graph
from _bcf_runtime.ci_graph_render import apply_ci_graph
compiled = validate_ci_graph(Path.cwd())
sources = [(w, j, a) for w in compiled.workflows for j in w['jobs'] for a in j['produces'] if compiled.graph['artifacts'][a]['kind'] == 'durable-source']
assert len(sources) == 1
workflow, job, artifact = sources[0]
assert 'matrix' not in job and 'strategy' not in job
apply_ci_graph(Path.cwd())
print(json.dumps({'workflow': workflow['path'], 'job': job['id'], 'artifact': artifact}))
"""
    rendered = subprocess.run([str(python), "-c", code], cwd=consumer, env=_environment(), capture_output=True, text=True)
    records = [_record(rendered)]
    assert rendered.returncode == 0, records[-1]
    identity = json.loads(rendered.stdout)
    generated = yaml.safe_load((consumer / identity["workflow"]).read_text())
    job = generated["jobs"][identity["job"]]
    assert "matrix" not in job and "strategy" not in job
    assert "github.event.repository.private" in job["runs-on"]
    for args in (("add", "."), ("commit", "--quiet", "-m", "Synthetic installed consumer")):
        subprocess.run(["git", *args], cwd=consumer, check=True, capture_output=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=consumer, text=True).strip()
    prepared = consumer / ".artifacts/prepared/scanner"
    prepared.parent.mkdir(parents=True, exist_ok=True)
    prepared.write_bytes(b"installed scanner\x00\xff exact bytes\n")
    environment = {
        "GITHUB_REPOSITORY": storage["provider"]["repository"], "GITHUB_REPOSITORY_ID": str(storage["provider"]["repository_id"]),
        "GITHUB_WORKFLOW_REF": storage["provider"]["repository"] + "/" + identity["workflow"] + "@refs/heads/main",
        "GITHUB_JOB": identity["job"], "GITHUB_SHA": commit,
        "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
    }
    output = consumer / ".artifacts/prepared-bundle"
    result = _cli(python, consumer, "prepare", "--repo-root", ".", "--artifact", identity["artifact"], "--output", str(output), environment=environment)
    records.append(_record(result))
    assert result.returncode == 0, result.stderr
    manifest = verify_input_bundle(consumer, output)
    assert manifest["subject"]["commit_sha"] == commit
    assert manifest["producer"]["run_id"] == "123"
    assert manifest["objects"][0]["target_path"] == "security/scanner"
    assert str(output / "evidence-input-manifest.json") in result.stdout
    prepared.unlink()
    failed_output = consumer / ".artifacts/missing-input-bundle"
    result = _cli(python, consumer, "prepare", "--repo-root", ".", "--artifact", identity["artifact"], "--output", str(failed_output), environment=environment)
    records.append(_record(result))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "source" in result.stderr
    assert not failed_output.exists()
    return records


def test_installed_graph_prepare_creates_verified_exact_bytes_and_rejects_missing_input(
    installed_consumer, isolated_python, tmp_path,
):
    _exercise_prepare(installed_consumer, isolated_python, tmp_path / "fixture")


def _record(result: subprocess.CompletedProcess) -> dict:
    return {"argv": result.args, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


@contextlib.contextmanager
def _provider(tmp_path: Path, api, *, reference_ref: str | None = None):
    """Serve only the read endpoints needed by the real vendored HTTPS adapter."""
    certificate, key = tmp_path / "fixture-cert.pem", tmp_path / "fixture-key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
         "-keyout", str(key), "-out", str(certificate)],
        check=True, capture_output=True,
    )
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            path = unquote(urlsplit(self.path).path)
            requests.append((self.command, path, self.headers.get("Accept")))
            if self.headers.get("Authorization") != "Bearer fixture-local-token":
                self.send_error(401)
                return
            prefix = "/repos/owner/project/"
            if path.startswith(prefix + "releases/tags/"):
                tag = path.removeprefix(prefix + "releases/tags/")
                payload = api.releases.get(tag)
            elif path.startswith(prefix + "git/ref/tags/"):
                tag = path.removeprefix(prefix + "git/ref/tags/")
                payload = {"ref": reference_ref if reference_ref is not None else f"refs/tags/{tag}", "object": {"type": "commit", "sha": api.tags[tag]}}
            elif path.startswith(prefix + "attestations/"):
                payload = {"attestations": [{"subject_digest": path.rsplit("/", 1)[-1]}]}
            elif path.startswith(prefix + "releases/assets/"):
                payload = api.assets.get(int(path.rsplit("/", 1)[-1]))
                if self.headers.get("Accept") != "application/octet-stream":
                    self.send_error(406)
                    return
            else:
                payload = None
            if payload is None:
                self.send_error(404)
                return
            binary = isinstance(payload, bytes)
            body = payload if binary else json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream" if binary else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "GITHUB_API_URL": f"https://127.0.0.1:{server.server_port}",
            "GITHUB_TOKEN": "fixture-local-token", "SSL_CERT_FILE": str(certificate),
            "NO_PROXY": "127.0.0.1,localhost",
        }, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _exercise_resolve(consumer: Path, python: Path, fixture_root: Path, corruption: str | None) -> dict:
    source = _storage_repo(fixture_root / "fixture")
    api, manifest, reference = _published_reference(source, fixture_root)
    _install_contract_fixture(source, consumer)
    target_reference = consumer / f".artifacts/reference-{corruption or 'valid'}.json"
    target_reference.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(reference, target_reference)
    expected = json.loads(reference.read_bytes())
    object_asset = next(item for item in expected["assets"] if item["name"] != manifest.name)
    if corruption == "asset":
        asset = api.assets[object_asset["id"]]
        api.assets[object_asset["id"]] = bytes([asset[0] ^ 1]) + asset[1:]
    elif corruption == "missing_asset":
        del api.assets[object_asset["id"]]
    elif corruption == "reference":
        expected["storage_contract_sha256"] = "f" * 64
        target_reference.write_text(json.dumps(expected))
    elif corruption == "missing_reference":
        target_reference.unlink()
    output = consumer / f".artifacts/cold-inputs-{corruption or 'valid'}"
    with _provider(
        fixture_root, api, reference_ref="refs/tags/different-subject" if corruption == "ref" else None,
    ) as (environment, requests):
        result = _cli(python, consumer, "resolve-github", "--repo-root", ".", "--reference", str(target_reference), "--output", str(output), environment=environment)
    if corruption is None:
        assert result.returncode == 0, result.stderr
        assert (output / "resolved/scanner.bin").read_bytes() == b"exact scanner bytes"
        assert (output / "resolved/scanner-copy.bin").read_bytes() == b"exact scanner bytes"
        assert len([row for row in requests if "/releases/assets/" in row[1]]) == 2
        assert all(method == "GET" for method, _, _ in requests)
    else:
        assert result.returncode == 1, result.stdout + result.stderr
        assert not output.exists()
        message = {"asset": "identity mismatch", "reference": "different storage contract", "missing_asset": "returned 404", "missing_reference": "reference must remain", "ref": "Git reference response does not match requested ref"}[corruption]
        assert message in result.stderr
        if corruption == "ref":
            assert not any("/releases/assets/" in path for _, path, _ in requests)
    return {**_record(result), "case": corruption or "valid", "provider_requests": requests}


@pytest.mark.parametrize("corruption", [None, "asset", "reference", "missing_asset", "missing_reference", "ref"])
def test_installed_cold_resolver_authenticates_bytes_and_fails_without_partial_output(
    installed_consumer, isolated_python, tmp_path, corruption,
):
    _exercise_resolve(installed_consumer, isolated_python, tmp_path, corruption)


def exercise_installed_consumer(consumer: Path, python: Path, fixture_root: Path) -> dict:
    """Reusable wheel/sdist acceptance against a genuinely installed consumer pack."""
    from semantic_typescript_fixture import exercise_consumer, repository

    consumer, python, fixture_root = consumer.resolve(), python.absolute(), fixture_root.resolve()
    probe = subprocess.run(
        [str(python), "-c", "import importlib.util; assert importlib.util.find_spec('bcf_governance') is None"],
        cwd=consumer, env=_environment(), capture_output=True, text=True,
    )
    assert probe.returncode == 0, _record(probe)
    schemas = {path: path.read_bytes() for path in (consumer / "schemas").glob("*.json")}
    repository(consumer, package="frontend", install_schemas=False)
    profile_path = consumer / "governance-profile.yml"
    profile = yaml.safe_load(profile_path.read_text())
    profile["release_gate_profile"] = {"gates": {"test": {
        "target": "test", "status": "required", "command_policy": "automated_tests",
        "rationale": "The synthetic durable graph declares one required test gate.",
    }}}
    profile_path.write_text(yaml.safe_dump(profile, sort_keys=False))
    semantic_records = exercise_consumer(consumer, python, consumer / "scripts/semantic_ownership.py")
    authored_code = """import importlib.util, json, sys
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0, str(Path('scripts').resolve()))
from _bcf_runtime import semantic_ownership_scan as scan
from _bcf_runtime import semantic_source_discovery as discovery
def unexpected_compiler(*args, **kwargs):
    raise AssertionError('authored Python query executed a foreign compiler')
discovery.compiler_contracts = unexpected_compiler
discovery.discover_typescript_source = unexpected_compiler
report = scan.validate_authored_semantic_ownership(Path.cwd())
assert report['authority'] is False and report['execution_qualified'] is False
assert 'operation_observations' in report
assert isinstance(report['operation_observations'], list)
print(json.dumps(report, sort_keys=True))
"""
    authored_query = subprocess.run(
        [str(python), "-I", "-c", authored_code], cwd=consumer, env=_environment(),
        capture_output=True, text=True,
    )
    assert authored_query.returncode == 0, _record(authored_query)
    provider_code = """import importlib.util, json, sys
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0, str(Path('scripts').resolve()))
from _bcf_runtime import release_adopter_sources as sources
from _bcf_runtime.ci_github_api import GitHubAPI
from _bcf_runtime.release_adopter_qualification import ReleaseQualificationError
state = {'commit': 'a' * 40}
reads = []
def request(self, method, path, **kwargs):
    assert method == 'GET'
    reads.append(path)
    if '/git/ref/' in path:
        return {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': state['commit']}}
    if '/git/commits/' in path:
        return {'sha': state['commit'], 'tree': {'sha': 'b' * 40}}
    return {'id': 123, 'default_branch': 'main',
            'full_name': '/'.join(path.split('/')[2:4])}
GitHubAPI._request = request
api = GitHubAPI(token='fixture-only')
contract = {'schema_version': '1.4', 'required_adopters': [
    {'id': 'consumer', 'repository': 'owner/consumer', 'profile': 'lite'}],
    'qualification': {'source': 'provider_default_branch_transaction',
    'caller_checkout_role': 'materialization_resource_only',
    'source_freshness': 'provider_exact_at_capture_and_collection'}}
captured = sources.resolve_adopter_sources(api, contract)
assert captured[0].repository_id == '123' and captured[0].default_branch == 'main'
sources.authenticate_adopter_sources(api, captured)
state['commit'] = 'c' * 40
try:
    sources.authenticate_adopter_sources(api, captured)
except sources.AdopterSourceError as exc:
    assert 'stale' in str(exc)
else:
    raise AssertionError('installed source freshness guard accepted moved head')
state['commit'] = 'a' * 40
from dataclasses import replace
for cause in ('physical-id', 'case-alias'):
    before = len(reads)
    duplicate = replace(captured[0], id='duplicate',
        repository='owner/other' if cause == 'physical-id' else 'OWNER/CONSUMER',
        repository_id='123' if cause == 'physical-id' else '124')
    try:
        sources.authenticate_adopter_sources(api, (captured[0], duplicate))
    except sources.AdopterSourceError as exc:
        assert 'inventory' in str(exc)
    else:
        raise AssertionError('installed frozen inventory accepted ' + cause)
    assert len(reads) == before
    duplicate_contract = json.loads(json.dumps(contract))
    duplicate_contract['required_adopters'].append({'id': 'duplicate', 'profile': 'lite',
        'repository': 'owner/other' if cause == 'physical-id' else 'OWNER/CONSUMER'})
    try:
        sources.resolve_adopter_sources(api, duplicate_contract)
    except sources.AdopterSourceError as exc:
        assert 'inventory' in str(exc)
    else:
        raise AssertionError('installed capture accepted ' + cause)
    assert len(reads) - before == (6 if cause == 'physical-id' else 0)
before = len(reads)
contract['schema_version'] = '1.3'
try:
    sources.resolve_adopter_sources(api, contract)
except sources.AdopterSourceError as exc:
    assert 'source policy' in str(exc)
else:
    raise AssertionError('installed query accepted caller-selected legacy policy')
assert len(reads) == before
print(json.dumps({'authority': False, 'publication_authority': False,
    'captured': [item.as_dict() for item in captured], 'freshness_rejection': True,
    'legacy_rejection_before_reads': True, 'physical_and_case_uniqueness': True}, sort_keys=True))
"""
    provider_query = subprocess.run(
        [str(python), "-I", "-c", provider_code], cwd=consumer, env=_environment(),
        capture_output=True, text=True,
    )
    assert provider_query.returncode == 0, _record(provider_query)
    prepare_records = _exercise_prepare(consumer, python, fixture_root / "prepare")
    resolve_records = [
        _exercise_resolve(consumer, python, fixture_root / f"resolve-{case or 'valid'}", case)
        for case in (None, "asset", "reference", "missing_asset", "missing_reference", "ref")
    ]
    assert schemas == {path: path.read_bytes() for path in (consumer / "schemas").glob("*.json")}
    return {
        "status": "pass", "consumer": str(consumer), "python": str(python),
        "bcf_package_absent": _record(probe), "semantic_commands": semantic_records,
        "authored_operation_query": _record(authored_query),
        "provider_source_query": _record(provider_query),
        "prepare_commands": prepare_records, "resolve_commands": resolve_records,
        "installed_schemas_preserved": True,
    }


def test_combined_installed_consumer_uses_real_compiler_and_durable_runtime(
    installed_consumer, isolated_python, tmp_path,
):
    report = exercise_installed_consumer(installed_consumer, isolated_python, tmp_path / "acceptance")
    assert report["status"] == "pass"
