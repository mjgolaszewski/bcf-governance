"""Independent report fixtures; command rows are synthetic, never execution proof."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import ci_github_release as release
from bcf_governance.tooling import release_runtime_verification as runtime
from bcf_governance.tooling.ci_github_identity import GitHubControllerError, MainIdentity


LABELS = (
    "wheel-venv", "wheel-closure-install", "twine-check", "wheel-install", "wheel-smoke",
    "sdist-venv", "sdist-closure-install", "sdist-install", "wheel-installed-consumer",
    "sdist-installed-consumer", "sdist-smoke",
)


def command_arguments(root: Path, wheel: Path, sdist: Path):
    selected = "/opt/python/bin/python"
    wheel_python = str(root / "wheel-env/bin/python")
    sdist_python = str(root / "sdist-env/bin/python")
    source = root / "source/exact-sdist"
    closure = ["-m", "pip", "install", "--no-index", "--find-links", str(root / "wheelhouse"),
               "--require-hashes", "-r", str(root / "closure.lock")]
    smoke = ["-m", "bcf_governance.cli", "--version"]
    consumer = [str(source / ".github/scripts/verify_installed_consumer.py"), "--source-root", str(source)]
    return {
        "wheel-venv": [selected, "-m", "venv", str(root / "wheel-env")],
        "sdist-venv": [selected, "-m", "venv", str(root / "sdist-env")],
        "wheel-closure-install": [wheel_python, *closure],
        "sdist-closure-install": [sdist_python, *closure],
        "twine-check": [wheel_python, "-m", "twine", "check", "--strict", str(wheel), str(sdist)],
        "wheel-install": [wheel_python, "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
        "sdist-install": [sdist_python, "-m", "pip", "install", "--no-index", "--no-deps", "--no-build-isolation", str(sdist)],
        "wheel-smoke": [wheel_python, *smoke], "sdist-smoke": [sdist_python, *smoke],
        "wheel-installed-consumer": [wheel_python, *consumer],
        "sdist-installed-consumer": [sdist_python, *consumer],
    }


def command_fixture(root: Path, version: str = "1.0", *, wheel: Path | None = None, sdist: Path | None = None):
    root.mkdir(parents=True, exist_ok=True)
    commands, paths = [], []
    arguments = command_arguments(root / "execution", wheel, sdist) if wheel is not None and sdist is not None else None
    labels = LABELS if version == "1.0" else LABELS[:-3] + ("sdist-smoke", "wheel-installed-consumer", "sdist-installed-consumer")
    for label in labels:
        if version == "1.0" and label == "sdist-installed-consumer":
            continue
        row = dict(label=label, argv=arguments[label] if arguments is not None else ["/fixture/python", "-c", "pass"], exit_code=0)
        for stream in ("stdout", "stderr"):
            path = root / (label + "." + stream)
            path.write_bytes(b"synthetic orchestration fixture; not execution evidence\n")
            row[stream] = path.name
            paths.append(path)
        commands.append(row)
    return commands, tuple(paths)


def command_report(tmp_path, version="1.0"):
    from test_release_runtime_verification import _fixture

    report, _, wheel, sdist = _fixture(tmp_path)
    commands, evidence = command_fixture(tmp_path / "commands", version,
                                         wheel=wheel if version == "1.1" else None,
                                         sdist=sdist if version == "1.1" else None)
    payload = json.loads(report.read_text())
    payload.update(schema_version=version, commands=commands,
                   evidence={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in evidence})
    report.write_text(json.dumps(payload))
    return report, evidence, wheel, sdist


@pytest.mark.parametrize("defect", [
    "missing", "empty", "duplicate", "dropped-with-streams", "unknown",
    "failed", "boolean-exit", "empty-argv", "nonstring-argv", "unbound-stream",
    "reused-stream", "orphan-stream", "install-before-closure", "consumer-before-install",
    "twine-before-closure", "smoke-after-consumer",
])
def test_reported_pass_cannot_contradict_runtime_commands(tmp_path, defect):
    report, evidence, wheel, sdist = command_report(tmp_path)
    value = json.loads(report.read_text())
    rows = value["commands"]
    if defect == "missing": del value["commands"]
    elif defect == "empty": value["commands"] = []
    elif defect == "duplicate": rows.append(copy.deepcopy(rows[0]))
    elif defect == "dropped-with-streams":
        removed = rows.pop()
        names = {removed["stdout"], removed["stderr"]}
        evidence = tuple(p for p in evidence if p.name not in names)
        value["evidence"] = {k: v for k, v in value["evidence"].items() if k not in names}
    elif defect == "unknown": rows[0]["label"] = "invented-success"
    elif defect == "failed": rows[0]["exit_code"] = 1
    elif defect == "boolean-exit": rows[0]["exit_code"] = False
    elif defect == "empty-argv": rows[0]["argv"] = []
    elif defect == "nonstring-argv": rows[0]["argv"][0] = True
    elif defect == "unbound-stream": rows[0]["stdout"] = "unbound.stdout"
    elif defect == "reused-stream": rows[1]["stdout"] = rows[0]["stdout"]
    elif defect == "orphan-stream":
        extra = tmp_path / "unclaimed.stdout"; extra.write_bytes(b"unclaimed")
        evidence += (extra,)
        value["evidence"][extra.name] = hashlib.sha256(extra.read_bytes()).hexdigest()
    elif defect == "install-before-closure": rows[1], rows[3] = rows[3], rows[1]
    elif defect == "consumer-before-install": rows[7], rows[8] = rows[8], rows[7]
    elif defect == "twine-before-closure": rows.insert(0, rows.pop(2))
    else: rows.insert(8, rows.pop(4))
    report.write_text(json.dumps(value))
    with pytest.raises(GitHubControllerError, match="runtime command"):
        runtime.verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist)


def test_genuine_legacy_command_report_retains_original_payload(tmp_path):
    report, evidence, wheel, sdist = command_report(tmp_path)
    original = json.loads(report.read_text())
    assert runtime.verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist) == original


def test_new_runtime_profile_requires_both_consumers(tmp_path):
    report, evidence, wheel, sdist = command_report(tmp_path, "1.1")
    assert runtime.verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist) == json.loads(report.read_text())
    value = json.loads(report.read_text())
    value["commands"] = [r for r in value["commands"] if r["label"] != "sdist-installed-consumer"]
    report.write_text(json.dumps(value))
    with pytest.raises(GitHubControllerError, match="runtime command"):
        runtime.verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist)


@pytest.mark.parametrize("work", ["_sha256", "verify_archive"])
def test_command_rejection_precedes_archive_reconstruction(tmp_path, monkeypatch, work):
    report, evidence, wheel, sdist = command_report(tmp_path)
    value = json.loads(report.read_text()); value["commands"][0]["exit_code"] = 1
    report.write_text(json.dumps(value))
    monkeypatch.setattr(runtime, work, lambda *args: pytest.fail("command rejection allocated " + work))
    with pytest.raises(GitHubControllerError, match="runtime command"):
        runtime.verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist)


def _legacy_release_inputs(tmp_path):
    from test_ci_github_release import _release_inputs

    values = _release_inputs(tmp_path)
    report = values["runtime_report"]
    payload = json.loads(report.read_text())
    commands, evidence = command_fixture(tmp_path / "legacy-commands")
    payload.update(schema_version="1.0", commands=commands,
                   evidence={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in evidence})
    report.write_text(json.dumps(payload))
    values["runtime_evidence"] = evidence
    return values


def test_trusted_release_verifier_rejects_legacy_profile_downgrade(tmp_path):
    from test_ci_github_release import _verify

    values = _legacy_release_inputs(tmp_path)
    output = tmp_path / "verification.json"
    with pytest.raises(GitHubControllerError, match="runtime report version"):
        _verify(values, output)
    assert not output.exists()


@pytest.mark.parametrize("defect", ["version", "dependency"])
def test_trusted_collector_requires_runtime_profile_and_dependency(tmp_path, monkeypatch, defect):
    from test_ci_github_release import _release_inputs, _json, COMMIT, TREE

    values = _legacy_release_inputs(tmp_path) if defect == "version" else _release_inputs(tmp_path)
    authorization = json.loads(values["authorization"].read_text())
    authorization["authorizer"] = dict(run_id="20", run_attempt=1)
    _json(values["authorization"], authorization)
    verification = _json(tmp_path / "verification.json", {"build": {
        "artifact_id": "40", "provider_digest": "sha256:" + "e" * 64},
        "dependency_closure": json.loads(values["build"].read_text())["dependency_closure"] if defect == "version" else {}})
    bundle = tmp_path / "bundle"; bundle.mkdir()
    for name in ("ci-certification.json", "evidence-session.json"): _json(bundle / name, {})
    # Test only post-authentication policy forwarding, never provider authenticity.
    monkeypatch.setattr(release, "verify_bundle", lambda *args: {})
    monkeypatch.setattr(release, "resolve_main", lambda *args: MainIdentity("101", "main", COMMIT, TREE))
    monkeypatch.setattr(release, "load_authority", lambda *args, **kwargs: {})
    monkeypatch.setattr(release, "authenticate_release_collection_roles", lambda *args, **kwargs: object())
    monkeypatch.setattr(release, "authority_role_workflow", lambda *args: {"workflow_id": "202"})
    monkeypatch.setattr(release, "authenticate_role_artifact", lambda *args, **kwargs: {})
    api = SimpleNamespace(workflow_runs=lambda *args, **kwargs: ({"id": 20, "run_attempt": 1},))
    output = tmp_path / "receipt.json"
    monkeypatch.setattr(runtime, "verify_archive", lambda *args: pytest.fail("collector dependency admission reached archive work"))
    expected = "runtime report version" if defect == "version" else "runtime dependency closure"
    with pytest.raises(GitHubControllerError, match=expected):
        release.collect_release(api, repository="owner/repo", bundle_dir=bundle,
            authorization_path=values["authorization"], build_manifest_path=values["build"],
            verification_path=verification, release_artifacts=values["artifacts"],
            collector_run_id="50", collector_run_attempt="1", runtime_report_path=values["runtime_report"],
            runtime_evidence=values["runtime_evidence"], output_path=output)
    assert not output.exists()


@pytest.mark.parametrize("layout", ["metadata-after-smoke", "development-eleven"])
def test_historical_runtime_layouts_keep_their_actual_scope(tmp_path, layout):
    report, evidence, wheel, sdist = command_report(tmp_path, "1.1" if layout == "development-eleven" else "1.0")
    value = json.loads(report.read_text())
    value["schema_version"] = "1.0"
    rows = value["commands"]
    if layout == "development-eleven": rows.append(rows.pop(8))
    else: rows.insert(4, rows.pop(2))
    report.write_text(json.dumps(value))
    assert runtime.verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist) == value


@pytest.mark.parametrize("defect", ["generic-success", "wrong-interpreter", "wrong-asset", "different-lock", "different-wheelhouse", "candidate-harness", "different-consumer-source", "no-offline-install", "missing-strict-metadata", "nul-argv"])
def test_new_profile_binds_commands_to_actual_operations(tmp_path, defect):
    report, _, wheel, sdist = command_report(tmp_path, "1.1")
    value = json.loads(report.read_text())
    commands, evidence = command_fixture(tmp_path / "arguments", "1.1", wheel=wheel, sdist=sdist)
    value['environment']['python_executable'] = "/opt/python/bin/python"
    value.update(commands=commands, evidence={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in evidence})
    rows = {r['label']: r for r in commands}
    if defect == "generic-success": rows['wheel-install']['argv'] = ["/bin/true"]
    elif defect == "wrong-interpreter": rows['sdist-smoke']['argv'][0] = rows['wheel-smoke']['argv'][0]
    elif defect == "wrong-asset": rows['wheel-install']['argv'][-1] = "/tmp/other.whl"
    elif defect == "different-lock": rows['sdist-closure-install']['argv'][-1] = "/tmp/other.lock"
    elif defect == "different-wheelhouse": rows['sdist-closure-install']['argv'][6] = "/tmp/other-wheelhouse"
    elif defect == "candidate-harness": rows['wheel-installed-consumer']['argv'][1] = "/tmp/candidate/pass.py"
    elif defect == "different-consumer-source": rows['sdist-installed-consumer']['argv'][-1] = "/tmp/other-source"
    elif defect == "no-offline-install": rows['wheel-install']['argv'].remove("--no-index")
    elif defect == "missing-strict-metadata": rows['twine-check']['argv'].remove("--strict")
    else: rows['wheel-install']['argv'][0] += "\0forged"
    report.write_text(json.dumps(value))
    with pytest.raises(GitHubControllerError, match="runtime command"):
        runtime.verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist)


@pytest.mark.parametrize("closure", [None, {}, {"status": "verified", "lock_sha256": "0" * 64}])
def test_trusted_verifier_recomputes_runtime_dependency_binding(tmp_path, closure):
    from test_ci_github_release import _release_inputs, _verify

    values = _release_inputs(tmp_path)
    report = values["runtime_report"]
    value = json.loads(report.read_text())
    value["dependency_closure"] = closure
    report.write_text(json.dumps(value))
    output = tmp_path / "verification.json"
    with pytest.raises(GitHubControllerError, match="runtime dependency closure"):
        _verify(values, output)
    assert not output.exists()


@pytest.mark.parametrize("defect", ["empty", "missing-status", "extra-field", "unverified", "empty-wheels", "boolean-digest", "bad-lock", "wrong-platform"])
def test_strict_runtime_binding_requires_complete_independent_closure(tmp_path, defect):
    report, evidence, wheel, sdist = command_report(tmp_path, "1.1")
    expected = {"status": "verified", "python": "3.12.14", "platform": "linux_x86_64",
                "lock_sha256": "a" * 64, "wheels": {"dependency.whl": "b" * 64}}
    if defect == "empty": expected = {}
    elif defect == "missing-status": del expected["status"]
    elif defect == "extra-field": expected["authority"] = True
    elif defect == "unverified": expected["status"] = "claimed"
    elif defect == "empty-wheels": expected["wheels"] = {}
    elif defect == "boolean-digest": expected["wheels"]["dependency.whl"] = True
    elif defect == "bad-lock": expected["lock_sha256"] = "not-a-digest"
    else: expected["platform"] = "unknown"
    value = json.loads(report.read_text()); value["dependency_closure"] = expected
    report.write_text(json.dumps(value))
    with pytest.raises(GitHubControllerError, match="runtime dependency closure"):
        runtime.verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist,
                                       required_version="1.1", expected_dependency_closure=expected)
