"""Offline compiler seeding and release verification orchestration boundaries."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest
import yaml

from bcf_governance.tooling import release_runtime_verification as runtime


ROOT = Path(__file__).resolve().parents[1]


def _module(path: Path):
    spec = importlib.util.spec_from_file_location("release_toolchain_" + path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try: spec.loader.exec_module(module)
    finally: sys.path.remove(str(path.parent))
    return module


def test_fresh_worktree_fixture_seeds_exact_compiler_once_without_checkout_node_modules(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "worktree"
    for relative in ("tests/semantic_typescript_fixture.py", ".github/scripts/bootstrap_test_toolchain.py"):
        target = source / relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    relative = "tests/fixtures/typescript-toolchain"
    shutil.copytree(ROOT / relative, source / relative, ignore=shutil.ignore_patterns("node_modules"))
    module = _module(source / "tests/semantic_typescript_fixture.py")
    assert not (module.TOOLCHAIN / "node_modules").exists()
    calls = []; run = subprocess.run
    def record(argv, **kwargs):
        calls.append(argv)
        return run(argv, **kwargs)
    monkeypatch.setattr(module.subprocess, "run", record)
    for name in ("positive", "negative"):
        consumer = tmp_path / name
        module.compiler(consumer)
        assert json.loads((consumer / "node_modules/typescript/package.json").read_text())["version"] == "6.0.3"
        assert (consumer / "node_modules/@bcf-test/declared-types/index.d.ts").read_bytes() == (module.TOOLCHAIN / "declared-types/index.d.ts").read_bytes()
    assert calls == [[sys.executable, str(source / ".github/scripts/bootstrap_test_toolchain.py")]]
    assert module.bootstrap_compiler.cache_info().misses == 1
    assert module.bootstrap_compiler.cache_info().hits == 1


def test_release_builder_cannot_run_source_tests_after_failed_compiler_bootstrap(tmp_path: Path, monkeypatch) -> None:
    module = _module(ROOT / ".github/scripts/build_release_bundle.py")
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        if ".github/scripts/bootstrap_test_toolchain.py" in argv:
            raise subprocess.CalledProcessError(1, argv)
    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(module, "_run_source_tests", lambda *_: pytest.fail("source tests ran without required compiler"))
    with pytest.raises(subprocess.CalledProcessError):
        module.build(tmp_path / "output", authorization=tmp_path / "authorization.json", artifact_name="fixture")
    assert calls[-1] == [sys.executable, ".github/scripts/bootstrap_test_toolchain.py", "--repo-root", "."]


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_standalone_package_qualifiers_seed_compiler_before_consumer_or_source_tests(tmp_path: Path, monkeypatch, kind: str) -> None:
    module = _module(ROOT / ".github/scripts/test_release_artifacts.py")
    source = tmp_path / "payload"; source.mkdir()
    monkeypatch.setattr(module, "validate_wheel_runtime_assets", lambda *_: None)
    monkeypatch.setattr(module, "validate_sdist_payload", lambda *_: None)
    monkeypatch.setattr(module, "validate_sdist_source_inventory", lambda *_: None)
    monkeypatch.setattr(module, "initialize_source_custody", lambda *_: None)
    monkeypatch.setattr(module, "venv_environment", lambda _: (Path(sys.executable), {}))
    calls = []
    class ReachedTestBoundary(Exception): pass
    def run(*argv, **kwargs):
        calls.append((argv, kwargs))
        if any(str(value).endswith("verify_installed_consumer.py") for value in argv) or "pytest" in argv:
            raise ReachedTestBoundary
    monkeypatch.setattr(module, "run", run)
    artifact = tmp_path / ("fixture.whl" if kind == "wheel" else "fixture.tar.gz")
    if kind == "wheel":
        with zipfile.ZipFile(artifact, "w"): pass
        invoke = lambda: module.verify_wheel(artifact, tmp_path, source)
    else:
        with tarfile.open(artifact, "w:gz") as output: output.add(source, arcname="fixture")
        invoke = lambda: module.verify_sdist(artifact, tmp_path)
    with pytest.raises(ReachedTestBoundary): invoke()
    bootstrap = [index for index, (argv, _) in enumerate(calls) if any(str(value).endswith("bootstrap_test_toolchain.py") for value in argv)]
    assert len(bootstrap) == 1 and bootstrap[0] < len(calls) - 1
    bootstrap_argv = calls[bootstrap[0]][0]
    assert bootstrap_argv[-2] == "--repo-root"
    assert Path(bootstrap_argv[-1]).is_relative_to(tmp_path)


def test_closed_runtime_binds_installed_consumer_stdout_and_preserves_bootstrap_order(tmp_path: Path, monkeypatch) -> None:
    files = {name: tmp_path / name for name in ("fixture.whl", "fixture.tar.gz", "manifest.yml", "closure.lock")}
    for path in files.values(): path.write_bytes(b"fixture bytes\n")
    source = tmp_path / "extracted-source"; source.mkdir()
    monkeypatch.setenv("PATH", os.environ["PATH"])
    for key in ("PYTHONPATH", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "NODE_OPTIONS"):
        monkeypatch.setenv(key, "must-not-enter-closed-runtime")
    monkeypatch.setattr(runtime, "verify_wheelhouse", lambda *_: SimpleNamespace(as_dict=lambda: {"status": "fixture-only"}))
    monkeypatch.setattr(runtime.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(runtime.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, runtime.EXPECTED_PYTHON + "\n", ""))
    monkeypatch.setattr(runtime, "_extract_sdist", lambda *_: source)
    monkeypatch.setattr(runtime, "_git_custody", lambda *_: [])
    environments = {}
    def environment(selected, root, **kwargs):
        env = runtime.runtime_environment(home=root.parent)
        environments[kwargs["label"]] = env
        return root / "bin/python", env, []
    monkeypatch.setattr(runtime, "_environment", environment)
    calls = []
    def run(label, argv, **kwargs):
        calls.append((label, argv, kwargs))
        for stream in ("stdout", "stderr"):
            (kwargs["output_dir"] / f"{label}.{stream}").write_bytes(f"stubbed {label} {stream}\n".encode())
        if label == "sdist-tests": (kwargs["output_dir"] / "sdist-tests.xml").write_text('<testsuite tests="1"/>')
        return {"label": label, "argv": argv, "exit_code": 0, "stdout": f"{label}.stdout", "stderr": f"{label}.stderr"}
    monkeypatch.setattr(runtime, "_run", run)
    output = tmp_path / "runtime"
    report = runtime.run_release_runtime_verification(selected_python=Path(sys.executable),
        manifest_path=files["manifest.yml"], lock_path=files["closure.lock"], wheelhouse=tmp_path,
        wheel=files["fixture.whl"], sdist=files["fixture.tar.gz"], output_dir=output)
    labels = [label for label, _, _ in calls]
    assert labels.index("sdist-test-toolchain") < labels.index("wheel-installed-consumer") < labels.index("sdist-tests")
    consumer = next(row for row in calls if row[0] == "wheel-installed-consumer")
    assert consumer[1][1:] == [str(source / ".github/scripts/verify_installed_consumer.py"), "--source-root", str(source)]
    assert consumer[1][0].endswith("wheel-env/bin/python") and consumer[2]["cwd"] != source
    assert consumer[2]["env"] is environments["wheel"]
    assert all(not set(env) & {"PYTHONPATH", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "NODE_OPTIONS"} for env in environments.values())
    assert all(env["PIP_NO_INDEX"] == "1" and shutil.which("node", path=env["PATH"]) for env in environments.values())
    stdout = output / "wheel-installed-consumer.stdout"
    assert report["schema_version"] == "1.0"
    assert report["evidence"][stdout.name] == hashlib.sha256(stdout.read_bytes()).hexdigest()
    path = output / "runtime-verification.json"
    evidence = runtime.runtime_evidence_paths(path, output)
    runtime.verify_runtime_evidence(path, evidence, wheel=files["fixture.whl"], sdist=files["fixture.tar.gz"])
    stdout.write_bytes(b"changed consumer report")
    with pytest.raises(runtime.GitHubControllerError, match="inventory is not exact"):
        runtime.verify_runtime_evidence(path, evidence, wheel=files["fixture.whl"], sdist=files["fixture.tar.gz"])


def test_graph_installs_test_node_only_in_existing_candidate_execution_jobs() -> None:
    graph = yaml.safe_load((ROOT / "governance/ci-graph.yml").read_text())
    release = yaml.safe_load((ROOT / "governance/ci-extensions/bcf-release.yml").read_text())
    setup = graph["step_components"]["setup-test-node"]
    assert setup["action"] == "setup-node" and setup["with"] == {"node-version": "22.23.2", "package-manager-cache": False}
    jobs = [job for owner in (graph, release) for workflow in owner["workflows"] for job in workflow["jobs"]]
    admitted = []
    for job in jobs:
        components = job.get("executor", {}).get("components", [])
        if "setup-test-node" not in components: continue
        admitted.append(job)
        assert job["trust"] == "candidate"
        if "bootstrap-test-toolchain" in components:
            assert components.index("setup-test-node") < components.index("bootstrap-test-toolchain")
        else:
            execution = "build-release-bundle" if "build-release-bundle" in components else "verify-release-runtime"
            assert components.index("setup-test-node") < components.index(execution)
    assert len(admitted) == 5
