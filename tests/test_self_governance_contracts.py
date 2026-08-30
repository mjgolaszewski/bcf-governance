from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.cli import COMMANDS
from bcf_governance.tooling.governance_validation.runner import validate_repo_root


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_github_script(name: str):
    path = REPO_ROOT / ".github/scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY_PATH = REPO_ROOT / "governance/self-governance-policy.yml"


def _policy() -> dict[str, object]:
    return yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))


def _architecture() -> dict[str, object]:
    payload = yaml.safe_load(
        (REPO_ROOT / "architecture-boundaries.yml").read_text(encoding="utf-8")
    )
    return payload["architecture"]


def _python_files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*.py") if "__pycache__" not in path.parts
    )


def test_source_roots_match_packaged_implementation() -> None:
    assert _architecture()["source_roots"] == ["bcf_governance"]
    packaging = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'include = ["bcf_governance*"]' in packaging


def test_source_layout_maps_to_declared_package_layers() -> None:
    layers = _architecture()["layers"]
    assert isinstance(layers, dict)
    for path in _python_files(REPO_ROOT / "bcf_governance"):
        relative = path.relative_to(REPO_ROOT).as_posix()
        package_parts = path.relative_to(REPO_ROOT / "bcf_governance").parts
        tokens = {package_parts[0] if len(package_parts) > 1 else path.stem}
        matches = [
            layer_id
            for layer_id, contract in layers.items()
            if tokens.intersection(contract["path_tokens"])
        ]
        assert len(matches) == 1, f"{relative} maps to {matches}"


def test_production_modules_respect_self_governance_loc_cap() -> None:
    cap = int(_architecture()["production_module_policy"]["max_loc"])
    violations = [
        f"{path.relative_to(REPO_ROOT)}:{len(path.read_text(encoding='utf-8').splitlines())}"
        for path in _python_files(REPO_ROOT / "bcf_governance")
        if len(path.read_text(encoding="utf-8").splitlines()) > cap
    ]
    assert not violations, "module LOC cap exceeded: " + ", ".join(violations)


def test_tooling_modules_map_to_exactly_one_context() -> None:
    contexts = _policy()["tooling_contexts"]
    assert isinstance(contexts, dict)
    for path in _python_files(REPO_ROOT / "bcf_governance/tooling"):
        relative = path.relative_to(REPO_ROOT / "bcf_governance/tooling").as_posix()
        if relative == "__init__.py" or relative.endswith("/__init__.py"):
            continue
        matches = [
            context
            for context, prefixes in contexts.items()
            if any(relative == prefix or relative.startswith(prefix) for prefix in prefixes)
        ]
        assert len(matches) == 1, f"{relative} maps to {matches}"


def test_packaged_code_does_not_import_public_wrapper_package() -> None:
    violations: list[str] = []
    for path in _python_files(REPO_ROOT / "bcf_governance"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else []
            if module == "scripts" or any(name == "scripts" or name.startswith("scripts.") for name in names):
                violations.append(path.relative_to(REPO_ROOT).as_posix())
    assert not violations, "packaged code imports generic scripts package: " + ", ".join(violations)


def test_cli_command_query_sides_are_complete_and_disjoint() -> None:
    groups = _policy()["cli_commands"]
    assert isinstance(groups, dict)
    read_only = set(groups["read_only"])
    mutating = set(groups["mutating"])
    assert not read_only & mutating
    assert read_only | mutating == set(COMMANDS)
    assert {"truth", "validate"} <= read_only
    assert {"install", "profile", "scaffold"} <= mutating


def test_cli_and_source_wrappers_remain_thin() -> None:
    cap = int(_policy()["thin_wrapper_loc_cap"])
    assert len((REPO_ROOT / "bcf_governance/cli.py").read_text(encoding="utf-8").splitlines()) < 100
    violations = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _python_files(REPO_ROOT / "scripts")
        if path.name != "__init__.py"
        and len(path.read_text(encoding="utf-8").splitlines()) >= cap
    ]
    assert not violations, "source wrappers are not thin: " + ", ".join(violations)


def test_template_and_private_runtime_copies_are_exact() -> None:
    tooling = REPO_ROOT / "bcf_governance/tooling"
    runtime = REPO_ROOT / "template-repo/scripts/_bcf_runtime"
    mismatches = [
        path.relative_to(tooling).as_posix()
        for path in _python_files(tooling)
        if path.read_bytes() != (runtime / path.relative_to(tooling)).read_bytes()
    ]
    assert not mismatches, "private runtime mismatch: " + ", ".join(mismatches)


def test_required_repository_artifact_contract_is_executable() -> None:
    validate_repo_root(REPO_ROOT)


def test_changelog_pr_enforcement_is_wired_into_repository_ci() -> None:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/governance-pack.yml").read_text(encoding="utf-8")
    )
    for job in workflow["jobs"].values():
        checkout_steps = [
            step
            for step in job["steps"]
            if step.get("uses", "").startswith("actions/checkout@")
        ]
        assert checkout_steps
        assert all(step.get("with", {}).get("fetch-depth") == 0 for step in checkout_steps)
    changelog_step = next(
        step
        for step in workflow["jobs"]["pack-checks"]["steps"]
        if step.get("name") == "Enforce pull-request changelog contract"
    )
    assert changelog_step["if"] == "github.event_name == 'pull_request'"
    assert changelog_step["env"] == {
        "BCF_ENFORCE_PR_CHANGELOG": "true",
        "BCF_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
    }


def test_exact_main_controller_wheel_is_built_once_after_pack_checks() -> None:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/governance-pack.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["pack-checks"]["steps"]
    build_index = next(
        index for index, step in enumerate(steps)
        if step.get("name") == "Build exact-main trusted controller wheel"
    )
    upload = next(
        step for step in steps
        if step.get("name") == "Upload exact-main trusted controller wheel"
    )
    pack_index = next(
        index for index, step in enumerate(steps)
        if step.get("name") == "Run governance pack tests"
    )
    assert build_index > pack_index
    assert steps[build_index]["if"] == (
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    assert upload["if"] == steps[build_index]["if"]
    assert upload["with"]["name"] == (
        "bcf-trusted-control-${{ github.sha }}-${{ github.run_attempt }}"
    )
    assert upload["with"]["retention-days"] == 30
    build_script = steps[build_index]["run"]
    assert "pip download --only-binary=:all:" in build_script
    assert "'PyYAML>=6.0,<7' 'jsonschema>=4.21,<5'" in build_script
    assert "sha256sum ./*.whl CONTROL-METADATA.json" in build_script


def test_trusted_bootstrap_is_owner_dispatched_pinned_and_offline() -> None:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/bcf-trusted-control-bootstrap.yml").read_text(
            encoding="utf-8"
        )
    )
    assert workflow[True] == {"workflow_dispatch": None}
    assert workflow["permissions"] == {"actions": "read", "contents": "read"}
    assert workflow["env"] == {
        "BCF_BOOTSTRAP_ARTIFACT_ID": "9740097978",
        "BCF_BOOTSTRAP_ARTIFACT_NAME": (
            "bcf-trusted-control-6368eb34ce08c1bfc4bc554fae02e5e10468455f-1"
        ),
        "BCF_BOOTSTRAP_ARTIFACT_DIGEST": (
            "sha256:b6015abf6b6b761c1f909d6e66fe72e71c0f67b84066db907800ab3b6c27d115"
        ),
        "BCF_BOOTSTRAP_RUN_ID": "33339477463",
        "BCF_BOOTSTRAP_RUN_ATTEMPT": "1",
        "BCF_BOOTSTRAP_COMMIT_SHA": "6368eb34ce08c1bfc4bc554fae02e5e10468455f",
        "BCF_BOOTSTRAP_TREE_SHA": "5d72e163481e7f8e42d20e5aeb1d7d8091dbf5d2",
        "BCF_BOOTSTRAP_REPOSITORY_ID": "1207503211",
        "BCF_BOOTSTRAP_WHEEL_SHA256": (
            "72cbc4bb1c9c31a1c3b362cd93e99ccf5704755c9499849e7174ffa419e4e58c"
        ),
    }
    job = workflow["jobs"]["bootstrap"]
    assert job["timeout-minutes"] == 10
    assert job["strategy"] == {
        "fail-fast": False,
        "max-parallel": 2,
        "matrix": {
            "trusted_runner": ["bcf-trusted-control-1", "bcf-trusted-control-2"]
        },
    }
    assert all("actions/checkout@" not in step.get("uses", "") for step in job["steps"])
    download = next(
        step for step in job["steps"]
        if step.get("name") == "Download only the authenticated controller artifact"
    )
    assert download["uses"] == (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    )
    assert download["with"] == {
        "artifact-ids": "${{ env.BCF_BOOTSTRAP_ARTIFACT_ID }}",
        "github-token": "${{ github.token }}",
        "repository": "${{ github.repository }}",
        "run-id": "${{ env.BCF_BOOTSTRAP_RUN_ID }}",
        "path": "${{ runner.temp }}/bcf-trusted-control-bootstrap",
        "digest-mismatch": "error",
    }
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "/actions/artifacts/{expected['id']}" in commands
    assert 'api != "https://api.github.com"' in commands
    assert 'repository != "mjgolaszewski/bcf-governance"' in commands
    assert "sha256sum --check SHA256SUMS" in commands
    assert "pip install --no-index" in commands
    assert "bcf_governance-0.6.1-py3-none-any.whl" in commands
    assert "pip install -r" not in commands
    assert "actions/checkout" not in commands
    assert "existing trusted control installation has stale provenance" in commands
    assert '"$selected_python" -m venv "$install_root"' in commands
    assert 'mv -- "$stage" "$install_root"' not in commands
    assert '"$install_root/bin/bcf" ci-github --help >/dev/null' in commands
    assert commands.rindex(
        '"$install_root/bin/bcf" ci-github --help >/dev/null'
    ) > commands.index('"$selected_python" -m venv "$install_root"')


def test_self_governance_runner_classification_is_exact_and_has_no_fallback() -> None:
    runner_policy = _policy()["runner_security"]
    expected_jobs = runner_policy["jobs"]
    observed_jobs: dict[str, dict[str, str]] = {}
    for relative_path, classification in expected_jobs.items():
        workflow_path = REPO_ROOT / relative_path
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        jobs = workflow["jobs"]
        assert set(jobs) == set(classification)
        observed_jobs[relative_path] = classification
        for job_id, trust_class in classification.items():
            if trust_class in {"trusted", "trusted_bootstrap"}:
                expected_labels = list(runner_policy["trusted_labels"])
                strategy = jobs[job_id].get("strategy")
                if strategy and "trusted_runner" in strategy.get("matrix", {}):
                    assert strategy["matrix"]["trusted_runner"] == runner_policy[
                        "trusted_instance_labels"
                    ]
                    expected_labels.append("${{ matrix.trusted_runner }}")
            else:
                expected_labels = runner_policy["candidate_routing"]["candidate_runner"]
            assert jobs[job_id]["runs-on"] == expected_labels
    assert observed_jobs == expected_jobs
    assert runner_policy["hosted_fallback_allowed"] is False
    assert runner_policy["candidate_substrate"] == "github_standard_hosted_fresh_vm"
    assert runner_policy["coordination_policy"] == [
        "no_polling",
        "no_sleeping",
        "no_idle_waiters",
    ]


def test_all_candidate_code_uses_fresh_standard_hosted_workers() -> None:
    runner_policy = _policy()["runner_security"]
    routing = runner_policy["candidate_routing"]
    assert routing == {
        "candidate_runner": "ubuntu-latest",
        "repository_visibility": "public",
        "billing_class": "standard_public_repository",
    }
    for relative_path, classifications in runner_policy["jobs"].items():
        workflow = yaml.safe_load(
            (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        )
        for job_id, trust_class in classifications.items():
            if trust_class == "candidate":
                assert workflow["jobs"][job_id]["runs-on"] == "ubuntu-latest"


def test_trusted_jobs_never_checkout_or_invoke_candidate_scripts() -> None:
    runner_policy = _policy()["runner_security"]
    pinned_action = re.compile(r"^[^@]+@[0-9a-f]{40}$")
    for relative_path, classification in runner_policy["jobs"].items():
        workflow = yaml.safe_load(
            (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        )
        for job_id, trust_class in classification.items():
            if trust_class not in {"trusted", "trusted_bootstrap"}:
                continue
            steps = workflow["jobs"][job_id]["steps"]
            assert all("actions/checkout@" not in step.get("uses", "") for step in steps)
            for step in steps:
                if "uses" in step:
                    assert pinned_action.fullmatch(step["uses"])
                command = step.get("run", "")
                assert "scripts/" not in command
                assert ".github/" not in command
                if trust_class == "trusted":
                    assert "python" not in command
                else:
                    assert "actions/checkout" not in command
                    assert "pip install --no-index" in "\n".join(
                        value.get("run", "") for value in steps
                    )
    interpreter = runner_policy["trusted_controller_interpreter"]
    for relative_path in interpreter["required_workflows"]:
        workflow = yaml.safe_load(
            (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        )
        steps = next(iter(workflow["jobs"].values()))["steps"]
        setup = [
            step
            for step in steps
            if step.get("uses", "").startswith("actions/setup-python@")
        ]
        assert len(setup) == 1
        assert setup[0]["uses"] == interpreter["action"]
        assert setup[0]["with"] == {"python-version": interpreter["python_version"]}


def test_hosted_candidates_and_trusted_publication_are_separated() -> None:
    runner_policy = _policy()["runner_security"]
    routing = runner_policy["candidate_routing"]
    assert routing["candidate_runner"] not in runner_policy["trusted_labels"]
    window = runner_policy["temporary_local_window"]
    assert window["status"] == "closed"
    assert window["privileged_publication_enabled"] is False
    for relative_path, classification in runner_policy["jobs"].items():
        workflow = yaml.safe_load(
            (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        )
        for job_id, trust_class in classification.items():
            if trust_class in {"trusted", "trusted_bootstrap"}:
                activation = runner_policy["trusted_job_activation"][relative_path][job_id]
                if activation == "disabled":
                    assert workflow["jobs"][job_id]["if"] == "${{ false }}"
                else:
                    assert activation == "owner_main_dispatch"
                    assert workflow["jobs"][job_id]["if"] == (
                        "${{ github.actor == 'mjgolaszewski' && "
                        "github.ref == 'refs/heads/main' }}"
                    )
    release = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    )
    assert release["jobs"]["release-artifacts"]["if"] == "${{ false }}"


def test_workflows_have_no_runner_occupying_coordination() -> None:
    forbidden = re.compile(r"\b(sleep|poll|wait|while|until)\b", re.IGNORECASE)
    for relative_path in _policy()["runner_security"]["jobs"]:
        workflow = yaml.safe_load(
            (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        )
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                assert forbidden.search(step.get("run", "")) is None


def test_governance_evidence_shards_derive_every_required_gate_once() -> None:
    module = _load_github_script("capture_governance_shard.py")
    expected = module.required_gate_targets(REPO_ROOT)
    shards = [
        module.partition_required_gates(REPO_ROOT, shard_index=index, shard_count=4)
        for index in range(4)
    ]
    flattened = [gate for shard in shards for gate in shard]
    assert sorted(flattened) == expected
    assert len(flattened) == len(set(flattened))
    assert max(map(len, shards)) - min(map(len, shards)) <= 1
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/governance.yml").read_text(encoding="utf-8")
    )
    strategy = workflow["jobs"]["evidence"]["strategy"]
    assert strategy["max-parallel"] == 4
    assert strategy["matrix"] == {"shard": [0, 1, 2, 3]}


def test_governance_shard_forwards_the_preflight_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_github_script("capture_governance_shard.py")
    commands: list[list[str]] = []
    monkeypatch.setattr(module, "partition_required_gates", lambda *_, **__: ["test"])
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **_: commands.append(command)
        or subprocess.CompletedProcess(command, 0),
    )
    manifest = tmp_path / "evidence-session.json"
    output = tmp_path / "session"
    monkeypatch.setattr(
        module.sys,
        "argv",
        [
            "capture_governance_shard.py",
            "--shard-index",
            "0",
            "--shard-count",
            "4",
            "--output-root",
            str(output),
            "--session-manifest",
            str(manifest),
        ],
    )
    module.main()
    assert len(commands) == 1
    assert commands[0][commands[0].index("--output") + 1] == str(output / "test")
    assert commands[0][commands[0].index("--session-manifest") + 1] == str(manifest)


def test_self_gate_runner_bootstraps_an_uninstalled_source_checkout() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            ".github/scripts/run_self_governance_gate.py",
            "runtime-smoke",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_self_gate_tests_use_the_selected_python_module_entrypoint() -> None:
    source = (REPO_ROOT / ".github/scripts/run_self_governance_gate.py").read_text(
        encoding="utf-8"
    )
    assert '[sys.executable, "-m", "pytest"' in source
    assert '["pytest", "-q"' not in source
    assert "TEST_NODES" not in source
    assert "governance/gate-contracts.yml" in source
    for workflow in (REPO_ROOT / ".github/workflows").glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        assert "run: pytest " not in text, workflow


def test_persistent_local_jobs_do_not_persist_checkout_credentials() -> None:
    policy = _policy()["runner_security"]
    for relative_path in policy["jobs"]:
        workflow = yaml.safe_load((REPO_ROOT / relative_path).read_text(encoding="utf-8"))
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if step.get("uses", "").startswith("actions/checkout@"):
                    assert step.get("with", {}).get("persist-credentials") is False


def test_governance_fan_in_is_preflight_ordered_and_attempt_exact() -> None:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/governance.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    assert jobs["evidence"]["needs"] == ["preflight"]
    preflight_command = next(
        step["run"]
        for step in jobs["preflight"]["steps"]
        if step.get("name") == "Run canonical cheap preflight and allocate one evidence session"
    )
    assert "scripts/preflight_governance.py" in preflight_command
    assert "--expected-producer evidence" in preflight_command
    assert jobs["preflight"]["outputs"]["session_manifest"] == (
        "${{ steps.preflight.outputs.session_manifest }}"
    )
    session_upload = next(
        step
        for step in jobs["preflight"]["steps"]
        if step.get("with", {}).get("name", "").startswith("bcf-session-")
    )
    assert session_upload["with"]["name"] == (
        "bcf-session-${{ github.run_id }}-${{ github.run_attempt }}"
    )

    evidence_download = next(
        step
        for step in jobs["evidence"]["steps"]
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert evidence_download["with"]["name"] == session_upload["with"]["name"]
    capture_command = next(
        step["run"]
        for step in jobs["evidence"]["steps"]
        if step.get("name") == "Capture mechanically derived evidence shard"
    )
    assert "--session-manifest" in capture_command
    assert "${session%/evidence-session.json}" in capture_command

    upload = next(
        step
        for step in jobs["evidence"]["steps"]
        if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    lane_namespace = upload["with"]["name"]
    assert lane_namespace == (
        "bcf-evidence-${{ github.run_id }}-${{ github.run_attempt }}-shard-${{ matrix.shard }}"
    )

    download = next(
        step
        for step in jobs["governance-truthfulness"]["steps"]
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert download["with"]["pattern"] == (
        "bcf-evidence-${{ github.run_id }}-${{ github.run_attempt }}-*"
    )
    assert download["with"]["path"] == ".artifacts/bcf/fan-in"
    assert "merge-multiple" not in download["with"]
    assert jobs["governance-truthfulness"]["needs"] == ["preflight", "evidence"]
    truth_command = next(
        step["run"]
        for step in jobs["governance-truthfulness"]["steps"]
        if "governance_truth.py" in step.get("run", "")
    )
    assert "/attempts/${{ github.run_attempt }}/" in truth_command
    terminal = next(
        step
        for step in jobs["governance-truthfulness"]["steps"]
        if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    truth_namespace = terminal["with"]["name"]
    assert truth_namespace == (
        "bcf-governance-truth-${{ github.run_id }}-${{ github.run_attempt }}"
    )
    assert not truth_namespace.startswith("bcf-evidence-")


def test_self_profile_builder_matches_canonical_negative_controls() -> None:
    generated = yaml.safe_load(
        subprocess.run(
            [sys.executable, ".github/scripts/build_self_governance_profile.py"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    canonical = yaml.safe_load(
        (REPO_ROOT / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    evidence_policy = yaml.safe_load(
        (REPO_ROOT / "governance/evidence-policy.yml").read_text(encoding="utf-8")
    )
    builtins = {"governance-validate", "governance-exposure-scan"}
    assert set(generated["gates"]) == set(canonical["gates"]) - builtins
    for gate_id, gate in generated["gates"].items():
        assert gate["invocation"] == canonical["gates"][gate_id]["invocation"]
        assert gate["negative_controls"] == canonical["gates"][gate_id]["negative_controls"]
        assert evidence_policy["gate_overrides"][gate_id]["negative_controls"] == gate[
            "negative_controls"
        ]
        if "test_contract" in gate["evidence"]:
            assert gate["evidence"]["test_contract"] == canonical["gates"][gate_id][
                "evidence"
            ]["test_contract"]
