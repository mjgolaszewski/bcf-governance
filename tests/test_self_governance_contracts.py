from __future__ import annotations

import ast
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.cli import COMMANDS
from bcf_governance.tooling.ci_adopt_github import (
    FINALIZER_ACTIVATION_EXPRESSION,
    PUBLISHER_ACTIVATION_EXPRESSION,
    render_github_v11_control_plane,
)
from bcf_governance.tooling.ci_github_actions import ACTION_PINS
from bcf_governance.tooling.ci_authority_pins import verify_workflow_authority
from bcf_governance.tooling.governance_validation.runner import validate_repo_root
from bcf_governance.tooling.release_runtime_verification import (
    is_release_sdist_test_context,
)
from bcf_governance.tooling.profile_v2_surfaces import render_v2_makefile


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
    if is_release_sdist_test_context(REPO_ROOT):
        pytest.skip("exact repository validation requires original Git custody")
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
    preflight_index = next(
        index for index, step in enumerate(steps)
        if step.get("name") == "Validate selected environment before package work"
    )
    assert preflight_index < pack_index < build_index
    assert "scripts/preflight_governance.py" in steps[preflight_index]["run"]
    assert "--python \"$(command -v python)\"" in steps[preflight_index]["run"]
    assert steps[preflight_index]["env"] == {
        "BCF_ENFORCE_PR_CHANGELOG": "${{ github.event_name == 'pull_request' }}",
        "BCF_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
    }
    assert workflow[True]["workflow_call"]["inputs"]["build_controller"] == {
        "description": "Build the trusted controller artifact for an exact-main admission",
        "required": False,
        "default": False,
        "type": "boolean",
    }
    assert steps[build_index]["if"] == (
        "inputs.build_controller == true && github.ref == 'refs/heads/main'"
    )
    assert upload["if"] == steps[build_index]["if"]
    assert upload["with"]["name"] == (
        "bcf-trusted-control-${{ github.sha }}-${{ github.run_attempt }}"
    )
    assert upload["with"]["retention-days"] == 30
    build_script = steps[build_index]["run"]
    assert "pip install build" not in build_script
    assert "pip download --only-binary=:all:" in build_script
    assert "'PyYAML>=6.0,<7' 'jsonschema>=4.21,<5'" in build_script
    assert "python -I .github/scripts/test_release_artifacts.py" in build_script
    assert "--controller-wheel-dir .artifacts/trusted-control" in build_script
    assert "sha256sum ./*.whl CONTROL-METADATA.json" in build_script


def test_trusted_bootstrap_is_owner_dispatched_pinned_and_offline() -> None:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/bcf-trusted-control-bootstrap.yml").read_text(
            encoding="utf-8"
        )
    )
    assert workflow[True] == {"workflow_dispatch": None}
    assert workflow["permissions"] == {"actions": "read", "contents": "read"}
    runner_policy = _policy()["runner_security"]
    artifact = runner_policy["trusted_controller_artifact"]
    installation = runner_policy["trusted_controller_installation"]
    assert workflow["env"] == {
        **artifact,
        "BCF_INSTALLED_CONTROLLER_COMMIT_SHA": installation[
            "installed_commit_sha"
        ],
    }
    assert artifact["BCF_BOOTSTRAP_ARTIFACT_NAME"] == (
        f"bcf-trusted-control-{artifact['BCF_BOOTSTRAP_COMMIT_SHA']}-"
        f"{artifact['BCF_BOOTSTRAP_RUN_ATTEMPT']}"
    )
    assert re.fullmatch(r"[1-9][0-9]*", artifact["BCF_BOOTSTRAP_ARTIFACT_ID"])
    assert re.fullmatch(r"[1-9][0-9]*", artifact["BCF_BOOTSTRAP_RUN_ID"])
    assert artifact["BCF_BOOTSTRAP_REPOSITORY_ID"] == "1207503211"
    assert re.fullmatch(
        r"sha256:[0-9a-f]{64}", artifact["BCF_BOOTSTRAP_ARTIFACT_DIGEST"]
    )
    assert re.fullmatch(r"[0-9a-f]{40}", artifact["BCF_BOOTSTRAP_COMMIT_SHA"])
    assert re.fullmatch(r"[0-9a-f]{40}", artifact["BCF_BOOTSTRAP_TREE_SHA"])
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["BCF_BOOTSTRAP_WHEEL_SHA256"])
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
        if step.get("name") == "Download only the pinned controller artifact"
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
    assert '"$control_root/bin/bcf" ci-github bootstrap' in commands
    assert "$BCF_INSTALLED_CONTROLLER_COMMIT_SHA" in commands
    assert '--provider-digest "$BCF_BOOTSTRAP_ARTIFACT_DIGEST"' in commands
    assert '--wheel-sha256 "$BCF_BOOTSTRAP_WHEEL_SHA256"' in commands
    assert '--tool-cache "$RUNNER_TOOL_CACHE"' in commands
    assert "python - <<" not in commands
    assert "sha256sum" not in commands
    assert "pip install" not in commands
    assert "bcf_governance-0.6.1-py3-none-any.whl" not in commands
    assert "pip install -r" not in commands
    assert "actions/checkout" not in commands

    probe = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/bcf-trusted-control-probe.yml").read_text(
            encoding="utf-8"
        )
    )
    assert probe["env"] == artifact
    assert job["name"] == "Install authenticated controller / ${{ matrix.trusted_runner }}"
    assert probe["jobs"]["probe"]["name"] == (
        "Verify exact-main controller / ${{ matrix.trusted_runner }}"
    )
    probe_commands = "\n".join(
        step.get("run", "") for step in probe["jobs"]["probe"]["steps"]
    )
    assert "$BCF_BOOTSTRAP_COMMIT_SHA" in probe_commands
    assert "$BCF_BOOTSTRAP_ARTIFACT_ID" in probe_commands
    assert "$BCF_BOOTSTRAP_WHEEL_SHA256" in probe_commands


def test_authority_canary_is_owner_dispatched_and_attempt_deterministic() -> None:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/bcf-authority-canary.yml").read_text(
            encoding="utf-8"
        )
    )
    scenario = workflow[True]["workflow_dispatch"]["inputs"]["scenario"]
    assert scenario == {
        "description": "Deterministic producer outcome for this exact run and every rerun attempt",
        "required": True,
        "default": "success",
        "type": "choice",
        "options": ["success", "producer-b-failure"],
    }
    jobs = workflow["jobs"]
    assert list(jobs) == ["admit", "producer-a", "producer-b", "observe"]
    assert jobs["producer-a"]["needs"] == ["admit"]
    assert jobs["producer-b"]["needs"] == ["admit"]
    assert jobs["observe"]["needs"] == ["admit", "producer-a", "producer-b"]
    assert jobs["observe"]["if"] == (
        "${{ always() && github.actor == 'mjgolaszewski' && "
        "github.ref == 'refs/heads/main' && needs.admit.result == 'success' }}"
    )
    for job_id in ("producer-a", "producer-b"):
        job = jobs[job_id]
        assert job["runs-on"] == _policy()["runner_security"]["candidate_routing"][
            "candidate_runner"
        ]
        assert job["permissions"] == {}
        assert job["env"] == {"BCF_CANARY_SCENARIO": "${{ inputs.scenario }}"}
        assert all("uses" not in step for step in job["steps"])
    assert "producer-b-failure) exit 86" in jobs["producer-b"]["steps"][0]["run"]
    assert workflow["env"]["BCF_CONTROL_COMMIT"] == _policy()["runner_security"][
        "trusted_controller_installation"
    ]["installed_commit_sha"]


@pytest.mark.parametrize(
    "relative_path",
    (
        ".github/workflows/governance-mutants-nightly.yml",
        ".github/workflows/governance-mutants-weekly.yml",
    ),
)
def test_scheduled_mutants_preflight_selected_interpreter_before_execution(
    relative_path: str,
) -> None:
    workflow = yaml.safe_load((REPO_ROOT / relative_path).read_text(encoding="utf-8"))
    steps = next(iter(workflow["jobs"].values()))["steps"]
    checkout = next(
        step for step in steps
        if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    commands = [step.get("run", "") for step in steps]
    preflight = (
        'python scripts/preflight_governance.py --repo-root . --mode release '
        '--python "$(command -v python)" --format text'
    )
    assert commands.count(preflight) == 1
    preflight_index = commands.index(preflight)
    mutant_indexes = [
        index
        for index, command in enumerate(commands)
        if "run_validator_mutants.py" in command
    ]
    assert mutant_indexes
    assert all(preflight_index < index for index in mutant_indexes)
    assert "--artifact-root" not in commands[preflight_index]
    assert all("--output .artifacts/scheduled-mutants/" in commands[index] for index in mutant_indexes)
    upload_index, upload = next(
        (index, step)
        for index, step in enumerate(steps)
        if step.get("name", "").startswith("Retain exact ")
    )
    schedule = "nightly" if "nightly" in relative_path else "weekly"
    assert upload_index > max(mutant_indexes)
    assert upload["if"] == "${{ always() }}"
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"] == {
        "name": (
            f"bcf-scheduled-mutants-{schedule}-"
            "${{ github.run_id }}-${{ github.run_attempt }}"
        ),
        "path": ".artifacts/scheduled-mutants",
        "if-no-files-found": "error",
        "retention-days": 90,
    }


def test_trusted_callbacks_reject_prs_and_failed_finalizers_before_runner() -> None:
    finalizer = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/bcf-trusted-finalizer.yml").read_text()
    )
    publisher = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/bcf-status-publisher.yml").read_text()
    )
    assert finalizer["jobs"]["finalize"]["if"] == FINALIZER_ACTIVATION_EXPRESSION
    assert publisher["jobs"]["publish"]["if"] == PUBLISHER_ACTIVATION_EXPRESSION
    assert "workflow_run.event == 'push'" in FINALIZER_ACTIVATION_EXPRESSION
    assert "workflow_run.head_branch == 'main'" in FINALIZER_ACTIVATION_EXPRESSION
    assert "workflow_run.conclusion" not in PUBLISHER_ACTIVATION_EXPRESSION


def test_self_control_plane_is_an_exact_v11_generator_product() -> None:
    topology = yaml.safe_load(
        (REPO_ROOT / "governance/github-ci-topology.yml").read_text(encoding="utf-8")
    )
    expected = render_github_v11_control_plane(
        default_branch="main",
        trusted_labels=("self-hosted", "Linux", "X64", "bcf-governance", "vm-linux-ci-runner"),
        producer_jobs=(
            ("governance", "Run exact-main governance evidence", ".github/workflows/governance.yml", (("evaluation_mode", "closure"),)),
            ("governance-pack", "Verify exact-main package and templates", ".github/workflows/governance-pack.yml", (("build_controller", True), ("evaluation_mode", "release"))),
        ),
        controller_commit=topology["controller_commit"],
    )
    for relative, content in expected.items():
        assert yaml.safe_load((REPO_ROOT / relative).read_bytes()) == yaml.safe_load(content)


def test_exact_main_is_the_only_default_branch_producer() -> None:
    governance = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/governance.yml").read_text(encoding="utf-8")
    )
    pack = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/governance-pack.yml").read_text(
            encoding="utf-8"
        )
    )
    exact_main = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/bcf-exact-main.yml").read_text(
            encoding="utf-8"
        )
    )
    evidence_policy = yaml.safe_load(
        (REPO_ROOT / "governance/evidence-policy.yml").read_text(encoding="utf-8")
    )
    assert governance[True] == {
        "pull_request": None,
        "workflow_call": {
            "inputs": {
                "evaluation_mode": {
                    "description": "Exact truth evaluation mode selected by the trusted caller",
                    "required": False,
                    "default": "pr",
                    "type": "string",
                }
            }
        },
    }
    assert pack[True] == {
        "pull_request": None,
        "workflow_call": {
            "inputs": {
                "build_controller": {
                    "description": "Build the trusted controller artifact for an exact-main admission",
                    "required": False,
                    "default": False,
                    "type": "boolean",
                },
                "evaluation_mode": {
                    "description": "Preflight mode selected by the authenticated caller",
                    "required": False,
                    "default": "pr",
                    "type": "string",
                },
            }
        },
    }
    assert exact_main["on"] == {"push": {"branches": ["main"]}}
    workflow_contract = evidence_policy["workflow_contract"]
    assert workflow_contract["paths"] == [".github/workflows/governance.yml"]
    assert workflow_contract["required_events"] == ["pull_request", "workflow_call"]
    assert {
        job_id: (job["uses"], job["permissions"])
        for job_id, job in exact_main["jobs"].items()
        if job_id != "admit"
    } == {
        "governance": (
            "./.github/workflows/governance.yml",
            {"contents": "read"},
        ),
        "governance-pack": (
            "./.github/workflows/governance-pack.yml",
            {"contents": "read"},
        ),
    }
    assert exact_main["jobs"]["governance-pack"]["with"] == {
        "build_controller": True,
        "evaluation_mode": "release",
    }


def test_self_ci_authority_matches_immutable_workflow_definitions() -> None:
    authority = yaml.safe_load(
        (REPO_ROOT / "governance/ci-authority.yml").read_text(encoding="utf-8")
    )
    assert authority["repository"] == {
        "provider": "github",
        "repository_id": "1207503211",
    }
    assert authority["schema_version"] == "1.1"
    assert "admission_workflow" not in authority
    registry = authority["workflow_registry"]
    assert authority["roles"] == {
        "admission": "admission",
        "reusable_producers": ["governance", "governance-pack"],
        "finalizer": "finalizer",
        "status_publisher": "status-publisher",
        "bootstrap": "bootstrap",
        "probe": "probe",
        "release_authorizer": "release",
        "release_build": "release",
        "release_verifier": "release-verifier",
        "release_collector": "release-collector",
        "release_publisher": "release-publisher",
        "authority_canary": "authority-canary",
    }
    expected_events = {
        "admission": ["push"],
        "governance": ["pull_request", "workflow_call"],
        "governance-pack": ["pull_request", "workflow_call"],
        "finalizer": ["workflow_run"],
        "status-publisher": ["workflow_run"],
        "bootstrap": ["workflow_dispatch"],
        "probe": ["workflow_dispatch"],
        "release": ["workflow_dispatch"],
        "release-verifier": ["workflow_run"],
        "release-collector": ["workflow_run"],
        "release-publisher": ["workflow_dispatch"],
        "authority-canary": ["workflow_dispatch"],
    }
    assert set(registry) == set(expected_events)
    assert verify_workflow_authority(
        REPO_ROOT,
        authority_path=Path("governance/ci-authority.yml"),
        require_history=not is_release_sdist_test_context(REPO_ROOT),
    ) == len(expected_events)
    for reference, workflow in registry.items():
        assert workflow["allowed_events"] == expected_events[reference]
    assert [producer["producer_id"] for producer in authority["producers"]] == [
        "governance",
        "governance-pack",
    ]
    assert [producer["workflow_ref"] for producer in authority["producers"]] == (
        authority["roles"]["reusable_producers"]
    )
    assert authority["admission_jobs"] == [
        {"job_id": "Authenticate exact-main admission and publish pending authority"}
    ]
    assert all(producer["expected_jobs"] for producer in authority["producers"])
    assert authority["trusted_external_inputs"] == []


def test_every_github_action_uses_the_canonical_immutable_pin() -> None:
    observed: set[str] = set()
    roots = (
        REPO_ROOT / ".github/workflows",
        REPO_ROOT / "template-repo/.github/workflows",
        REPO_ROOT / "bcf_governance/pack/template-repo/.github/workflows",
    )
    for root in roots:
        for workflow_path in sorted(root.glob("*.yml")):
            workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    source = step.get("uses")
                    if not source:
                        continue
                    action_id = source.split("@", 1)[0].removeprefix("actions/")
                    assert source == ACTION_PINS[action_id], workflow_path
                    observed.add(action_id)
    assert observed == set(ACTION_PINS)


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
    assert strategy["matrix"] == module.workflow_shard_matrix()
    assert workflow["jobs"]["evidence"]["name"] == (
        "Evidence / ${{ matrix.display_name }}"
    )


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
            for step in job.get("steps", []):
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
    prerequisite_guard = (
        "needs.preflight.result == 'success' && needs.evidence.result == 'success'"
    )
    guarded = [
        step
        for step in jobs["governance-truthfulness"]["steps"]
        if step.get("uses", "").startswith(("actions/setup-python@", "actions/download-artifact@"))
        or "pip install" in step.get("run", "")
        or "find .artifacts/bcf/fan-in" in step.get("run", "")
        or "governance_truth.py" in step.get("run", "")
    ]
    assert guarded and all(step["if"] == prerequisite_guard for step in guarded)
    terminal_observation = next(
        step
        for step in jobs["governance-truthfulness"]["steps"]
        if step.get("name") == "Preserve a causal terminal result"
    )
    assert terminal_observation["if"] == "always()"
    assert "governance_terminal_observation.py" in terminal_observation["run"]
    assert '--preflight-result "${{ needs.preflight.result }}"' in terminal_observation["run"]
    assert '--evidence-result "${{ needs.evidence.result }}"' in terminal_observation["run"]
    truth_command = next(
        step["run"]
        for step in jobs["governance-truthfulness"]["steps"]
        if "governance_truth.py" in step.get("run", "")
    )
    assert "/attempts/${{ github.run_attempt }}/" in truth_command
    assert "--evaluation-mode" in truth_command
    assert "inputs.evaluation_mode || 'pr'" in truth_command
    assert "github.event_name" not in truth_command
    preflight_command = next(
        step["run"]
        for step in jobs["preflight"]["steps"]
        if step.get("id") == "preflight"
    )
    assert "inputs.evaluation_mode == 'closure'" in preflight_command
    assert "&& 'release' || 'pr'" in preflight_command
    assert "github.event_name" not in preflight_command
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


def test_self_release_check_is_an_exact_generator_product() -> None:
    contract = yaml.safe_load(
        (REPO_ROOT / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )

    assert (REPO_ROOT / "Makefile.fragment").read_text(
        encoding="utf-8"
    ) == render_v2_makefile(contract)


def test_self_profile_builder_keeps_evidence_semantics_single_owned() -> None:
    generated = yaml.safe_load(
        subprocess.run(
            [sys.executable, ".github/scripts/build_self_governance_profile.py"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
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
    assert evidence_policy["gate_overrides"] == {}
    for gate_id, gate in generated["gates"].items():
        assert gate["invocation"] == canonical["gates"][gate_id]["invocation"]
        assert gate["negative_controls"] == canonical["gates"][gate_id]["negative_controls"]
        if "test_contract" in gate["evidence"]:
            assert gate["evidence"]["test_contract"] == canonical["gates"][gate_id][
                "evidence"
            ]["test_contract"]
