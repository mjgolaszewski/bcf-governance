from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from bcf_governance.cli import COMMANDS
from bcf_governance.tooling.ci_authority_pins import verify_workflow_authority
from bcf_governance.tooling.ci_github_actions import ACTION_PINS
from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.ci_graph_render import check_ci_graph, render_ci_graph
from bcf_governance.tooling.governance_validation.runner import validate_repo_root
from bcf_governance.tooling.profile_v2_surfaces import render_v2_makefile
from bcf_governance.tooling.release_runtime_verification import (
    is_release_sdist_test_context,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "governance/self-governance-policy.yml"


def _load_github_script(name: str):
    path = REPO_ROOT / ".github/scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _policy() -> dict[str, object]:
    return yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))


def _architecture() -> dict[str, object]:
    payload = yaml.safe_load(
        (REPO_ROOT / "architecture-boundaries.yml").read_text(encoding="utf-8")
    )
    return payload["architecture"]


def _python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _workflow(workflow_id: str) -> dict[str, object]:
    return next(
        workflow
        for workflow in validate_ci_graph(REPO_ROOT).workflows
        if workflow["id"] == workflow_id
    )


def _job(workflow_id: str, job_id: str) -> dict[str, object]:
    return next(job for job in _workflow(workflow_id)["jobs"] if job["id"] == job_id)


def test_source_roots_match_packaged_implementation() -> None:
    assert _architecture()["source_roots"] == ["bcf_governance"]
    assert 'include = ["bcf_governance*"]' in (REPO_ROOT / "pyproject.toml").read_text()


def test_source_layout_maps_to_declared_package_layers() -> None:
    layers = _architecture()["layers"]
    for path in _python_files(REPO_ROOT / "bcf_governance"):
        parts = path.relative_to(REPO_ROOT / "bcf_governance").parts
        token = parts[0] if len(parts) > 1 else path.stem
        matches = [name for name, rule in layers.items() if token in rule["path_tokens"]]
        assert len(matches) == 1, f"{path.relative_to(REPO_ROOT)} maps to {matches}"


def test_production_modules_respect_self_governance_loc_cap() -> None:
    cap = int(_architecture()["production_module_policy"]["max_loc"])
    violations = [
        f"{path.relative_to(REPO_ROOT)}:{len(path.read_text().splitlines())}"
        for path in _python_files(REPO_ROOT / "bcf_governance")
        if len(path.read_text().splitlines()) > cap
    ]
    assert not violations, "module LOC cap exceeded: " + ", ".join(violations)


def test_tooling_modules_map_to_exactly_one_context() -> None:
    contexts = _policy()["tooling_contexts"]
    for path in _python_files(REPO_ROOT / "bcf_governance/tooling"):
        relative = path.relative_to(REPO_ROOT / "bcf_governance/tooling").as_posix()
        if relative == "__init__.py" or relative.endswith("/__init__.py"):
            continue
        matches = [
            name
            for name, prefixes in contexts.items()
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
    assert not violations


def test_cli_command_query_sides_are_complete_and_disjoint() -> None:
    groups = _policy()["cli_commands"]
    read_only, mutating = set(groups["read_only"]), set(groups["mutating"])
    assert not read_only & mutating
    assert read_only | mutating == set(COMMANDS)


def test_cli_and_source_wrappers_remain_thin() -> None:
    cap = int(_policy()["thin_wrapper_loc_cap"])
    violations = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _python_files(REPO_ROOT / "scripts")
        if path.name != "__init__.py" and len(path.read_text().splitlines()) >= cap
    ]
    assert not violations


def test_template_and_private_runtime_copies_are_exact() -> None:
    tooling = REPO_ROOT / "bcf_governance/tooling"
    runtime = REPO_ROOT / "template-repo/scripts/_bcf_runtime"
    mismatches = [
        path.relative_to(tooling).as_posix()
        for path in _python_files(tooling)
        if path.read_bytes() != (runtime / path.relative_to(tooling)).read_bytes()
    ]
    assert not mismatches


def test_required_repository_artifact_contract_is_executable() -> None:
    if is_release_sdist_test_context(REPO_ROOT):
        pytest.skip("exact repository validation requires original Git custody")
    validate_repo_root(REPO_ROOT)


def test_changelog_pr_enforcement_is_wired_into_repository_ci() -> None:
    for relative in (".github/workflows/governance.yml", ".github/workflows/governance-pack.yml"):
        payload = yaml.safe_load(render_ci_graph(REPO_ROOT)[relative])
        assert payload["env"] == {
            "BCF_ENFORCE_PR_CHANGELOG": "${{ github.event_name == 'pull_request' }}",
            "BCF_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        }


def test_exact_main_controller_wheel_is_built_once_after_pack_checks() -> None:
    pack = _job("governance-pack", "pack-checks")
    assert pack["executor"]["components"] == [
        "checkout-candidate", "setup-python", "install-governance",
        "check-generated-pack", "build-trusted-controller", "upload-trusted-controller",
    ]
    assert pack["produces"] == ["trusted-controller-bundle"]
    graph = validate_ci_graph(REPO_ROOT).graph
    assert graph["conditions"]["build-exact-main-controller"] == (
        "inputs.build_controller == true && github.ref == 'refs/heads/main'"
    )


def test_trusted_bootstrap_is_owner_dispatched_pinned_and_offline() -> None:
    workflow = _workflow("trusted-controller-bootstrap")
    job = _job("trusted-controller-bootstrap", "bootstrap")
    assert workflow["events"] == [{"type": "workflow_dispatch"}]
    assert job["trust"] == "trusted" and job["checkout"] is False
    assert job["resource_class"] == "trusted-control-instance"
    assert job["executor"]["components"] == [
        "setup-python", "download-bootstrap-controller", "bootstrap-controller",
    ]
    command = validate_ci_graph(REPO_ROOT).commands["bootstrap-controller"]
    assert command["argv"][:3] == ["{controller}", "ci-github", "bootstrap"]
    assert set(command["required_environment"]) == set(
        _policy()["runner_security"]["trusted_controller_artifact"]
    )


def test_authority_canary_is_owner_dispatched_and_attempt_deterministic() -> None:
    workflow = _workflow("authority-canary")
    assert workflow["events"][0]["inputs"]["scenario"]["options"] == [
        "success", "producer-b-failure",
    ]
    assert [job["id"] for job in workflow["jobs"]] == [
        "admit", "producer-a", "producer-b", "observe",
    ]
    assert _job("authority-canary", "observe")["needs"] == [
        "admit", "producer-a", "producer-b",
    ]
    assert validate_ci_graph(REPO_ROOT).graph["conditions"]["owner-main-observer"].startswith(
        "always() &&"
    )


@pytest.mark.parametrize(
    "workflow_id",
    ("scheduled-nightly-mutants", "scheduled-weekly-mutants"),
)
def test_scheduled_mutants_preflight_selected_interpreter_before_execution(
    workflow_id: str,
) -> None:
    job = _workflow(workflow_id)["jobs"][0]
    components = job["executor"]["components"]
    assert components.index("scheduled-preflight") < components.index(
        "nightly-validator-mutants" if "nightly" in workflow_id else "weekly-validator-mutants"
    )
    assert components[-1] == (
        "upload-nightly-mutants" if "nightly" in workflow_id else "upload-weekly-mutants"
    )
    upload = validate_ci_graph(REPO_ROOT).graph["step_components"][components[-1]]
    assert upload["condition"] == "always-step"
    checkout = validate_ci_graph(REPO_ROOT).graph["step_components"]["checkout-candidate"]
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}


def test_trusted_callbacks_reject_prs_and_failed_finalizers_before_runner() -> None:
    conditions = validate_ci_graph(REPO_ROOT).graph["conditions"]
    assert "workflow_run.event == 'push'" in conditions["exact-main-finalizer-admitted"]
    assert "workflow_run.conclusion" not in conditions["exact-main-publisher-admitted"]
    assert conditions["exact-main-publisher-admitted"] == (
        "vars.BCF_CI_AUTHORITY_ENABLED == 'true' && "
        "github.event.workflow_run.event == 'workflow_run' && "
        "github.event.workflow_run.head_branch == 'main'"
    )


def test_self_control_plane_is_an_exact_v11_generator_product() -> None:
    assert check_ci_graph(REPO_ROOT).status == "clean"


def test_exact_main_is_the_only_default_branch_producer() -> None:
    workflows = validate_ci_graph(REPO_ROOT).workflows
    push = [
        workflow for workflow in workflows
        if any(event["type"] == "push" for event in workflow["events"])
    ]
    assert [(workflow["id"], workflow["role"]) for workflow in push] == [
        ("exact-main", "exact-main")
    ]
    assert [job["id"] for job in _workflow("exact-main")["jobs"]] == [
        "admit", "governance", "governance-pack",
    ]
    assert _job("exact-main", "governance-pack")["executor"]["inputs"] == {
        "build_controller": True,
        "evaluation_mode": "release",
    }


def test_self_ci_authority_matches_immutable_workflow_definitions() -> None:
    assert verify_workflow_authority(
        REPO_ROOT,
        authority_path=Path("governance/ci-authority.yml"),
        require_history=not is_release_sdist_test_context(REPO_ROOT),
    ) == 12


def test_every_github_action_uses_the_canonical_immutable_pin() -> None:
    observed: set[str] = set()
    for content in render_ci_graph(REPO_ROOT).values():
        workflow = yaml.safe_load(content)
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                source = step.get("uses")
                if source:
                    action_id = source.split("@", 1)[0].removeprefix("actions/")
                    assert source == ACTION_PINS[action_id]
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
    evidence = _job("governance", "evidence")
    assert evidence["display_name"] == "Evidence / ${{ matrix.display_name }}"
    assert evidence["strategy"]["matrix"] == module.workflow_shard_matrix()


def test_governance_shard_forwards_the_preflight_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_github_script("capture_governance_shard.py")
    commands: list[list[str]] = []
    monkeypatch.setattr(module, "partition_required_gates", lambda *_, **__: ["test"])
    monkeypatch.setattr(
        module.subprocess, "run",
        lambda command, **_: commands.append(command) or subprocess.CompletedProcess(command, 0),
    )
    manifest, output = tmp_path / "evidence-session.json", tmp_path / "session"
    monkeypatch.setattr(
        module.sys, "argv",
        ["capture_governance_shard.py", "--shard-index", "0", "--shard-count", "4",
         "--output-root", str(output), "--session-manifest", str(manifest)],
    )
    module.main()
    assert commands[0][commands[0].index("--session-manifest") + 1] == str(manifest)


def test_self_gate_runner_bootstraps_an_uninstalled_source_checkout() -> None:
    result = subprocess.run(
        [sys.executable, "-I", ".github/scripts/run_self_governance_gate.py", "runtime-smoke"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_self_gate_tests_use_the_selected_python_module_entrypoint() -> None:
    source = (REPO_ROOT / ".github/scripts/run_self_governance_gate.py").read_text()
    assert '[sys.executable, "-m", "pytest"' in source
    assert "TEST_NODES" not in source
    assert all(
        "run: pytest " not in content.decode("utf-8")
        for content in render_ci_graph(REPO_ROOT).values()
    )


def test_persistent_local_jobs_do_not_persist_checkout_credentials() -> None:
    for content in render_ci_graph(REPO_ROOT).values():
        workflow = yaml.safe_load(content)
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("actions/checkout@"):
                    assert step.get("with", {}).get("persist-credentials") is False


def test_governance_fan_in_is_preflight_ordered_and_attempt_exact() -> None:
    graph = validate_ci_graph(REPO_ROOT).graph
    evidence = _job("governance", "evidence")
    truth = _job("governance", "governance-truthfulness")
    assert evidence["needs"] == ["preflight"]
    assert truth["needs"] == ["preflight", "evidence"]
    assert truth["consumes"] == evidence["produces"] == ["governance-receipts"]
    assert graph["artifacts"]["governance-receipts"]["scope"] == "run-attempt"
    assert graph["artifacts"]["governance-truth-report"]["kind"] == "terminal"
    assert graph["commands"]["governance-preflight"]["argv"][5] == (
        "${{ inputs.evaluation_mode == 'closure' && 'release' || 'pr' }}"
    )
    assert graph["step_components"]["run-governance-truth"]["condition"] == (
        "evidence-prerequisites-green"
    )


def test_self_release_check_is_an_exact_generator_product() -> None:
    contract = yaml.safe_load((REPO_ROOT / "governance/gate-contracts.yml").read_text())
    assert (REPO_ROOT / "Makefile.fragment").read_text() == render_v2_makefile(contract)


def test_self_profile_builder_keeps_evidence_semantics_single_owned() -> None:
    generated = yaml.safe_load(
        subprocess.run(
            [sys.executable, ".github/scripts/build_self_governance_profile.py"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        ).stdout
    )
    canonical = yaml.safe_load((REPO_ROOT / "governance/gate-contracts.yml").read_text())
    assert set(generated["gates"]) == set(canonical["gates"]) - {
        "governance-validate", "governance-exposure-scan",
    }
    for gate_id, gate in generated["gates"].items():
        assert gate["invocation"] == canonical["gates"][gate_id]["invocation"]
        assert gate["negative_controls"] == canonical["gates"][gate_id]["negative_controls"]
