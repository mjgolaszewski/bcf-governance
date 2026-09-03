from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest
import yaml

from bcf_governance.cli import COMMANDS
from bcf_governance.tooling.ci_authority_pins import verify_workflow_authority
from bcf_governance.tooling.ci_github_actions import ACTION_PINS
from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.ci_graph_execution import job_required_environment
from bcf_governance.tooling.ci_graph_render import check_ci_graph, render_ci_graph
from bcf_governance.tooling.governance_validation.runner import validate_repo_root
from bcf_governance.tooling.profile_v2_surfaces import render_v2_makefile
from bcf_governance.tooling.release_runtime_verification import (
    is_release_sdist_test_context,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "governance/self-governance-policy.yml"


def _all_strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(
            item for nested in value.values() for item in _all_strings(nested)
        )
    if isinstance(value, list):
        return tuple(item for nested in value for item in _all_strings(nested))
    return ()


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
        "setup-python",
        "download-bootstrap-controller",
        "stage-bootstrap-controller",
        "bootstrap-controller",
    ]
    command = validate_ci_graph(REPO_ROOT).commands["bootstrap-controller"]
    assert command["argv"][:3] == ["{ephemeral_controller}", "ci-github", "bootstrap"]
    assert set(command["required_environment"]) == set(
        _policy()["runner_security"]["trusted_controller_artifact"]
    )


def test_every_required_environment_is_validated_once_before_generated_work() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    rendered = render_ci_graph(REPO_ROOT)
    observed = 0
    for workflow in compiled.workflows:
        projection = yaml.safe_load(rendered[workflow["path"]])
        for job in workflow["jobs"]:
            bindings, issues = job_required_environment(
                compiled.graph, workflow, job, job["executor"]
            )
            assert not issues
            if not bindings:
                continue
            observed += 1
            first = projection["jobs"][job["id"]]["steps"][0]
            assert first["name"] == "Validate all required environment inputs before work"
            assert first["env"] == bindings
    assert observed > 0


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


def test_trusted_no_checkout_artifacts_are_job_scoped() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    rendered = {
        path: yaml.safe_load(content)
        for path, content in render_ci_graph(REPO_ROOT).items()
    }
    inspected = 0
    for workflow in compiled.workflows:
        workflow_jobs = rendered[workflow["path"]]["jobs"]
        for job in workflow["jobs"]:
            if job["trust"] != "trusted" or job["checkout"] is not False:
                continue
            for step in workflow_jobs[job["id"]].get("steps", []):
                for value in _all_strings(step):
                    assert ".artifacts/" not in value
                    parts = value.split("${{ runner.temp }}/")
                    for tail in parts[1:]:
                        suffix = "-${{ github.run_id }}-${{ github.run_attempt }}"
                        suffix_at = tail.find(suffix)
                        assert suffix_at > 0
                        assert "/" not in tail[:suffix_at]
                        inspected += 1
    assert inspected >= 15


def test_exact_main_is_the_only_default_branch_producer() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    workflows = compiled.workflows
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
    assert compiled.graph["conditions"]["exact-main-authority-enabled"] == (
        "vars.BCF_CI_AUTHORITY_ENABLED == 'true'"
    )


def test_self_ci_authority_matches_immutable_workflow_definitions() -> None:
    authority = yaml.safe_load(
        (REPO_ROOT / "governance/ci-authority.yml").read_text(encoding="utf-8")
    )
    assert verify_workflow_authority(
        REPO_ROOT,
        authority_path=Path("governance/ci-authority.yml"),
        require_history=not is_release_sdist_test_context(REPO_ROOT),
    ) == len(authority["workflow_registry"])


def test_automation_authority_is_metadata_only_and_candidate_excluded() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    admission = _job("automation-admission", "admit")
    reconcile = _job("automation-reconcile", "reconcile")
    publisher = _job("pr-status-publisher", "publish")
    assert _workflow("automation-admission")["events"] == [
        {"type": "pull_request_target"}
    ]
    assert compiled.graph["conditions"]["automation-dependabot-actor"] == (
        "github.event.pull_request.user.id == 49699333"
    )
    assert admission["checkout"] is False and admission["trust"] == "trusted"
    assert admission["permissions"].get("contents") == "read"
    assert reconcile["checkout"] is False
    assert reconcile["protected_environment"] == "bcf-trusted-automation"
    assert publisher["permissions"] == {
        "actions": "read",
        "checks": "write",
        "contents": "read",
        "pull-requests": "read",
    }
    assert all(
        job["permissions"].get("checks") != "write"
        for workflow in compiled.workflows
        for job in workflow["jobs"]
        if job["trust"] == "candidate"
    )


def test_automation_front_doors_precede_expensive_fanout_and_old_runner_is_absent() -> None:
    governance = _workflow("governance")
    package = _workflow("governance-pack")
    def depends_on(workflow: dict[str, object], job_id: str, owner: str) -> bool:
        by_id = {job["id"]: job for job in workflow["jobs"]}
        pending = list(by_id[job_id]["needs"])
        visited: set[str] = set()
        while pending:
            dependency = pending.pop()
            if dependency == owner:
                return True
            if dependency not in visited:
                visited.add(dependency)
                pending.extend(by_id[dependency]["needs"])
        return False

    assert all(
        depends_on(governance, job["id"], "preflight")
        for job in governance["jobs"]
        if job["id"] != "preflight"
    )
    assert all(
        depends_on(package, job["id"], "front-door")
        for job in package["jobs"]
        if job["id"] != "front-door"
    )
    rendered = b"\n".join(render_ci_graph(REPO_ROOT).values())
    assert b"bcf-governance-vm-linux-ci-runner-dependabot-1" not in rendered
    assert b"dependabot-1" not in rendered


def test_pre_activation_protected_checks_remain_rendered_until_mechanical_cutover() -> None:
    baseline = yaml.safe_load(
        (REPO_ROOT / "audits/p18-provider-baseline.yml").read_text(encoding="utf-8")
    )
    compiled = validate_ci_graph(REPO_ROOT)
    rendered_job_names = {
        str(job["display_name"])
        for workflow in compiled.workflows
        if any(event["type"] == "pull_request" for event in workflow["events"])
        for job in workflow["jobs"]
    }

    assert set(baseline["ruleset"]["required_checks"]) <= rendered_job_names


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
    assert graph["commands"]["governance-preflight"]["argv"][6:8] == [
        "--evaluation-mode",
        "${{ inputs.evaluation_mode || 'pr' }}",
    ]
    assert graph["step_components"]["run-governance-truth"]["condition"] == (
        "evidence-prerequisites-green"
    )


def test_governance_artifact_transport_restores_private_modes_before_capture(
    tmp_path: Path,
) -> None:
    graph = validate_ci_graph(REPO_ROOT).graph
    components = _job("governance", "evidence")["executor"]["components"]
    assert components.index("restore-governance-session-modes") == (
        components.index("download-governance-session") + 1
    )
    restore = graph["step_components"]["restore-governance-session-modes"]
    assert restore["condition"] is None
    assert restore["restores_private_artifacts"] == [
        "governance-session"
    ]
    assert graph["commands"][restore["command"]]["argv"][-1] == (
        ".artifacts/bcf/sessions"
    )
    rendered = yaml.safe_load(render_ci_graph(REPO_ROOT)[".github/workflows/governance.yml"])
    steps = rendered["jobs"]["evidence"]["steps"]
    rendered_restore = next(
        step for step in steps if step["name"] == "Restore downloaded evidence-session modes"
    )
    assert "if" not in rendered_restore
    assert ".artifacts/bcf/sessions" in rendered_restore["run"]
    assert steps.index(rendered_restore) + 1 == next(
        index
        for index, step in enumerate(steps)
        if step["name"] == "Capture the mechanically derived evidence shard"
    )
    root = tmp_path / "downloaded"
    session = root / "session-id"
    session.mkdir(parents=True)
    manifest = session / "evidence-session.json"
    manifest.write_text("{}\n", encoding="utf-8")
    root.chmod(0o755)
    session.chmod(0o755)
    manifest.chmod(0o644)

    restored = _load_github_script("restore_evidence_modes.py").restore(root)

    assert restored == 1
    assert stat.S_IMODE(session.stat().st_mode) == 0o700
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o400


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
