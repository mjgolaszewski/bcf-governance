from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import yaml

from bcf_governance.cli import COMMANDS
from bcf_governance.tooling.governance_validation.runner import validate_repo_root


REPO_ROOT = Path(__file__).resolve().parents[1]
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
    assert workflow["env"]["BCF_PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    for job in workflow["jobs"].values():
        checkout_steps = [
            step
            for step in job["steps"]
            if step.get("uses", "").startswith("actions/checkout@")
        ]
        assert checkout_steps
        assert all(step.get("with", {}).get("fetch-depth") == 0 for step in checkout_steps)


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
    builtins = {"governance-validate", "governance-exposure-scan"}
    assert set(generated["gates"]) == set(canonical["gates"]) - builtins
    for gate_id, gate in generated["gates"].items():
        assert gate["invocation"] == canonical["gates"][gate_id]["invocation"]
        assert gate["negative_controls"] == canonical["gates"][gate_id]["negative_controls"]
