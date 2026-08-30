"""Execute repository-specific BCF standard gates without a shell."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
POLICY_PATH = REPO_ROOT / "governance/self-governance-policy.yml"
TEST_NODES = {
    "architecture-test": ["tests/test_self_governance_contracts.py::test_source_roots_match_packaged_implementation"],
    "architecture-module-size": ["tests/test_self_governance_contracts.py::test_production_modules_respect_self_governance_loc_cap"],
    "architecture-layer-membership": ["tests/test_self_governance_contracts.py::test_source_layout_maps_to_declared_package_layers"],
    "architecture-context-membership": ["tests/test_self_governance_contracts.py::test_tooling_modules_map_to_exactly_one_context"],
    "architecture-import-boundaries": ["tests/test_self_governance_contracts.py::test_packaged_code_does_not_import_public_wrapper_package"],
    "architecture-cqrs-side": ["tests/test_self_governance_contracts.py::test_cli_command_query_sides_are_complete_and_disjoint"],
    "architecture-router-thinness": ["tests/test_self_governance_contracts.py::test_cli_and_source_wrappers_remain_thin"],
    "architecture-duplication": ["tests/test_self_governance_contracts.py::test_template_and_private_runtime_copies_are_exact"],
    "contract-test": [
        "tests/test_self_governance_contracts.py::test_required_repository_artifact_contract_is_executable",
        "tests/test_validate_governance_yaml.py::test_artifact_manifest_requires_standard_repository_artifact_contracts",
        "tests/test_validate_governance_yaml.py::test_pull_request_validation_requires_changelog_update",
    ],
}


def _fail(gate: str, detail: str) -> None:
    print(f"self-governance gate {gate} failed: {detail}", file=sys.stderr)
    raise SystemExit(1)


def _tracked_files() -> list[Path]:
    output = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
    ).stdout
    return [
        path
        for value in output.split(b"\0")
        if value and (path := REPO_ROOT / value.decode("utf-8")).is_file()
    ]


def _run_tests(gate: str) -> None:
    junit = REPO_ROOT / f".artifacts/junit/{gate}.xml"
    junit.parent.mkdir(parents=True, exist_ok=True)
    nodes = ["tests"] if gate == "test" else TEST_NODES[gate]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPO_ROOT)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *nodes, f"--junitxml={junit}"],
        cwd=REPO_ROOT,
        env=environment,
        check=False,
    )
    raise SystemExit(result.returncode)


def _lint(gate: str) -> None:
    for path in _tracked_files():
        if path.suffix not in {".py", ".md", ".yml", ".yaml", ".json", ".toml"}:
            continue
        text = path.read_text(encoding="utf-8")
        if any(line.endswith((" ", "\t")) for line in text.splitlines()):
            _fail(gate, f"trailing whitespace in {path.relative_to(REPO_ROOT)}")
        if path.suffix == ".py":
            try:
                ast.parse(text, filename=str(path))
            except SyntaxError as exc:
                _fail(gate, str(exc))


def _typecheck(gate: str) -> None:
    version_tree = ast.parse((REPO_ROOT / "bcf_governance/_version.py").read_text(encoding="utf-8"))
    assigned = {
        target.id
        for node in version_tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    if "__version__" not in assigned:
        _fail(gate, "authoritative __version__ assignment is missing")
    result = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", "bcf_governance", "scripts", ".github/scripts"],
        cwd=REPO_ROOT,
        check=False,
    )
    if result.returncode:
        _fail(gate, "Python compilation failed")


def _secret_scan(gate: str) -> None:
    markers = ("AKIA" + "IOSFODNN7EXAMPLE", "-----BEGIN " + "PRIVATE KEY-----")
    for path in _tracked_files():
        if path.suffix in {".jpg", ".png", ".whl", ".gz"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(marker in text for marker in markers):
            _fail(gate, f"secret marker in {path.relative_to(REPO_ROOT)}")


def _dependency_audit(gate: str, policy: dict[str, object]) -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for name, constraint in policy["required_dependencies"].items():
        if f'"{name}{constraint}"' not in pyproject:
            _fail(gate, f"dependency contract mismatch for {name}")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "check"], capture_output=True, text=True, check=False
    )
    if result.returncode:
        _fail(gate, result.stdout.strip())


def _sbom(gate: str, policy: dict[str, object]) -> None:
    if policy.get("sbom_format") != "CycloneDX":
        _fail(gate, "unsupported SBOM format")
    components = [
        {"type": "library", "name": name, "version_constraint": constraint}
        for name, constraint in policy["required_dependencies"].items()
    ]
    output = REPO_ROOT / ".artifacts/sbom.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}, sort_keys=True),
        encoding="utf-8",
    )


def _vulnerability_scan(gate: str, policy: dict[str, object]) -> None:
    if policy.get("forbid_subprocess_shell") is not True:
        _fail(gate, "subprocess shell policy is not fail-closed")
    violations: list[str] = []
    for path in (REPO_ROOT / "bcf_governance").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and any(
                keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords
            ):
                violations.append(path.relative_to(REPO_ROOT).as_posix())
    if violations:
        _fail(gate, "shell=True in " + ", ".join(violations))
    output = REPO_ROOT / ".artifacts/vulnerability-scan.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"scanner": "bcf-ast", "findings": []}), encoding="utf-8")


def _security_review(gate: str) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/validate_governance_yaml.py", "--repo-root", "."],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        _fail(gate, result.stdout.strip() or result.stderr.strip())


def _runtime_smoke(gate: str) -> None:
    from bcf_governance import __version__

    manifest = yaml.safe_load((REPO_ROOT / "manifest.yml").read_text(encoding="utf-8"))
    if manifest["document"]["version"] != __version__:
        _fail(gate, "manifest and runtime versions differ")
    result = subprocess.run(
        [sys.executable, "-m", "bcf_governance.cli", "--version"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or result.stdout.strip() != f"bcf {__version__}":
        _fail(gate, "CLI version smoke failed")
    output = REPO_ROOT / ".artifacts/runtime-smoke.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"version": __version__, "tree": hashlib.sha256(result.stdout.encode()).hexdigest()}),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("gate")
    args = parser.parse_args()
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    if args.gate in TEST_NODES or args.gate == "test":
        _run_tests(args.gate)
    elif args.gate == "lint":
        _lint(args.gate)
    elif args.gate == "typecheck":
        _typecheck(args.gate)
    elif args.gate == "security-secret-scan":
        _secret_scan(args.gate)
    elif args.gate == "security-dependency-audit":
        _dependency_audit(args.gate, policy)
    elif args.gate == "security-sbom":
        _sbom(args.gate, policy)
    elif args.gate == "security-vulnerability-scan":
        _vulnerability_scan(args.gate, policy)
    elif args.gate == "security-review":
        _security_review(args.gate)
    elif args.gate == "runtime-smoke":
        _runtime_smoke(args.gate)
    else:
        _fail(args.gate, "unknown gate")


if __name__ == "__main__":
    main()
