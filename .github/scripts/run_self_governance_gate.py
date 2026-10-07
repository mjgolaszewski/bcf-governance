"""Execute repository-specific BCF standard gates without a shell."""

from __future__ import annotations

import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import hashlib
from importlib import metadata
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from bcf_governance.tooling.dependency_assurance import (  # noqa: E402
    DependencyAssuranceError,
    audit_envelope,
    collect_installed_inventory,
    cyclonedx_sbom,
    write_frozen_requirements,
)
from bcf_governance.tooling.evidence_scheduling import (  # noqa: E402
    compile_test_splinter_plan,
    validate_test_splinter_results,
)
from bcf_governance.tooling.runtime_capacity import (  # noqa: E402
    allocate_child_execution_state,
    retire_execution_state,
)
from bcf_governance.tooling.test_manifests import collect_selector_map  # noqa: E402
POLICY_PATH = REPO_ROOT / "governance/self-governance-policy.yml"
GATE_CONTRACTS_PATH = REPO_ROOT / "governance/gate-contracts.yml"


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


def _junit_nodes(path: Path) -> list[str]:
    nodes: list[str] = []
    for case in ET.parse(path).getroot().iter("testcase"):
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "")
        nodes.append(f"{classname}::{name}" if classname else name)
    return sorted(nodes)


def _merge_junit(paths: list[Path], output: Path) -> None:
    root = ET.Element("testsuites")
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    elapsed = 0.0
    for path in paths:
        parsed = ET.parse(path).getroot()
        suites = [parsed] if parsed.tag == "testsuite" else list(parsed.findall("testsuite"))
        for suite in suites:
            root.append(suite)
            for name in totals:
                totals[name] += int(suite.attrib.get(name, "0"))
            elapsed += float(suite.attrib.get("time", "0"))
    root.attrib.update({name: str(value) for name, value in totals.items()})
    root.attrib["time"] = f"{elapsed:.6f}"
    output.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)


def _run_test_splinters(
    gate: str, test_contract: dict[str, object], junit: Path
) -> int:
    raw = test_contract.get("splinter")
    if not isinstance(raw, dict):
        return -1
    if set(raw) != {"algorithm", "max_splinters", "minimum_cpus", "report"}:
        _fail(gate, "test splinter contract fields are invalid")
    if raw.get("algorithm") != "stable_lpt_v1":
        _fail(gate, "test splinter algorithm is unsupported")
    max_splinters = raw.get("max_splinters")
    minimum_cpus = raw.get("minimum_cpus")
    report_value = raw.get("report")
    if (
        isinstance(max_splinters, bool)
        or not isinstance(max_splinters, int)
        or max_splinters < 1
        or isinstance(minimum_cpus, bool)
        or not isinstance(minimum_cpus, int)
        or minimum_cpus < 1
        or not isinstance(report_value, str)
        or not report_value
    ):
        _fail(gate, "test splinter contract values are invalid")
    report = REPO_ROOT / report_value
    try:
        report.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        _fail(gate, "test splinter report escapes the repository")
    selector_map = collect_selector_map(REPO_ROOT, gate, python_executable=sys.executable)
    nodes = dict(selector_map.entries)
    cpu_count = os.cpu_count() or 1
    resources_compatible = cpu_count >= minimum_cpus
    identity = {
        "subject_commit": subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], text=True
        ).strip(),
        "subject_tree": subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD^{tree}"], text=True
        ).strip(),
        "session": os.environ.get("BCF_EXECUTION_STATE_NAMESPACE", "direct-gate"),
        "policy_sha256": hashlib.sha256(GATE_CONTRACTS_PATH.read_bytes()).hexdigest(),
        "producer": gate,
    }
    plan = compile_test_splinter_plan(
        nodes,
        {},
        max_splinters=min(max_splinters, cpu_count),
        identity=identity,
        resources_compatible=resources_compatible,
    )
    leases = {}
    worktrees: dict[str, Path] = {}
    temporary = tempfile.TemporaryDirectory(prefix="bcf-test-splinters-")
    try:
        for splinter in plan["splinters"]:
            splinter_id = str(splinter["id"])
            lease = allocate_child_execution_state(
                os.environ, execution_id=f"test:{splinter_id}"
            )
            leases[splinter_id] = lease
            worktree = Path(temporary.name) / splinter_id
            added = subprocess.run(
                [
                    "git", "-C", str(REPO_ROOT), "worktree", "add", "--quiet",
                    "--detach", str(worktree), "HEAD",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if added.returncode:
                _fail(gate, added.stderr.strip() or "splinter worktree allocation failed")
            worktrees[splinter_id] = worktree
        def execute(splinter: dict[str, object]) -> dict[str, object]:
            splinter_id = str(splinter["id"])
            splinter_junit = junit.with_name(f"{junit.stem}.{splinter_id}.xml")
            worktree = worktrees[splinter_id]
            base_temp = Path(temporary.name) / f"pytest-{splinter_id}"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(worktree)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            lease = leases[splinter_id]
            if lease is not None:
                environment.update(lease.environment())
            started = time.monotonic_ns()
            bootstrap = subprocess.run(
                [
                    sys.executable,
                    str(worktree / ".github/scripts/bootstrap_test_toolchain.py"),
                    "--repo-root",
                    str(worktree),
                ],
                cwd=worktree,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            if bootstrap.returncode:
                return {
                    "id": splinter_id,
                    "returncode": bootstrap.returncode,
                    "duration_ms": max(1, (time.monotonic_ns() - started) // 1_000_000),
                    "stdout": bootstrap.stdout,
                    "stderr": bootstrap.stderr,
                    "junit": splinter_junit,
                }
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    *[str(value) for value in splinter["selectors"]],
                    f"--basetemp={base_temp}",
                    f"--junitxml={splinter_junit}",
                ],
                cwd=worktree,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            return {
                "id": splinter_id,
                "returncode": result.returncode,
                "duration_ms": max(1, (time.monotonic_ns() - started) // 1_000_000),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "junit": splinter_junit,
            }
        with ThreadPoolExecutor(max_workers=len(plan["splinters"])) as executor:
            results = list(executor.map(execute, plan["splinters"]))
    finally:
        cleanup = {
            splinter_id: retire_execution_state(lease) if lease is not None else None
            for splinter_id, lease in reversed(list(leases.items()))
        }
        worktree_cleanup = {}
        for splinter_id, worktree in reversed(list(worktrees.items())):
            removed = subprocess.run(
                [
                    "git", "-C", str(REPO_ROOT), "worktree", "remove", "--force",
                    str(worktree),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            worktree_cleanup[splinter_id] = (
                removed.returncode == 0 and not worktree.exists()
            )
        temporary.cleanup()
    results.sort(key=lambda item: str(item["id"]))
    for result in results:
        sys.stdout.write(str(result["stdout"]))
        sys.stderr.write(str(result["stderr"]))
    junit_paths = [Path(str(result["junit"])) for result in results]
    if any(not path.is_file() for path in junit_paths):
        _fail(gate, "test splinter did not emit its declared JUnit result")
    observed = {
        str(result["id"]): _junit_nodes(Path(str(result["junit"]))) for result in results
    }
    try:
        validate_test_splinter_results(plan, observed)
    except ValueError as exc:
        _fail(gate, str(exc))
    _merge_junit(junit_paths, junit)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(
            {
                **plan,
                "resources": {"observed_cpus": cpu_count, "minimum_cpus": minimum_cpus},
                "results": [
                    {
                        "id": result["id"],
                        "returncode": result["returncode"],
                        "duration_ms": result["duration_ms"],
                        "execution_state": cleanup[result["id"]],
                        "worktree_removed": worktree_cleanup[result["id"]],
                    }
                    for result in results
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return 1 if any(result["returncode"] != 0 for result in results) else 0


def _run_tests(gate: str) -> None:
    junit = REPO_ROOT / f".artifacts/junit/{gate}.xml"
    junit.parent.mkdir(parents=True, exist_ok=True)
    registry = yaml.safe_load(GATE_CONTRACTS_PATH.read_text(encoding="utf-8"))
    gate_contract = registry.get("gates", {}).get(gate, {})
    test_contract = gate_contract.get("evidence", {}).get("test_contract", {})
    selectors = test_contract.get("selectors")
    if not isinstance(selectors, list) or not selectors:
        _fail(gate, "governed test selectors are missing")
    splintered = _run_test_splinters(gate, test_contract, junit)
    if splintered >= 0:
        raise SystemExit(splintered)
    nodes: list[str] = []
    for selector in selectors:
        if selector == "@test_roots":
            agents = yaml.safe_load((REPO_ROOT / "AGENTS.yml").read_text(encoding="utf-8"))
            nodes.extend(agents["testing_governance"]["test_roots"])
        elif isinstance(selector, str):
            nodes.append(selector)
        else:
            _fail(gate, "governed test selector is invalid")
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
    contract = policy.get("dependency_advisory_audit")
    if not isinstance(contract, dict):
        _fail(gate, "dependency advisory audit contract is missing")
    scanner = contract.get("scanner")
    expected_version = contract.get("version")
    service = contract.get("service")
    if scanner != "pip-audit" or not isinstance(expected_version, str) or service != "pypi":
        _fail(gate, "dependency advisory audit contract is invalid")
    try:
        observed_version = metadata.version("pip-audit")
        inventory = collect_installed_inventory(REPO_ROOT)
    except (metadata.PackageNotFoundError, DependencyAssuranceError) as exc:
        _fail(gate, str(exc))
    if observed_version != expected_version:
        _fail(gate, f"pip-audit version must be {expected_version}, got {observed_version}")
    artifact_root = REPO_ROOT / ".artifacts"
    frozen = artifact_root / "dependency-audit-input.txt"
    raw_path = artifact_root / "dependency-audit-raw.json"
    output = artifact_root / "dependency-audit.json"
    write_frozen_requirements(inventory, frozen)
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--requirement",
        str(frozen),
        "--no-deps",
        "--disable-pip",
        "--strict",
        "--vulnerability-service",
        service,
        "--format",
        "json",
        "--output",
        str(raw_path),
        "--progress-spinner",
        "off",
    ]
    try:
        audited = subprocess.run(
            command, cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=120
        )
    except subprocess.TimeoutExpired as exc:
        audited = subprocess.CompletedProcess(command, 2, "", f"scanner timeout: {exc}")
    raw: dict[str, object] | None = None
    try:
        loaded = json.loads(raw_path.read_text(encoding="utf-8"))
        raw = loaded if isinstance(loaded, dict) else None
    except (OSError, UnicodeError, json.JSONDecodeError):
        pass
    envelope = audit_envelope(
        inventory=inventory,
        scanner_version=observed_version,
        service=service,
        returncode=audited.returncode,
        raw=raw,
        diagnostic=(audited.stderr.strip() or audited.stdout.strip()),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if envelope["status"] != "clean":
        _fail(gate, f"dependency advisory status is {envelope['status']}")


def _sbom(gate: str, policy: dict[str, object]) -> None:
    if policy.get("sbom_format") != "CycloneDX":
        _fail(gate, "unsupported SBOM format")
    try:
        inventory = collect_installed_inventory(REPO_ROOT)
    except DependencyAssuranceError as exc:
        _fail(gate, str(exc))
    output = REPO_ROOT / ".artifacts/sbom.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(cyclonedx_sbom(inventory), indent=2, sort_keys=True) + "\n",
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


def _semantic_ownership(gate: str) -> None:
    report_path = REPO_ROOT / ".artifacts/semantic-ownership/report.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bcf_governance.tooling.semantic_ownership_scan",
            "--repo-root",
            ".",
            "--output",
            report_path.relative_to(REPO_ROOT).as_posix(),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        diagnostic = ""
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            violation = report.get("violations", [{}])[0]
            diagnostic = str(violation.get("diagnostic") or violation.get("kind") or "")
        except (OSError, UnicodeError, json.JSONDecodeError, IndexError, AttributeError):
            pass
        _fail(gate, diagnostic or result.stdout.strip() or result.stderr.strip())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("gate")
    args = parser.parse_args()
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    registry = yaml.safe_load(GATE_CONTRACTS_PATH.read_text(encoding="utf-8"))
    gate_contract = registry.get("gates", {}).get(args.gate, {})
    if isinstance(gate_contract.get("evidence", {}).get("test_contract"), dict):
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
    elif args.gate == "semantic-ownership":
        _semantic_ownership(args.gate)
    else:
        _fail(args.gate, "unknown gate")


if __name__ == "__main__":
    main()
