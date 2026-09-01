from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.ci_graph_render import apply_ci_graph, check_ci_graph
from bcf_governance.tooling.evidence_sessions import (
    allocate_session,
    local_producer_identity,
)
from bcf_governance.tooling.governance_profiles import _v2_builtin_contracts
from scripts.governance_evidence import attest_bundle, capture_gate
from scripts.governance_truth import derive_truth


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts/install_governance_pack.py"
PROFILE_CLI = REPO_ROOT / "scripts/profile_governance.py"
DOCTOR = REPO_ROOT / "scripts/doctor_governance_pack.py"
BUILTIN_GATES = {"governance-validate", "governance-exposure-scan"}
EXPLICIT_HOSTED_RUNNERS = [
    "--candidate-runner-label",
    "ubuntu-24.04",
    "--trusted-runner-label",
    "ubuntu-24.04",
    "--candidate-runner-kind",
    "hosted",
    "--trusted-runner-kind",
    "hosted",
]
TEST_POLICIES = {
    "automated_tests",
    "contract_tests",
    "architecture_tests",
    "architecture_module_size",
    "architecture_layer_membership",
    "architecture_context_membership",
    "architecture_import_boundaries",
    "architecture_cqrs_side",
    "architecture_router_thinness",
    "architecture_duplication",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def gate_catalog() -> dict[str, dict[str, Any]]:
    profile = yaml.safe_load(
        (REPO_ROOT / "template-repo/governance-profile.yml").read_text(encoding="utf-8")
    )
    return profile["release_gate_profile"]["gates"]


def write_gate_runner(repo: Path) -> None:
    (repo / "gate.py").write_text(
        """from __future__ import annotations
import json
import pathlib
import sys

BROKEN = False
gate = sys.argv[1]
artifacts = pathlib.Path('.artifacts')
artifacts.mkdir(exist_ok=True)
if gate.startswith('architecture-') or gate in {'test', 'contract-test'}:
    junit = artifacts / 'junit' / f'{gate}.xml'
    junit.parent.mkdir(parents=True, exist_ok=True)
    failure = '<failure>mutated gate</failure>' if BROKEN else ''
    junit.write_text(f'<testsuite tests="1" failures="{int(BROKEN)}"><testcase classname="tests/gates.py" name="{gate}">{failure}</testcase></testsuite>')
for name in {
    'security-sbom': 'sbom.json',
    'security-vulnerability-scan': 'vulnerability-scan.json',
    'runtime-smoke': 'runtime-smoke.json',
}.items():
    if gate == name[0]:
        (artifacts / name[1]).write_text(json.dumps({'gate': gate, 'production': True}))
if BROKEN:
    print(f'mutated gate {gate}', file=sys.stderr)
    raise SystemExit(1)
print(f'gate passed: {gate}')
""",
        encoding="utf-8",
    )


def gate_config(repo: Path, profile: str, public_key: Path | None) -> Path:
    gates: dict[str, Any] = {}
    for gate in gate_catalog().values():
        target = gate["target"]
        policy = gate["command_policy"]
        if target in {*BUILTIN_GATES, "ci-certification"}:
            continue
        is_test = policy in TEST_POLICIES
        evidence: dict[str, Any] = {}
        if is_test:
            evidence = {
                "kind": "test_suite",
                "test_contract": {
                    "junit_xml": f".artifacts/junit/{target}.xml",
                    "min_collected": 1,
                    "min_executed": 1,
                    "max_skipped": 0,
                },
            }
        elif policy == "runtime_smoke":
            evidence = {
                "kind": "runtime_health",
                "environment_assertions": [
                    {"name": "BCF_EXECUTION_PROFILE", "operator": "equals", "value": "production"}
                ],
                "output_requirements": [
                    {"path": ".artifacts/runtime-smoke.json", "media_type": "application/json"}
                ],
            }
        elif policy == "security_review":
            evidence = {
                "kind": "security_review",
                "environment_assertions": [
                    {"name": "BCF_EXECUTION_PROFILE", "operator": "equals", "value": "production"}
                ],
                "output_requirements": [
                    {"path": "governance/findings.yml", "media_type": "application/yaml"}
                ],
            }
        elif policy == "security_sbom":
            evidence = {
                "output_requirements": [
                    {"path": ".artifacts/sbom.json", "media_type": "application/json"}
                ]
            }
        elif policy == "security_vulnerability_scan":
            evidence = {
                "output_requirements": [
                    {"path": ".artifacts/vulnerability-scan.json", "media_type": "application/json"}
                ]
            }
        oracle = (
            {
                "kind": "test_node_failure",
                "node_ids": [f"tests/gates.py::{target}"],
            }
            if is_test
            else {
                "kind": "diagnostic",
                "exit_codes": [1],
                "stream": "stderr",
                "regex": f"mutated gate {target}",
            }
        )
        gates[target] = {
            "invocation": {
                "argv": ["python3", "gate.py", target],
                "cwd": ".",
                "env": (
                    {"BCF_EXECUTION_PROFILE": "production"}
                    if policy in {"runtime_smoke", "security_review"}
                    else {}
                ),
                "required_env": [],
            },
            "evidence": evidence,
            "negative_controls": [
                {
                    "id": f"{target}-must-detect-mutation",
                    "mutation": {
                        "path": "gate.py",
                        "search": "BROKEN = False",
                        "replace": "BROKEN = True",
                    },
                    "oracle": oracle,
                }
            ],
        }
    provenance: dict[str, Any] = {}
    if profile == "regulated":
        assert public_key is not None
        provenance = {
            "trusted_verifier_keys": {
                "regulated-test-verifier": public_key.relative_to(repo).as_posix()
            },
            "permitted_risk_authorities": ["regulated-test-authority"],
        }
    path = repo / f"{profile}-profile.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "target_profile": profile,
                "gates": gates,
                "provenance": provenance,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def complete_phase(repo: Path) -> None:
    log_path = repo / "phases/phase-01-log.yml"
    log = yaml.safe_load(log_path.read_text(encoding="utf-8"))
    log["document"]["status"] = "completed"
    for item in log["workitems"]:
        item["status"] = "DONE"
    log_path.write_text(yaml.safe_dump(log, sort_keys=False), encoding="utf-8")
    workitems_path = repo / "plans/phase-01-workitems.yml"
    workitems = yaml.safe_load(workitems_path.read_text(encoding="utf-8"))
    workitems["document"]["status"] = "completed"
    for item in workitems["workitems"]:
        item["status"] = "DONE"
    workitems_path.write_text(yaml.safe_dump(workitems, sort_keys=False), encoding="utf-8")
    ledger_path = repo / "plans/phase-ledger.yml"
    ledger = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
    ledger["active_phase"]["lifecycle_status"] = "completed"
    ledger_path.write_text(yaml.safe_dump(ledger, sort_keys=False), encoding="utf-8")


def test_lite_profile_install_evidence_truth_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "lite"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "profile-flow@example.invalid")
    git(repo, "config", "user.name", "Profile Flow")
    subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--target",
            str(repo),
            "--profile",
            "lite",
            "--project-id",
            "lite-flow",
            "--project-name",
            "Lite Flow",
            "--product-name",
            "Lite Flow",
            *EXPLICIT_HOSTED_RUNNERS,
            "--require-strict-validation",
        ],
        check=True,
    )
    complete_phase(repo)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "complete lite governed phase")
    monkeypatch.setenv(
        "PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]
    )
    evidence = repo / ".artifacts/bcf"
    for target in sorted(BUILTIN_GATES):
        receipt = json.loads(
            capture_gate(repo, target, evidence / target).read_text(encoding="utf-8")
        )
        assert receipt["result"] == "passed"
    report = derive_truth(repo, evidence)
    assert report["status"] == "pass", report["issues"]
    assert report["effective_state"] == "closed"
    assert report["claims"]["required_suites_green"]["applicability"] == "not_applicable"


def test_profile_promotion_is_checkable_monotonic_and_preserves_phase_artifacts(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "promotion"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "profile-flow@example.invalid")
    git(repo, "config", "user.name", "Profile Flow")
    subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--target",
            str(repo),
            "--profile",
            "lite",
            "--project-id",
            "promotion-flow",
            "--project-name",
            "Promotion Flow",
            "--product-name",
            "Promotion Flow",
            *EXPLICIT_HOSTED_RUNNERS,
            "--require-strict-validation",
        ],
        check=True,
    )
    write_gate_runner(repo)
    config = gate_config(repo, "standard", None)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "configure standard promotion")
    phase_paths = [
        repo / "plans/phase-01-plan.yml",
        repo / "plans/phase-01-workitems.yml",
        repo / "phases/phase-01-log.yml",
    ]
    before = {path: path.read_bytes() for path in phase_paths}
    workflow_before = (repo / ".github/workflows/governance.yml").read_bytes()
    subprocess.run(
        [
            sys.executable,
            str(PROFILE_CLI),
            "--repo-root",
            str(repo),
            "--to",
            "standard",
            "--config",
            str(config),
            "--check",
        ],
        check=True,
    )
    profile = yaml.safe_load((repo / "governance-profile.yml").read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "lite"
    subprocess.run(
        [
            sys.executable,
            str(PROFILE_CLI),
            "--repo-root",
            str(repo),
            "--to",
            "standard",
            "--config",
            str(config),
            "--apply",
        ],
        check=True,
    )
    profile = yaml.safe_load((repo / "governance-profile.yml").read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "standard"
    assert {path: path.read_bytes() for path in phase_paths} == before
    assert (repo / ".github/workflows/governance.yml").read_bytes() == workflow_before
    repeated = subprocess.run(
        [
            sys.executable,
            str(PROFILE_CLI),
            "--repo-root",
            str(repo),
            "--to",
            "standard",
            "--config",
            str(config),
            "--apply",
        ],
        capture_output=True,
        text=True,
    )
    assert repeated.returncode != 0
    assert "must advance beyond standard" in repeated.stderr


def test_standard_v1_to_v2_promotion_is_explicit_and_preserves_workflow(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "contract-promotion"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "profile-flow@example.invalid")
    git(repo, "config", "user.name", "Profile Flow")
    write_gate_runner(repo)
    config = gate_config(repo, "standard", None)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "application gate contracts")
    subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--target",
            str(repo),
            "--profile",
            "standard",
            "--profile-contract-version",
            "1.0",
            "--profile-config",
            str(config),
            "--project-id",
            "contract-promotion",
            "--project-name",
            "Contract Promotion",
            "--product-name",
            "Contract Promotion",
            "--require-strict-validation",
        ],
        check=True,
    )
    installed_contracts_path = repo / "governance/gate-contracts.yml"
    installed_contracts = yaml.safe_load(installed_contracts_path.read_text(encoding="utf-8"))
    installed_contracts["gates"]["architecture-test"]["evidence"]["test_contract"][
        "selectors"
    ] = ["tests/test_architecture.py"]
    custom_semantic = _v2_builtin_contracts()["semantic-ownership"]
    custom_semantic["negative_controls"][0]["id"] = "consumer-semantic-owner-must-fail"
    installed_contracts["gates"]["semantic-ownership"] = custom_semantic
    installed_contracts_path.write_text(
        yaml.safe_dump(installed_contracts, sort_keys=False, width=120),
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "install standard v1")
    workflow_before = (repo / ".github/workflows/governance.yml").read_bytes()
    command = [
        sys.executable,
        str(PROFILE_CLI),
        "--repo-root",
        str(repo),
        "--to",
        "standard",
        "--contract-version",
        "2.0",
    ]

    subprocess.run([*command, "--check"], check=True)
    subprocess.run([*command, "--apply"], check=True)

    profile = yaml.safe_load((repo / "governance-profile.yml").read_text(encoding="utf-8"))
    assert profile["profile"]["selected"] == "standard"
    assert profile["profile_contract_version"] == "2.0"
    assert profile["release_gate_profile"]["gates"]["semantic_ownership"]["status"] == "required"
    assert (repo / ".github/workflows/governance.yml").read_bytes() == workflow_before
    contracts = yaml.safe_load(
        (repo / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    assert contracts["gates"]["semantic-ownership"]["invocation"]["argv"][1] == (
        "scripts/semantic_ownership.py"
    )
    assert contracts["gates"]["semantic-ownership"]["negative_controls"][0]["id"] == (
        "consumer-semantic-owner-must-fail"
    )
    assert contracts["gates"]["architecture-test"]["evidence"]["test_contract"][
        "selectors"
    ] == ["tests/test_architecture.py"]
    evidence_policy = yaml.safe_load(
        (repo / "governance/evidence-policy.yml").read_text(encoding="utf-8")
    )
    assert evidence_policy["gate_overrides"] == {}
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "promote to standard v2")
    session = allocate_session(
        repo,
        repo / ".artifacts/bcf",
        contracts["gates"],
        expected_producers=["local"],
        producer_identity=local_producer_identity(repo),
    )
    receipt = json.loads(
        capture_gate(
            repo,
            "semantic-ownership",
            session.root / "semantic-ownership",
            python_executable=sys.executable,
            session_manifest=session.manifest_path,
        ).read_text(encoding="utf-8")
    )
    assert receipt["result"] == "passed"
    assert receipt["behavioral_probes"][0]["oracle_observation"]["satisfied"] is True


@pytest.mark.parametrize("profile", ["standard", "regulated"])
def test_full_profile_install_evidence_truth_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str
) -> None:
    repo = tmp_path / profile
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "profile-flow@example.invalid")
    git(repo, "config", "user.name", "Profile Flow")
    write_gate_runner(repo)
    private_key: Path | None = None
    public_key: Path | None = None
    if profile == "regulated":
        private_key = tmp_path / "regulated-private.pem"
        public_key = repo / "governance/trusted-verifier.pem"
        public_key.parent.mkdir(parents=True)
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            check=True,
            capture_output=True,
        )
    config = gate_config(repo, profile, public_key)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "application gate contracts")
    subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--target",
            str(repo),
            "--profile",
            profile,
            "--profile-config",
            str(config),
            "--project-id",
            "profile-flow",
            "--project-name",
            "Profile Flow",
            "--product-name",
            "Profile Flow",
            *EXPLICIT_HOSTED_RUNNERS,
            "--require-strict-validation",
        ],
        check=True,
    )
    complete_phase(repo)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "complete governed phase")
    monkeypatch.setenv(
        "PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]
    )
    doctor = subprocess.run(
        [
            sys.executable,
            str(DOCTOR),
            "--repo-root",
            str(repo),
            "--format",
            "json",
            "--compact",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    doctor_report = json.loads(doctor.stdout)
    assert doctor_report["status"] == "warn"
    assert doctor_report["profile_v2"]["status"] == "ready"
    assert any("CI authority" in value for value in doctor_report["warnings"])
    evidence = repo / ".artifacts/bcf"
    contracts = yaml.safe_load(
        (repo / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    workflow = yaml.safe_load(
        (repo / ".github/workflows/governance.yml").read_text(encoding="utf-8")
    )
    compiled = validate_ci_graph(repo)
    governance_workflow = next(
        item for item in compiled.workflows if item["path"] == ".github/workflows/governance.yml"
    )
    evidence_policy = yaml.safe_load(
        (repo / "governance/evidence-policy.yml").read_text(encoding="utf-8")
    )
    assert evidence_policy["workflow_contract"] == {
        "paths": [governance_workflow["path"]],
        "required_events": [event["type"] for event in governance_workflow["events"]],
    }
    governed_gates = [
        gate
        for job in governance_workflow["jobs"]
        if job["executor"]["kind"] == "gate_group"
        for gate in job["executor"]["gates"]
    ]
    assert workflow["env"]["BCF_ENFORCE_PR_CHANGELOG"] == (
        "${{ github.event_name == 'pull_request' }}"
    )
    assert workflow["env"]["BCF_PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert len(governed_gates) == len(set(governed_gates))
    assert set(governed_gates) == set(contracts["gates"])
    session = allocate_session(
        repo,
        evidence,
        contracts["gates"],
        expected_producers=["local"],
        producer_identity=local_producer_identity(repo),
    )
    for target in contracts["gates"]:
        receipt_path = capture_gate(
            repo,
            target,
            session.root / target,
            session_manifest=session.manifest_path,
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        assert receipt["schema_version"] == "2.0"
        assert receipt["result"] == "passed", (target, receipt)
    if profile == "regulated":
        assert private_key is not None
        attest_bundle(
            repo,
            evidence,
            private_key,
            "regulated-test-verifier",
            "independent-verifier",
            evidence / "regulated.attestation.json",
            actor_kind="human",
        )
    report = derive_truth(repo, evidence)
    assert report["status"] == "pass", report["issues"]
    assert report["effective_state"] == "closed"
    assert report["release_readiness"]["effective_state"] == "closed"
    if profile == "regulated":
        assert (repo / "governance/MODEL_RISK_AND_PROVENANCE.md").is_file()
        assert (repo / "governance/HOTFIX_LANE.md").is_file()


def test_clean_standard_v2_fixture_installs_extends_regenerates_and_rolls_back(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "clean-standard-graph"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "graph-fixture@example.invalid")
    git(repo, "config", "user.name", "Graph Fixture")
    write_gate_runner(repo)
    config = gate_config(repo, "standard", None)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "fixture gate contracts")
    subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--target",
            str(repo),
            "--profile",
            "standard",
            "--profile-config",
            str(config),
            "--project-id",
            "clean-graph-fixture",
            "--project-name",
            "Clean Graph Fixture",
            "--product-name",
            "Clean Graph Fixture",
            *EXPLICIT_HOSTED_RUNNERS,
            "--require-strict-validation",
        ],
        check=True,
    )
    unrelated = repo / ".github/workflows/application.yml"
    unrelated.write_text("name: application\non: workflow_dispatch\njobs: {}\n", encoding="utf-8")
    unrelated_bytes = unrelated.read_bytes()
    fixture_root = REPO_ROOT / "tests/fixtures/consumer_ci_graph"
    extension_path = repo / "governance/ci-extensions/fixture.yml"
    extension_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(fixture_root / "fixture-extension.yml", extension_path)
    script_path = repo / ".github/scripts/fixture_extension.py"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(fixture_root / "fixture_extension.py", script_path)
    graph_path = repo / "governance/ci-graph.yml"
    graph = yaml.safe_load(graph_path.read_text(encoding="utf-8"))
    graph["extensions"] = [
        {
            "id": "fixture-consumer",
            "path": "governance/ci-extensions/fixture.yml",
            "sha256": hashlib.sha256(extension_path.read_bytes()).hexdigest(),
        }
    ]
    graph_path.write_text(yaml.safe_dump(graph, sort_keys=False), encoding="utf-8")

    apply_ci_graph(repo)
    compiled = validate_ci_graph(repo)
    governance = next(item for item in compiled.workflows if item["id"] == "governance")
    assert [job["id"] for job in governance["jobs"]].count("fixture-extension") == 1
    assert check_ci_graph(repo).status == "clean"
    assert unrelated.read_bytes() == unrelated_bytes
    output = repo / ".artifacts/bcf/fixture-extension.json"
    subprocess.run([sys.executable, str(script_path), "--output", str(output)], check=True)
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "pass"

    extension_path.unlink()
    graph["extensions"] = []
    graph_path.write_text(yaml.safe_dump(graph, sort_keys=False), encoding="utf-8")
    apply_ci_graph(repo)
    assert check_ci_graph(repo).status == "clean"
    assert unrelated.read_bytes() == unrelated_bytes
