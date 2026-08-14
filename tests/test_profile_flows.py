from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.governance_evidence import attest_bundle, capture_gate
from scripts.governance_truth import derive_truth


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts/install_governance_pack.py"
PROFILE_CLI = REPO_ROOT / "scripts/profile_governance.py"
BUILTIN_GATES = {"governance-validate", "governance-exposure-scan"}
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
        if target in BUILTIN_GATES:
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
    evidence = repo / ".artifacts/bcf"
    contracts = yaml.safe_load(
        (repo / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    workflow = yaml.safe_load(
        (repo / ".github/workflows/governance.yml").read_text(encoding="utf-8")
    )
    matrix = workflow["jobs"]["evidence"]["strategy"]["matrix"]["gate"]
    assert workflow["env"]["BCF_PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert matrix == list(contracts["gates"])
    for target in contracts["gates"]:
        receipt_path = capture_gate(repo, target, evidence / target)
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
    assert report["effective_state"] == "closed"
    assert report["release_readiness"]["effective_state"] == "closed"
    assert report["status"] == "pass", report["issues"]
    if profile == "regulated":
        assert (repo / "governance/MODEL_RISK_AND_PROVENANCE.md").is_file()
        assert (repo / "governance/HOTFIX_LANE.md").is_file()
