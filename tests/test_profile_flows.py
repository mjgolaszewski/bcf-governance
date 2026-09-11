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
from bcf_governance.tooling.ci_graph_audit import audit_ci_graph
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
from dataclasses import dataclass
import json
import pathlib
import sys

BROKEN = False

@dataclass(frozen=True)
class GateResult:
    gate: str
    passed: bool

def build_gate_result(gate: str) -> GateResult:
    return GateResult(gate=gate, passed=not BROKEN)

def main() -> None:
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

PUBLIC_OPERATIONS = {'gate': main}

if __name__ == '__main__':
    main()
""",
        encoding="utf-8",
    )
    (repo / "gate-contract-source.json").write_text(
        '{"kind":"gate-result","version":1}\n', encoding="utf-8"
    )
    generator = repo / "generate_gate_contract.py"
    generator.write_text(
        """from __future__ import annotations
import json
from pathlib import Path

def main() -> None:
    source = json.loads(Path('gate-contract-source.json').read_text(encoding='utf-8'))
    Path('gate-contract.json').write_text(json.dumps(source, sort_keys=True, separators=(',', ':')) + '\\n', encoding='utf-8')

if __name__ == '__main__':
    main()
""",
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(generator)], cwd=repo, check=True)


def semantic_config(repo: Path) -> Path:
    """Write an explicit, complete semantic adoption decision for the fixture."""
    semantic_id = "fixture.gate-result.v1"
    family_id = "gate_result"
    source = "gate.py"
    canonical_symbol = "gate.py::GateResult"
    owner = "gate.py::build_gate_result"
    contract = {
        "semantic_families": {
            "schema_version": "1.0",
            "document": {
                "kind": "semantic_family_registry",
                "id": "fixture-semantic-families",
                "version": "1.0.0",
                "status": "active",
                "path": "governance/semantic-families.yml",
            },
            "families": [{
                "id": family_id,
                "significance": "authoritative",
                "ownership_required": True,
                "canonical_semantic_ids": [semantic_id],
                "material_selectors": {
                    "source_paths": [source],
                    "symbols": [canonical_symbol],
                    "secondary_paths": ["gate-contract.json"],
                },
                "responsibilities": {
                    "construction": ["build_gate_result"],
                    "decoding": [],
                    "transition": [],
                    "projection": [],
                },
            }],
            "migrations": [],
        },
        "application_operations": {
            "schema_version": "1.0",
            "document": {
                "kind": "application_operation_registry",
                "id": "fixture-application-operations",
                "version": "1.0.0",
                "status": "active",
                "path": "governance/application-operations.yml",
            },
            "populations": [{
                "id": "fixture_cli",
                "adapter": "python_mapping",
                "source": source,
                "symbol": "PUBLIC_OPERATIONS",
                "public_only": True,
            }],
            "operations": [{
                "id": "fixture.operation.gate.v1",
                "population": "fixture_cli",
                "population_key": "gate",
                "family": family_id,
                "bounded_context": "fixture",
                "entrypoints": ["gate.py::main"],
                "semantic_kind": "command",
                "authoritative_read": True,
                "authoritative_mutation": True,
                "authority_conferral": False,
                "produces_projection": False,
                "model_callable": False,
                "allowed_mutation_ports": [
                    "gate.py::artifacts.mkdir",
                    "gate.py::junit.parent.mkdir",
                    "gate.py::junit.write_text",
                    "gate.py::(artifacts / name[1]).write_text",
                ],
                "allowed_authority_ports": [],
                "non_authoritative_output_effects": [],
            }],
            "migrations": [],
        },
        "canonical_representations": {
            "document": {
                "kind": "canonical_representation_registry",
                "id": "fixture-canonical-representations",
                "version": "1.0.0",
                "status": "active",
                "path": "governance/canonical-representations.yml",
            },
            "enforcement": {
                "phase": "P01",
                "default_mode": "declared_families_blocking",
                "declared_families": [family_id],
                "blocking_semantic_ids": [semantic_id],
                "report_path": ".artifacts/semantic-ownership/report.json",
                "unresolved_dynamic_policy": "fail_closed",
            },
            "source_authority": {
                "discovery_precedes_registry_load": True,
                "python_engine": "scripts/_bcf_runtime/semantic_ownership_inventory.py",
                "typescript_engine": "not_applicable_until_declared_by_consumer",
                "cross_language_trace": "not_applicable_until_declared_by_consumer",
                "completeness_authority": "independent_exact_tree_source_inventory",
                "authoritative_python_roots": [source],
                "generated_mirror_roots": [],
            },
            "representations": [{
                "semantic_id": semantic_id,
                "family": family_id,
                "schema_version": 1,
                "lifecycle": "enforced",
                "finding_ids": [],
                "canonical_type": {"language": "python", "symbol": canonical_symbol},
                "authoritative_owner": {"symbol": owner, "owner_kind": "constructor"},
                "authorized_constructors_and_factories": [owner],
                "authorized_pure_delegates": [],
                "hostile_boundary_decoder": {
                    "symbol": owner,
                    "trust_boundary": "fixture input",
                },
                "field_invariants": [{"field": "passed", "invariant": "reflects gate outcome"}],
                "permitted_defaults_and_single_application_point": [],
                "accepted_aliases_and_single_ingress_boundary": [],
                "persistence_codec_and_envelope": {
                    "applicability": "not_applicable",
                    "codec_symbol": owner,
                    "semantic_id": semantic_id,
                    "schema_version": 1,
                    "exact_byte_format": "frozen in-memory value",
                    "integrity_algorithm": "source inventory",
                    "identity_bindings": ["gate", "passed"],
                    "migration_dispatch": "none",
                },
                "protocol_translations": [],
                "intentional_projections": [],
                "declared_consumer_layers_and_sinks": {
                    "read": [],
                    "authorization": ["gate.py::main"],
                    "persistence": [],
                    "cache": [],
                    "queue": [],
                    "network": [],
                    "api": [],
                    "browser": [],
                },
                "generated_source_authority": {
                    "authoritative_roots": [],
                    "generated_mirrors": [],
                    "generator": "not_applicable",
                    "parity_proof": "not_applicable",
                },
                "migration_policy": {
                    "source_versions": [],
                    "destination_version": 1,
                    "owner": owner,
                    "runtime_exclusion": "none",
                    "removal_condition": "reviewed successor",
                },
                "narrow_suppressions": [],
            }],
            "secondary_representations": [{
                "id": "fixture.gate-contract-projection.v1",
                "classification": "derived",
                "canonical_semantic_id": semantic_id,
                "derivation_kind": "exact_generated_projection",
                "source_inputs": ["gate-contract-source.json"],
                "outputs": ["gate-contract.json"],
                "recipe": {
                    "kind": "tracked_command",
                    "argv": ["python3", "generate_gate_contract.py"],
                },
                "migration_owner": "fixture-maintainer",
                "direct_edit_policy": "prohibited",
            }],
        },
    }
    path = repo / "semantic-config.yml"
    path.write_text(
        yaml.safe_dump({"contracts": contract}, sort_keys=False, width=120),
        encoding="utf-8",
    )
    return path


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
    semantic = semantic_config(repo)
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
        "--semantic-config",
        str(semantic),
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


def test_fresh_standard_v2_missing_semantic_config_fails_before_mutation(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "missing-semantic-config"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "profile-flow@example.invalid")
    git(repo, "config", "user.name", "Profile Flow")
    write_gate_runner(repo)
    config = gate_config(repo, "standard", None)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "application gate contracts")
    before = git(repo, "status", "--porcelain=v1", "--untracked-files=all")

    result = subprocess.run(
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
            "missing-semantic-config",
            "--project-name",
            "Missing Semantic Config",
            *EXPLICIT_HOSTED_RUNNERS,
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "--semantic-config is required" in result.stderr
    assert git(repo, "status", "--porcelain=v1", "--untracked-files=all") == before


def test_incomplete_semantic_config_reports_independent_blockers_before_mutation(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "incomplete-semantic-config"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "profile-flow@example.invalid")
    git(repo, "config", "user.name", "Profile Flow")
    write_gate_runner(repo)
    config = gate_config(repo, "standard", None)
    semantic = semantic_config(repo)
    payload = yaml.safe_load(semantic.read_text(encoding="utf-8"))
    payload["contracts"]["semantic_families"]["families"][0][
        "canonical_semantic_ids"
    ] = []
    semantic.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    gate_source = repo / "gate.py"
    gate_source.write_text(
        gate_source.read_text(encoding="utf-8").replace(
            "PUBLIC_OPERATIONS = {'gate': main}",
            "PUBLIC_OPERATIONS = {'gate': main, 'unclassified': main}",
        ),
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "application gate contracts")
    before = git(repo, "status", "--porcelain=v1", "--untracked-files=all")

    result = subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--target",
            str(repo),
            "--profile",
            "standard",
            "--profile-config",
            str(config),
            "--semantic-config",
            str(semantic),
            "--project-id",
            "incomplete-semantic-config",
            "--project-name",
            "Incomplete Semantic Config",
            *EXPLICIT_HOSTED_RUNNERS,
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "semantic adoption has 2 blocker(s)" in result.stderr
    assert "[semantic_family_completeness]" in result.stderr
    assert "should be non-empty" in result.stderr
    assert "[application_operation_inventory]" in result.stderr
    assert "unclassified public application operations" in result.stderr
    assert git(repo, "status", "--porcelain=v1", "--untracked-files=all") == before


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
    semantic = semantic_config(repo)
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
            "--semantic-config",
            str(semantic),
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


@pytest.mark.parametrize("cycle", range(1, 6))
def test_clean_standard_v2_fixture_installs_upgrades_customizes_and_rolls_back(
    tmp_path: Path, cycle: int,
) -> None:
    repo = tmp_path / f"clean-standard-graph-{cycle}"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "graph-fixture@example.invalid")
    git(repo, "config", "user.name", "Graph Fixture")
    write_gate_runner(repo)
    config = gate_config(repo, "standard", None)
    semantic = semantic_config(repo)
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
            "--semantic-config",
            str(semantic),
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
    unrelated.write_text(
        "name: application\non: workflow_dispatch\n"
        "jobs:\n  application:\n    runs-on: ubuntu-24.04\n"
        "    steps:\n    - run: 'true'\n",
        encoding="utf-8",
    )
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
    audit = audit_ci_graph(repo)
    assert audit["status"] == "pass"
    assert audit["inventory"]["required_status_checks"] == []
    assert audit["inventory"]["dependabot_update_rules"] == []
    assert audit["inventory"]["unmanaged_workflow_paths"] == [
        ".github/workflows/application.yml"
    ]
    assert unrelated.read_bytes() == unrelated_bytes
    project_owned = {
        path: (repo / path).read_bytes()
        for path in (
            "governance-profile.yml",
            "governance/gate-contracts.yml",
            "governance/ci-graph.yml",
            "governance/ci-extensions/fixture.yml",
            "governance/semantic-families.yml",
            "governance/application-operations.yml",
            "governance/canonical-representations.yml",
            "governance/semantic-lock.yml",
            ".github/workflows/application.yml",
        )
    }
    subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--target",
            str(repo),
            "--upgrade",
            "--skip-validation",
        ],
        check=True,
    )
    assert {
        path: (repo / path).read_bytes() for path in project_owned
    } == project_owned
    assert check_ci_graph(repo).status == "clean"
    output = repo / ".artifacts/bcf/fixture-extension.json"
    subprocess.run([sys.executable, str(script_path), "--output", str(output)], check=True)
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "pass"

    extension_path.unlink()
    graph["extensions"] = []
    graph_path.write_text(yaml.safe_dump(graph, sort_keys=False), encoding="utf-8")
    apply_ci_graph(repo)
    assert check_ci_graph(repo).status == "clean"
    assert unrelated.read_bytes() == unrelated_bytes
