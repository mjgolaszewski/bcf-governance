from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from bcf_governance.tooling.evidence_planning import (
    build_dependency_manifest,
    load_claim_model,
    plan_verification,
    parse_claim_model,
    qualification_applicability,
    receipt_producing_legacy_gates,
    receipt_applicability,
    load_prior_receipts,
)
from bcf_governance.tooling.evidence_execution import EvidenceError
from bcf_governance.tooling.ci_github_bundle import canonical_json
from bcf_governance.tooling.evidence_claims import qualification_equivalence


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_preflight_claims_are_not_receipt_producing_workitem_evidence() -> None:
    model = load_claim_model(REPO_ROOT)
    receipt_gates = receipt_producing_legacy_gates(model)

    assert "governance-validate" not in receipt_gates
    assert model["execution_groups"]["preflight-structural"]["captured_by_preflight"] is True
    assert {"test", "contract-test", "runtime-smoke"}.issubset(receipt_gates)


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _repo(tmp_path: Path, *, scope: str = "normal") -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root / "app.py", "VALUE = 1\n")
    _write(root / "other.py", "OTHER = 1\n")
    _write(root / "detector.py", "DETECTOR = 1\n")
    _write(root / "tests/test_app.py", "def test_app(): assert True\n")
    _write(root / "docs/guide.md", "base\n")
    _write(root / "tool.lock", "tool=1\n")
    _write(root / "trust.yml", "authority: one\n")
    profile = {
        "profile_contract_version": "3.0",
        "assurance_scope": scope,
        "profile": {"selected": "regulated" if scope == "regulated" else "standard"},
    }
    _write(root / "governance-profile.yml", yaml.safe_dump(profile))
    claims = {
        "governance-valid": {
            "truth": "current preflight is valid",
            "execution_group": "preflight",
            "legacy_gate": "governance-validate",
            "dependencies": {"subject": ["whole"], "detector": ["detector"], "test_population": [], "toolchain": ["tool"], "trust": ["trust"]},
            "qualification_scope": "detector",
            "profiles": ["normal", "regulated", "self"],
            "whole_tree": True,
        },
        "app-valid": {
            "truth": "application behavior passes",
            "execution_group": "app-tests",
            "legacy_gate": "test",
            "dependencies": {"subject": ["app"], "detector": ["detector"], "test_population": ["tests"], "toolchain": ["tool"], "trust": ["trust"]},
            "qualification_scope": "subject",
            "profiles": ["normal", "regulated", "self"],
        },
        "other-valid": {
            "truth": "unrelated behavior passes",
            "execution_group": "other-tests",
            "legacy_gate": "other-test",
            "dependencies": {"subject": ["other"], "detector": ["detector"], "test_population": ["tests"], "toolchain": ["tool"], "trust": ["trust"]},
            "qualification_scope": "detector",
            "profiles": ["normal", "regulated", "self"],
        },
        "regulated-custody": {
            "truth": "regulated custody is present",
            "execution_group": "custody",
            "legacy_gate": "custody",
            "dependencies": {"subject": [], "detector": [], "test_population": [], "toolchain": [], "trust": ["trust"]},
            "qualification_scope": "none",
            "profiles": ["regulated"],
        },
        "self-parity": {
            "truth": "self projections remain exact",
            "execution_group": "self",
            "legacy_gate": "self",
            "dependencies": {"subject": ["self"], "detector": ["detector"], "test_population": ["tests"], "toolchain": ["tool"], "trust": ["trust"]},
            "qualification_scope": "subject",
            "profiles": ["self"],
        },
    }
    registry = {
        "gates": {
            gate: {}
            for gate in ("test", "other-test", "custody", "self")
        },
        "claim_model": {
            "version": "1.0",
            "dependency_sets": {
                "whole": ["**"], "app": ["app.py"], "other": ["other.py"],
                "detector": ["detector.py"], "tests": ["tests/**"],
                "tool": ["tool.lock"], "trust": ["trust.yml"],
                "self": ["governance/**"],
            },
            "execution_groups": {
                "preflight": {"producer": "preflight", "captured_by_preflight": True, "claims": ["governance-valid"]},
                "app-tests": {"producer": "test", "claims": ["app-valid"]},
                "other-tests": {"producer": "other-test", "claims": ["other-valid"]},
                "custody": {"producer": "custody", "claims": ["regulated-custody"]},
                "self": {"producer": "self", "claims": ["self-parity"]},
            },
            "claims": claims,
        }
    }
    _write(root / "governance/gate-contracts.yml", yaml.safe_dump(registry, sort_keys=False))
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
    return root


def _receipt(root: Path, claims: list[str], *, freshness: int | None = None) -> dict:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
    model = load_claim_model(root)
    first_claim = model["claims"][claims[0]]
    producer = model["execution_groups"][first_claim["execution_group"]]["producer"]
    receipt = {
        "schema_version": "3.0",
        "evidence_id": "evidence-" + "-".join(claims),
        "claims": claims,
        "gate_id": producer,
        "dependency_manifest": build_dependency_manifest(root, claims),
        "subject": {"commit_sha": commit, "tree_sha": tree},
        "result": "passed",
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "qualification": {
            "scope": "subject" if "app-valid" in claims else "detector",
            "satisfied": True,
            "fingerprint": "a" * 64,
            "control_ids": ["control"],
        },
        "qualifications": {
            claim: {
                "scope": "subject" if claim in {"app-valid", "self-parity"} else "detector",
                "satisfied": True,
                "fingerprint": "a" * 64,
                "control_ids": ["control"],
            }
            for claim in claims
            if claim not in {"regulated-custody"}
        },
    }
    if freshness is not None:
        receipt["freshness_limit_seconds"] = freshness
    receipt["artifact_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True).encode()
    ).hexdigest()
    return receipt


def _commit(root: Path, path: str, text: str) -> None:
    _write(root / path, text)
    subprocess.run(["git", "add", path], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", f"change {path}"], cwd=root, check=True)


def _registry_change(root: Path, mutate) -> None:
    path = root / "governance/gate-contracts.yml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutate(payload)
    _commit(root, "governance/gate-contracts.yml", yaml.safe_dump(payload, sort_keys=False))


def test_source_syntax_format_covers_template_scripts_and_tests() -> None:
    manifest = build_dependency_manifest(REPO_ROOT, ["source-syntax-format"])
    subject = next(
        item
        for item in manifest["claim_dependencies"]["source-syntax-format"]
        if item["class"] == "subject"
    )
    covered = set(subject["paths"])
    tracked = subprocess.check_output(
        ["git", "ls-files", "--", "template-repo/scripts", "tests"],
        cwd=REPO_ROOT,
        text=True,
    ).splitlines()
    required = {path for path in tracked if path.endswith(".py")}
    assert required
    assert any(path.startswith("template-repo/scripts/") for path in required)
    assert any(path.startswith("tests/") for path in required)
    assert required <= covered


def test_provider_tree_and_canonical_claim_bytes_recompute_same_closure(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    payload = yaml.safe_load((root / "governance/gate-contracts.yml").read_text())
    model = parse_claim_model(payload)
    entries = tuple(
        (line.split("\t", 1)[1], line.split("\t", 1)[0].split()[2])
        for line in subprocess.check_output(
            ["git", "ls-tree", "-r", "--full-tree", "HEAD"], cwd=root, text=True
        ).splitlines()
    )
    assert build_dependency_manifest(root, ["app-valid", "other-valid"]) == (
        build_dependency_manifest(
            root, ["app-valid", "other-valid"], model=model, tree_entries=entries,
        )
    )
    receipt = _receipt(root, ["app-valid"])
    current = {
        "commit_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "tree_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
        ).strip(),
    }
    assert receipt_applicability(
        root, receipt, "app-valid", current_subject=current,
        model=model, tree_entries=entries,
    ) == receipt_applicability(root, receipt, "app-valid")
    with pytest.raises(EvidenceError, match="context must be complete"):
        receipt_applicability(root, receipt, "app-valid", current_subject=current)


def test_documentation_only_change_reuses_unrelated_claims(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipts = [_receipt(root, ["app-valid"]), _receipt(root, ["other-valid"])]
    _commit(root, "docs/guide.md", "changed\n")
    plan = plan_verification(root, receipts, preflight_claims=["governance-valid"])
    assert {value["claim_id"] for value in plan["reused_evidence"]} == {"app-valid", "other-valid"}
    assert plan["execution_dag"]["nodes"] == []


def test_lifecycle_only_change_reuses_behavior_claims(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipts = [_receipt(root, ["app-valid"]), _receipt(root, ["other-valid"])]
    _commit(root, "plans/phase.yml", "state: active\n")
    plan = plan_verification(root, receipts, preflight_claims=["governance-valid"])
    assert {value["claim_id"] for value in plan["reused_evidence"]} == {"app-valid", "other-valid"}
    assert plan["execution_dag"]["nodes"] == []


def test_unavailable_source_commit_uses_exact_local_tree_for_planning_only(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    receipt["subject"]["commit_sha"] = "f" * 40
    plan = plan_verification(root, [receipt], preflight_claims=["governance-valid"])
    assert {value["claim_id"] for value in plan["reused_evidence"]} == {"app-valid"}
    assert [node["id"] for node in plan["execution_dag"]["nodes"]] == ["other-tests"]


def test_unavailable_or_conflicting_source_tree_falls_back_to_execution(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    receipt["subject"]["commit_sha"] = "f" * 40
    receipt["subject"]["tree_sha"] = "e" * 40
    plan = plan_verification(root, [receipt], preflight_claims=["governance-valid"])
    assert plan["reused_evidence"] == []
    assert {node["id"] for node in plan["execution_dag"]["nodes"]} == {"app-tests", "other-tests"}

    receipt["subject"]["commit_sha"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    plan = plan_verification(root, [receipt], preflight_claims=["governance-valid"])
    assert plan["reused_evidence"] == []


def test_unavailable_commit_with_local_prior_tree_keeps_selective_invalidation(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    app = _receipt(root, ["app-valid"])
    other = _receipt(root, ["other-valid"])
    for receipt in (app, other):
        receipt["subject"]["commit_sha"] = "f" * 40
    _commit(root, "app.py", "VALUE = 2\n")
    plan = plan_verification(root, [app, other], preflight_claims=["governance-valid"])
    assert {value["claim_id"] for value in plan["reused_evidence"]} == {"other-valid"}
    assert [node["id"] for node in plan["execution_dag"]["nodes"]] == ["app-tests"]


def test_main_side_qualification_recomputes_digest_and_control_inventory(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    qualified = receipt["qualifications"]["app-valid"]
    qualified["control_ids"] = []
    qualified["fingerprint"] = qualification_equivalence(
        root, receipt, "app-valid"
    )["main_sha256"]
    assert qualification_equivalence(root, receipt, "app-valid")["equivalent"] is True
    payload = yaml.safe_load((root / "governance/gate-contracts.yml").read_text())
    entries = tuple(
        (line.split("\t", 1)[1], line.split("\t", 1)[0].split()[2])
        for line in subprocess.check_output(
            ["git", "ls-tree", "-r", "--full-tree", "HEAD"], cwd=root, text=True
        ).splitlines()
    )
    assert qualification_equivalence(
        root, receipt, "app-valid", contract_payload=payload, tree_entries=entries,
    ) == qualification_equivalence(root, receipt, "app-valid")
    qualified["control_ids"] = ["undeclared-control"]
    assert qualification_equivalence(root, receipt, "app-valid")["equivalent"] is False
    qualified["control_ids"] = []
    qualified["fingerprint"] = "0" * 64
    assert qualification_equivalence(root, receipt, "app-valid")["equivalent"] is False
    qualified["fingerprint"] = qualification_equivalence(
        root, receipt, "app-valid"
    )["main_sha256"]
    _commit(root, "app.py", "VALUE = 2\n")
    assert qualification_equivalence(root, receipt, "app-valid")["equivalent"] is False


def test_detector_qualification_survives_subject_only_change(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["other-valid"])
    qualified = receipt["qualifications"]["other-valid"]
    qualified["control_ids"] = []
    qualified["fingerprint"] = qualification_equivalence(
        root, receipt, "other-valid"
    )["main_sha256"]
    _commit(root, "other.py", "OTHER = 2\n")
    assert qualification_equivalence(root, receipt, "other-valid")["equivalent"] is True
    assert receipt_applicability(root, receipt, "other-valid")[0] is False


def test_semantic_ownership_change_invalidates_only_owning_claim(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    registry_path = root / "governance/gate-contracts.yml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["claim_model"]["dependency_sets"]["app"].append("semantic.py")
    _write(registry_path, yaml.safe_dump(registry, sort_keys=False))
    _write(root / "semantic.py", "OWNER = 'app'\n")
    subprocess.run(["git", "add", "governance/gate-contracts.yml", "semantic.py"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "declare semantic owner"], cwd=root, check=True)
    receipts = [_receipt(root, ["app-valid"]), _receipt(root, ["other-valid"])]
    _commit(root, "semantic.py", "OWNER = 'app-v2'\n")
    plan = plan_verification(root, receipts, preflight_claims=["governance-valid"])
    assert [node["id"] for node in plan["execution_dag"]["nodes"]] == ["app-tests"]
    assert {value["claim_id"] for value in plan["reused_evidence"]} == {"other-valid"}


def test_isolated_implementation_change_invalidates_only_its_domain(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipts = [_receipt(root, ["app-valid"]), _receipt(root, ["other-valid"])]
    _commit(root, "app.py", "VALUE = 2\n")
    plan = plan_verification(root, receipts, preflight_claims=["governance-valid"])
    assert [node["id"] for node in plan["execution_dag"]["nodes"]] == ["app-tests"]
    assert {value["claim_id"] for value in plan["reused_evidence"]} == {"other-valid"}


def test_detector_change_invalidates_detector_dependents(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["other-valid"])
    _commit(root, "detector.py", "DETECTOR = 2\n")
    applicable, reasons = receipt_applicability(root, receipt, "other-valid")
    assert not applicable
    assert "detector_dependency_changed" in reasons


def test_toolchain_change_reports_toolchain_and_environment_contract(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    _commit(root, "tool.lock", "tool=2\n")
    applicable, reasons = receipt_applicability(root, receipt, "app-valid")
    assert not applicable
    assert reasons == ["environment_contract_changed", "toolchain_changed"]


def test_trust_change_reports_trust_and_artifact_identity(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    _commit(root, "trust.yml", "authority: two\n")
    applicable, reasons = receipt_applicability(root, receipt, "app-valid")
    assert not applicable
    assert reasons == ["artifact_identity_changed", "trust_input_changed"]


def test_detector_qualification_reused_for_subject_remediation(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["other-valid"])
    _commit(root, "other.py", "OTHER = 2\n")
    plan = plan_verification(root, [receipt], preflight_claims=["governance-valid"])
    node = next(value for value in plan["execution_dag"]["nodes"] if value["id"] == "other-tests")
    assert node["qualification_refs"] == [{
        "claim_id": "other-valid",
        "evidence_id": receipt["evidence_id"],
        "artifact_sha256": receipt["artifact_sha256"],
    }]


def test_failed_source_cannot_supply_reuse_or_qualification(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["other-valid"])
    receipt["result"] = "failed"
    _commit(root, "other.py", "OTHER = 2\n")
    plan = plan_verification(root, [receipt], preflight_claims=["governance-valid"])
    node = next(value for value in plan["execution_dag"]["nodes"] if value["id"] == "other-tests")
    assert node["qualification_refs"] == []
    assert "other-valid" not in {value["claim_id"] for value in plan["reused_evidence"]}


def test_multi_claim_receipt_cannot_launder_claim_from_another_producer(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid", "other-valid"])
    _commit(root, "app.py", "VALUE = 2\n")
    app_ok, app_reasons = receipt_applicability(root, receipt, "app-valid")
    other_ok, other_reasons = receipt_applicability(root, receipt, "other-valid")
    assert not app_ok and app_reasons == ["subject_dependency_changed"]
    assert not other_ok and other_reasons == ["claim_producer_mismatch"]


def test_claim_model_rejects_duplicate_legacy_gate_during_preflight(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    _registry_change(
        root,
        lambda registry: registry["claim_model"]["claims"]["other-valid"].update(
            {"legacy_gate": "test"}
        ),
    )

    with pytest.raises(EvidenceError, match="duplicate legacy gate test"):
        load_claim_model(root)


def test_remediation_preserves_unrelated_success(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipts = [_receipt(root, ["app-valid"]), _receipt(root, ["other-valid"])]
    _commit(root, "app.py", "VALUE = 0\n")
    first = plan_verification(root, receipts, preflight_claims=["governance-valid"])
    assert [node["id"] for node in first["execution_dag"]["nodes"]] == ["app-tests"]
    _commit(root, "app.py", "VALUE = 3\n")
    second = plan_verification(root, receipts, preflight_claims=["governance-valid"])
    assert [node["id"] for node in second["execution_dag"]["nodes"]] == ["app-tests"]
    assert {value["claim_id"] for value in second["reused_evidence"]} == {"other-valid"}


def test_remediation_touching_unrelated_domain_expands_only_union(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipts = [_receipt(root, ["app-valid"]), _receipt(root, ["other-valid"])]
    _commit(root, "app.py", "VALUE = 2\n")
    _commit(root, "other.py", "OTHER = 2\n")
    plan = plan_verification(root, receipts, preflight_claims=["governance-valid"])
    assert {node["id"] for node in plan["execution_dag"]["nodes"]} == {"app-tests", "other-tests"}


def test_freshness_expiry_forces_only_fresh_claim(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    expired = _receipt(root, ["app-valid"], freshness=1)
    expired["timestamp"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    applicable, reasons = receipt_applicability(root, expired, "app-valid")
    assert not applicable
    assert reasons == ["freshness_expired"]


def test_ambiguous_dependency_manifest_fails_closed(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    receipt["dependency_manifest"]["complete"] = False
    applicable, reasons = receipt_applicability(root, receipt, "app-valid")
    assert not applicable
    assert reasons == ["dependency_closure_ambiguous"]


def test_receipt_cannot_replace_declared_dependency_patterns(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    subject = next(
        value for value in receipt["dependency_manifest"]["claim_dependencies"]["app-valid"]
        if value["class"] == "subject"
    )
    subject["patterns"] = []
    subject["paths"] = []
    subject["fingerprint"] = hashlib.sha256(b"[]").hexdigest()
    applicable, reasons = receipt_applicability(root, receipt, "app-valid")
    assert not applicable
    assert reasons == ["dependency_closure_ambiguous"]


def test_duplicate_dependency_class_fails_closed(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    classes = receipt["dependency_manifest"]["claim_dependencies"]["app-valid"]
    classes.append(dict(classes[0]))
    assert receipt_applicability(root, receipt, "app-valid") == (
        False,
        ["dependency_closure_ambiguous"],
    )


def test_claim_freshness_cannot_be_omitted_from_receipt(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _registry_change(
        root,
        lambda payload: payload["claim_model"]["claims"]["app-valid"].update(
            {"freshness_limit_seconds": 1}
        ),
    )
    receipt = _receipt(root, ["app-valid"])
    receipt.pop("freshness_limit_seconds", None)
    receipt["timestamp"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    assert receipt_applicability(root, receipt, "app-valid") == (
        False,
        ["freshness_expired"],
    )
    assert qualification_applicability(root, receipt, "app-valid") is False


def test_future_timestamp_cannot_extend_freshness(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"], freshness=60)
    receipt["timestamp"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    assert receipt_applicability(root, receipt, "app-valid") == (
        False,
        ["freshness_expired"],
    )


def test_qualification_reference_cannot_replace_claim_qualification(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipt = _receipt(root, ["app-valid"])
    receipt.pop("qualification", None)
    receipt.pop("qualifications", None)
    receipt["qualification_refs"] = [{
        "claim_id": "app-valid",
        "evidence_id": "unverified-reference",
        "artifact_sha256": "a" * 64,
    }]
    applicable, reasons = receipt_applicability(root, receipt, "app-valid")
    assert not applicable
    assert reasons == ["qualification_missing"]


def test_duplicate_evidence_identity_cannot_win_by_input_order(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    first = _receipt(root, ["app-valid"])
    second = _receipt(root, ["app-valid"])
    second["artifact_sha256"] = "f" * 64
    plan = plan_verification(
        root,
        [first, second, _receipt(root, ["other-valid"])],
        preflight_claims=["governance-valid"],
    )
    assert [node["id"] for node in plan["execution_dag"]["nodes"]] == ["app-tests"]
    invalid = next(value for value in plan["invalidated_evidence"] if value["claim_id"] == "app-valid")
    assert invalid["reasons"] == ["dependency_closure_ambiguous"]


def test_unknown_behavior_path_expands_to_full_relevant_profile(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    receipts = [_receipt(root, ["app-valid"]), _receipt(root, ["other-valid"])]
    _commit(root, "backdoor.py", "ENABLED = True\n")
    plan = plan_verification(root, receipts, preflight_claims=["governance-valid"])
    assert {node["id"] for node in plan["execution_dag"]["nodes"]} == {
        "app-tests",
        "other-tests",
    }
    assert any(text.startswith("expanded because") for text in plan["decision_explanations"])


def test_missing_execution_producer_is_rejected(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _registry_change(
        root,
        lambda payload: payload["claim_model"]["execution_groups"]["app-tests"].update(
            {"producer": "missing-gate"}
        ),
    )
    with pytest.raises(EvidenceError, match="producer is not an executable gate"):
        load_claim_model(root)


def test_duplicate_execution_group_membership_is_rejected(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _registry_change(
        root,
        lambda payload: payload["claim_model"]["execution_groups"]["other-tests"]["claims"].append(
            "app-valid"
        ),
    )
    with pytest.raises(EvidenceError, match="exactly one execution group"):
        load_claim_model(root)


def test_legacy_receipt_maps_only_its_declared_gate_and_exact_subject(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
    receipt = {
        "schema_version": "2.0",
        "gate_id": "test",
        "result": "passed",
        "subject": {"commit_sha": commit, "tree_sha": tree},
    }
    assert receipt_applicability(root, receipt, "app-valid") == (True, [])
    assert receipt_applicability(root, receipt, "regulated-custody") == (
        False,
        ["legacy_evidence_exact_subject_only"],
    )
    _commit(root, "docs/guide.md", "new commit\n")
    assert receipt_applicability(root, receipt, "app-valid") == (
        False,
        ["legacy_evidence_exact_subject_only"],
    )


def test_prior_bundle_is_digest_closed_and_rejects_symlink_root(tmp_path: Path) -> None:
    root = tmp_path / "prior"
    root.mkdir()
    payload = {"schema_version": "3.0", "evidence_id": "one"}
    path = root / "note.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    material = [(path.name, hashlib.sha256(path.read_bytes()).hexdigest())]
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    governed = _repo(tmp_path)
    assert load_prior_receipts(governed, root, digest) == []
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceError, match="digest mismatch"):
        load_prior_receipts(governed, root, digest)
    link = tmp_path / "prior-link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(EvidenceError, match="directory is unsafe"):
        load_prior_receipts(governed, link, digest)


def test_prior_bundle_rejects_malformed_receipt(tmp_path: Path) -> None:
    root = tmp_path / "prior"
    root.mkdir()
    path = root / "bad.evidence.json"
    path.write_text("{", encoding="utf-8")
    material = [(path.name, hashlib.sha256(path.read_bytes()).hexdigest())]
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(EvidenceError, match="receipt is invalid"):
        load_prior_receipts(_repo(tmp_path), root, digest)


def test_prior_bundle_admits_applicability_only_invalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    governed = _repo(tmp_path)
    root = tmp_path / "prior"
    root.mkdir()
    receipt = _receipt(governed, ["app-valid"])
    path = root / "old.evidence.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    material = [(path.name, hashlib.sha256(path.read_bytes()).hexdigest())]
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    from bcf_governance.tooling import truth_receipts

    monkeypatch.setattr(
        truth_receipts,
        "load_receipts",
        lambda *args, **kwargs: {
            "test": [{
                "result": "invalid",
                "issues": ["subject_dependency_changed"],
                "invalidation": {"reasons": ["subject_dependency_changed"]},
                "receipt": receipt,
                "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }]
        },
    )

    loaded = load_prior_receipts(governed, root, digest)
    assert loaded[0]["evidence_id"] == receipt["evidence_id"]


def test_prior_bundle_rejects_non_applicability_validation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    governed = _repo(tmp_path)
    root = tmp_path / "prior"
    root.mkdir()
    receipt = _receipt(governed, ["app-valid"])
    path = root / "bad.evidence.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    material = [(path.name, hashlib.sha256(path.read_bytes()).hexdigest())]
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    from bcf_governance.tooling import truth_receipts

    monkeypatch.setattr(
        truth_receipts,
        "load_receipts",
        lambda *args, **kwargs: {
            "test": [{
                "result": "invalid",
                "issues": ["receipt_schema:forged"],
                "invalidation": {"reasons": []},
                "receipt": receipt,
                "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }]
        },
    )

    with pytest.raises(EvidenceError, match="receipt_schema:forged"):
        load_prior_receipts(governed, root, digest)


def test_provider_transport_bundle_uses_its_canonical_mapping_and_exact_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    governed = _repo(tmp_path)
    root = tmp_path / "transport"
    source = _receipt(governed, ["app-valid"])
    receipt_raw = json.dumps(source).encode()
    expanded = root / "expanded/123/test/app.evidence.json"
    archive = root / "archives/123.zip"
    _write(expanded, receipt_raw.decode())
    _write(archive, "archive bytes")
    material = {
        "archives/123.zip": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "expanded/123/test/app.evidence.json": hashlib.sha256(receipt_raw).hexdigest(),
    }
    transport_digest = hashlib.sha256(canonical_json(material)).hexdigest()
    manifest = {
        "schema_version": "1.0", "kind": "prior_evidence_transport",
        "main": {"commit_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=governed, text=True).strip(),
                 "tree_sha": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=governed, text=True).strip()},
        "bundle_sha256": transport_digest,
        "artifacts": [{"artifact_id": "123", "archive_sha256": material["archives/123.zip"],
                       "files": [{"path": "test/app.evidence.json", "sha256": material["expanded/123/test/app.evidence.json"],
                                  "size": len(receipt_raw)}]}],
        "receipts": [{"artifact_id": "123", "path": "test/app.evidence.json",
                      "receipt_sha256": material["expanded/123/test/app.evidence.json"]}],
    }
    _write(root / "prior-evidence-transport.json", json.dumps(manifest))
    bundle_material = sorted(
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.rglob("*") if path.is_file()
    )
    digest = hashlib.sha256(json.dumps(bundle_material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    from bcf_governance.tooling import truth_receipts

    monkeypatch.setattr(truth_receipts, "load_receipts", lambda *args, **kwargs: {
        "test": [{"result": "verified", "receipt": source,
                  "artifact_sha256": material["expanded/123/test/app.evidence.json"]}]
    })
    before = expanded.read_bytes()
    assert load_prior_receipts(governed, root, digest)[0]["evidence_id"] == source["evidence_id"]
    assert expanded.read_bytes() == before
    with pytest.raises(EvidenceError, match="digest mismatch"):
        load_prior_receipts(governed, root, "0" * 64)
    manifest_path = root / "prior-evidence-transport.json"
    manifest_path.write_text(json.dumps({**manifest, "main": {"commit_sha": "0" * 40, "tree_sha": "0" * 40}}))
    with pytest.raises(EvidenceError, match="digest mismatch"):
        load_prior_receipts(governed, root, digest)
    manifest_path.write_text(json.dumps(manifest))
    _write(root / "expanded/123/test/app.evidence.json", "{}")
    with pytest.raises(EvidenceError, match="digest mismatch"):
        load_prior_receipts(governed, root, digest)


def test_provider_transport_bundle_rejects_wrong_main_and_extra_member(tmp_path: Path) -> None:
    governed = _repo(tmp_path)
    root = tmp_path / "transport"
    _write(root / "archives/123.zip", "archive")
    transport_digest = hashlib.sha256(canonical_json({"archives/123.zip": hashlib.sha256(b"archive").hexdigest()})).hexdigest()
    manifest = {"schema_version": "1.0", "kind": "prior_evidence_transport",
                "main": {"commit_sha": "0" * 40, "tree_sha": "0" * 40},
                "bundle_sha256": transport_digest, "artifacts": [], "receipts": []}
    _write(root / "prior-evidence-transport.json", json.dumps(manifest))
    bundle_material = sorted(
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.rglob("*") if path.is_file()
    )
    digest = hashlib.sha256(json.dumps(bundle_material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(EvidenceError, match="main subject is not current"):
        load_prior_receipts(governed, root, digest)
    manifest["main"] = {
        "commit_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=governed, text=True).strip(),
        "tree_sha": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=governed, text=True).strip(),
    }
    manifest["artifacts"] = [{"artifact_id": "123", "archive_sha256": hashlib.sha256(b"archive").hexdigest(),
                              "files": [{"path": "one.txt", "sha256": hashlib.sha256(b"one").hexdigest(), "size": 3}]}]
    _write(root / "expanded/123/one.txt", "one")
    _write(root / "extra.txt", "extra")
    _write(root / "prior-evidence-transport.json", json.dumps(manifest))
    bundle_material = sorted(
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.rglob("*") if path.is_file()
    )
    digest = hashlib.sha256(json.dumps(bundle_material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(EvidenceError, match="digest mismatch"):
        load_prior_receipts(governed, root, digest)


def test_regulated_scope_adds_only_explicit_regulated_claim(tmp_path: Path) -> None:
    root = _repo(tmp_path, scope="regulated")
    plan = plan_verification(root, preflight_claims=["governance-valid"])
    assert "regulated-custody" in plan["required_claims"]
    assert "self-parity" not in plan["required_claims"]


def test_self_scope_adds_self_claim_without_regulated_claim(tmp_path: Path) -> None:
    root = _repo(tmp_path, scope="self")
    plan = plan_verification(root, preflight_claims=["governance-valid"])
    assert "self-parity" in plan["required_claims"]
    assert "regulated-custody" not in plan["required_claims"]
