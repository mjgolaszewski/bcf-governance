from __future__ import annotations

from pathlib import Path
import subprocess
import copy
import yaml

import pytest

from bcf_governance.tooling.governance_validation.ci_state_matrix import (
    CIStateMatrixError,
    validate_ci_state_matrix,
)


ROOT = Path(__file__).resolve().parents[1]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "spec/phase0").mkdir(parents=True)
    (repo / "bcf_governance/tooling").mkdir(parents=True)
    (repo / "spec/RELEASE_TRAIN_STATE_DAG.md").write_bytes(
        (ROOT / "spec/RELEASE_TRAIN_STATE_DAG.md").read_bytes()
    )
    (repo / "spec/phase0/release-train-backtrace.yml").write_bytes(
        (ROOT / "spec/phase0/release-train-backtrace.yml").read_bytes()
    )
    (repo / "schemas").mkdir()
    (repo / "schemas/release-train-backtrace.schema.json").write_bytes(
        (ROOT / "schemas/release-train-backtrace.schema.json").read_bytes()
    )
    (repo / "bcf_governance/tooling/preflight.py").write_text("VALUE = 1\n")
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.name", "BCF Test")
    _git(repo, "config", "user.email", "bcf@example.invalid")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    _git(repo, "remote", "add", "origin", str(repo))
    _git(repo, "fetch", "origin", "main")
    return repo


def test_changed_ci_contract_requires_same_candidate_matrix_update(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "bcf_governance/tooling/preflight.py").write_text("VALUE = 2\n")
    with pytest.raises(CIStateMatrixError, match="same-candidate state matrix"):
        validate_ci_state_matrix(repo)
    with (repo / "spec/RELEASE_TRAIN_STATE_DAG.md").open("a", encoding="utf-8") as stream:
        stream.write("\nCandidate-specific transition coverage.\n")
    report = validate_ci_state_matrix(repo)
    assert report["changed_contracts"] == ["bcf_governance/tooling/preflight.py", "spec/RELEASE_TRAIN_STATE_DAG.md"]
    assert report["machine_backtrace"] == {"edges": 7, "transitions": 15}


def test_machine_backtrace_rejects_an_incomplete_edge_before_ci_allocation(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "authority_effect: exact_release_byte_verification, ", "", 1
        ),
        encoding="utf-8",
    )
    with pytest.raises(CIStateMatrixError, match="AC-001 lacks: authority_effect"):
        validate_ci_state_matrix(repo)


def test_matrix_guard_is_self_required_and_adopter_inapplicable(tmp_path: Path) -> None:
    adopter = tmp_path / "adopter"
    adopter.mkdir()
    assert validate_ci_state_matrix(adopter)["status"] == "not_applicable_to_adopter"
    (adopter / "governance").mkdir()
    (adopter / "governance/self-governance-policy.yml").write_text("document: {}\n")
    with pytest.raises(CIStateMatrixError, match="unavailable"):
        validate_ci_state_matrix(adopter)


@pytest.mark.parametrize("defect", ["duplicate_invariant", "duplicate_primitive", "duplicate_state", "duplicate_transition", "state_reference", "invariant_reference", "active_primitive_reference", "schema_version", "declared_field_bypass", "field_list_omission", "source_identity"])
def test_machine_backtrace_rejects_typed_identity_and_shape_defects(tmp_path: Path, defect: str) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    model = yaml.safe_load(path.read_text())
    if defect.startswith("duplicate_"):
        section = {"invariant": "invariants", "primitive": "primitives", "state": "states", "transition": "transitions"}[defect.removeprefix("duplicate_")]
        duplicate = copy.deepcopy(model[section][0])
        field = {"invariants": "statement", "primitives": "owner", "states": "owner", "transitions": "cost"}[section]
        duplicate[field] += "-different"
        model[section].append(duplicate)
    elif defect == "state_reference":
        model["transitions"][0]["to"] = "ST-UNKNOWN"
    elif defect == "invariant_reference":
        model["primitives"][0]["invariants"] = ["INV-RT-999"]
    elif defect == "active_primitive_reference":
        model["adopter_compatibility_observation"]["primitives"].append("PRIM-UNKNOWN")
    elif defect == "schema_version":
        model["document"]["schema_version"] = 99
    elif defect == "source_identity":
        model["document"]["source"]["commit_sha"] = "not-a-commit"
    else:
        observation = model["adopter_compatibility_observation"]
        observation["edge_contract_fields"].remove("authority_effect")
        if defect == "declared_field_bypass":
            del observation["edges"][0]["authority_effect"]
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    with pytest.raises(CIStateMatrixError, match="machine-readable"):
        validate_ci_state_matrix(repo)


def test_machine_backtrace_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    path.write_text(path.read_text() + "\nvalidation_status: {}\n")
    with pytest.raises(CIStateMatrixError, match="duplicate YAML key"):
        validate_ci_state_matrix(repo)


def test_machine_backtrace_rejects_symlinked_input(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    retained = path.with_suffix(".retained.yml")
    path.rename(retained)
    path.symlink_to(retained.name)
    with pytest.raises(CIStateMatrixError, match="nonsymlink"):
        validate_ci_state_matrix(repo)


def test_authored_machine_mode_defers_prose_projection_checks(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "spec/RELEASE_TRAIN_STATE_DAG.md").write_text("Pending canonical projection.\n")
    result = validate_ci_state_matrix(repo, authored_only=True)
    assert result["authority"] is False
    assert result["execution_qualified"] is False
    assert result["machine_backtrace"]["transitions"] > 0
    with pytest.raises(CIStateMatrixError, match="required coverage"):
        validate_ci_state_matrix(repo)


@pytest.mark.parametrize("field", ["rejection_transition", "retry_of"])
@pytest.mark.parametrize("defect", ["missing", "self", "wrong-kind", "wrong-source", "lost-invariant"])
def test_authored_backtrace_rejects_unbound_typed_transition_reference(tmp_path, field, defect):
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    model = yaml.safe_load(path.read_text())
    source, target = model["transitions"][:2]
    source["kind"] = "success" if field == "rejection_transition" else "recovery"
    if field == "retry_of": source["max_attempts"] = 2
    if defect == "missing": source[field] = "TR-999"
    elif defect == "self": source[field] = source["id"]
    elif defect == "wrong-kind":
        source[field] = target["id"]
        target["kind"] = "recovery" if field == "rejection_transition" else "rejection"
        if target["kind"] == "recovery":
            target.update(retry_of=model["transitions"][2]["id"], max_attempts=2)
    else:
        source[field] = target["id"]
        target["kind"] = "rejection" if field == "rejection_transition" else "success"
        if field == "rejection_transition":
            target["from"] = source["from"]
            target["invariants"] = list(source["invariants"])
            if defect == "wrong-source": target["from"] = source["to"]
            else: target["invariants"] = ["INV-RT-018"]
        else:
            rejected = model["transitions"][2]
            target["rejection_transition"] = rejected["id"]
            rejected.update(kind="rejection", invariants=list(target["invariants"]))
            rejected["from"] = target["from"]
            source.update(invariants=list(target["invariants"]))
            source["from"], source["to"] = rejected["to"], target["from"]
            if defect == "wrong-source": source["from"] = target["from"]
            else: source["invariants"] = ["INV-RT-018"]
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    with pytest.raises(CIStateMatrixError, match="typed transition reference"):
        validate_ci_state_matrix(repo, authored_only=True)


@pytest.mark.parametrize("recovery", [False, True])
def test_authored_backtrace_accepts_declared_typed_transition_references(tmp_path, recovery):
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    model = yaml.safe_load(path.read_text())
    success, rejection, retry = model["transitions"][:3]
    success.update(kind="success", rejection_transition=rejection["id"])
    rejection.update(kind="rejection", invariants=list(success["invariants"]))
    rejection["from"] = success["from"]
    if recovery:
        retry.update(kind="recovery", retry_of=success["id"], max_attempts=2, invariants=list(success["invariants"]))
        retry["from"], retry["to"] = rejection["to"], success["from"]
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    result = validate_ci_state_matrix(repo, authored_only=True)
    assert result["authority"] is False
    assert result["execution_qualified"] is False


@pytest.mark.parametrize("field", ["rejection_transition", "retry_of"])
@pytest.mark.parametrize("defect", ["missing", "changed", "duplicate"])
def test_authored_reference_guard_rejects_lost_guard_obligation(field, defect):
    from bcf_governance.tooling.governance_validation.ci_state_matrix import _validate_backtrace_references

    model = yaml.safe_load((ROOT / "spec/phase0/release-train-backtrace.yml").read_text())
    success, rejected, recovery = model["transitions"][:3]
    success.update(kind="success", rejection_transition=rejected["id"], guard_refs=["sha256:" + "a" * 64])
    rejected.update(kind="rejection", guard_refs=list(success["guard_refs"]), invariants=list(success["invariants"]))
    rejected["from"] = success["from"]
    recovery.update(kind="recovery", retry_of=success["id"], max_attempts=2,
                    guard_refs=list(success["guard_refs"]), invariants=list(success["invariants"]))
    recovery["from"], recovery["to"] = rejected["to"], success["from"]
    changed = rejected if field == "rejection_transition" else recovery
    if defect == "missing": changed.pop("guard_refs")
    elif defect == "changed": changed["guard_refs"] = ["sha256:" + "b" * 64]
    else: changed["guard_refs"] *= 2
    with pytest.raises(CIStateMatrixError, match="guard"):
        _validate_backtrace_references(model)


@pytest.mark.parametrize("changed", [False, True])
def test_authored_only_recovery_preserves_declared_guard_before_allocation(tmp_path, changed):
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    model = yaml.safe_load(path.read_text())
    success, rejected, recovery = model["transitions"][:3]
    refs = ["sha256:" + "a" * 64]
    success.update(kind="success", rejection_transition=rejected["id"], guard_refs=list(refs))
    rejected.update(kind="rejection", guard_refs=list(refs), invariants=list(success["invariants"]))
    rejected["from"] = success["from"]
    recovery.update(kind="recovery", retry_of=success["id"], max_attempts=2,
                    guard_refs=list(refs), invariants=list(success["invariants"]))
    recovery["from"], recovery["to"] = rejected["to"], success["from"]
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    assert validate_ci_state_matrix(repo, authored_only=True)["authority"] is False
    if changed: recovery["guard_refs"] = ["sha256:" + "b" * 64]
    else: recovery.pop("guard_refs")
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    with pytest.raises(CIStateMatrixError, match="guard"):
        validate_ci_state_matrix(repo, authored_only=True)
