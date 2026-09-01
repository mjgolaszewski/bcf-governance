from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

import pytest
import yaml

from bcf_governance.tooling.ci_authority_pins import (
    CIAuthorityPinError,
    _compile_inventories,
    pin_workflow_authority,
    verify_workflow_authority,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str, bytes]:
    root = tmp_path / "repo"
    workflow = root / ".github/workflows/exact.yml"
    workflow.parent.mkdir(parents=True)
    content = b"name: exact\non: push\n"
    workflow.write_bytes(content)
    authority = root / "governance/ci-authority.yml"
    authority.parent.mkdir()
    authority.write_text(
        "schema_version: '1.1'\n"
        "workflow_registry:\n"
        "  admission:\n"
        "    workflow_id: '1'\n"
        "    active_path: .github/workflows/exact.yml\n"
        f"    trusted_workflow_blob_oid: {'a' * 40}\n"
        f"    trusted_workflow_sha256: {'b' * 64}\n"
        f"    trusted_workflow_definition_commit: {'c' * 40}\n"
        "    allowed_events: [push]\n",
        encoding="utf-8",
    )
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "BCF Test")
    _git(root, "config", "user.email", "bcf@example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "workflow bytes")
    return root, _git(root, "rev-parse", "HEAD"), content


def test_workflow_authority_pins_are_derived_from_exact_committed_bytes(
    tmp_path: Path,
) -> None:
    root, commit, content = _repository(tmp_path)
    result = pin_workflow_authority(
        root,
        authority_path=Path("governance/ci-authority.yml"),
        definition_commit=commit,
        references=("admission",),
        apply=True,
    )
    payload = yaml.safe_load((root / "governance/ci-authority.yml").read_text())
    entry = payload["workflow_registry"]["admission"]
    assert result.status == "changed"
    assert entry["trusted_workflow_blob_oid"] == _git(
        root, "rev-parse", f"{commit}:.github/workflows/exact.yml"
    )
    assert entry["trusted_workflow_sha256"] == hashlib.sha256(content).hexdigest()
    assert entry["trusted_workflow_definition_commit"] == commit
    assert pin_workflow_authority(
        root,
        authority_path=Path("governance/ci-authority.yml"),
        definition_commit=commit,
        references=("admission",),
        apply=False,
    ).status == "clean"


def test_workflow_authority_pinning_rejects_uncommitted_definition_bytes(
    tmp_path: Path,
) -> None:
    root, commit, _ = _repository(tmp_path)
    (root / ".github/workflows/exact.yml").write_text("name: changed\n", encoding="utf-8")
    with pytest.raises(CIAuthorityPinError, match="differ from definition commit"):
        pin_workflow_authority(
            root,
            authority_path=Path("governance/ci-authority.yml"),
            definition_commit=commit,
            references=("admission",),
            apply=False,
        )


def test_workflow_authority_compiles_matrix_names_and_semantic_roles(
    tmp_path: Path,
) -> None:
    root, _, _ = _repository(tmp_path)
    workflow = root / ".github/workflows/exact.yml"
    workflow.write_text(
        "name: exact\n"
        "on: workflow_dispatch\n"
        "jobs:\n"
        "  produce:\n"
        "    name: Produce ${{ matrix.slot }}\n"
        "    strategy:\n"
        "      matrix:\n"
        "        slot: [a, b]\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n"
        "  observe:\n"
        "    name: Observe exact inventory\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n",
        encoding="utf-8",
    )
    authority_path = root / "governance/ci-authority.yml"
    payload = yaml.safe_load(authority_path.read_text(encoding="utf-8"))
    entry = payload["workflow_registry"]["admission"]
    entry["job_roles"] = {"produce": "producer", "observe": "observer"}
    entry["expected_jobs"] = [{"job_id": "copied-value"}]
    authority_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "matrix workflow")
    commit = _git(root, "rev-parse", "HEAD")

    pin_workflow_authority(
        root,
        authority_path=Path("governance/ci-authority.yml"),
        definition_commit=commit,
        references=(),
        apply=True,
    )

    pinned = yaml.safe_load(authority_path.read_text(encoding="utf-8"))
    assert pinned["workflow_registry"]["admission"]["expected_jobs"] == [
        {"job_id": "Produce a", "role": "producer"},
        {"job_id": "Produce b", "role": "producer"},
        {"job_id": "Observe exact inventory", "role": "observer"},
    ]


def test_self_workflow_authority_is_mechanically_compiled() -> None:
    assert verify_workflow_authority(
        REPO_ROOT, authority_path=Path("governance/ci-authority.yml")
    ) == 12
    payload = yaml.safe_load(
        (REPO_ROOT / "governance/ci-authority.yml").read_text(encoding="utf-8")
    )
    privileged = {
        reference
        for role, reference in payload["roles"].items()
        if role not in {"admission", "reusable_producers"}
    }
    expected = {
        reference: payload["workflow_registry"][reference].pop("expected_jobs")
        for reference in privileged
    }
    payload.pop("admission_jobs")
    for producer in payload["producers"]:
        producer.pop("expected_jobs")
    workflow_bytes = {
        reference: (REPO_ROOT / entry["active_path"]).read_bytes()
        for reference, entry in payload["workflow_registry"].items()
    }

    _compile_inventories(payload, workflow_bytes)

    assert all(
        payload["workflow_registry"][reference]["expected_jobs"] == expected[reference]
        for reference in privileged
    )
    assert payload["workflow_registry"]["authority-canary"]["job_roles"] == {
        "admit": "admission",
        "producer-a": "producer",
        "producer-b": "producer",
        "observe": "observer",
    }


def test_bridge_admission_roles_are_inferred_from_exact_producer_source_keys() -> None:
    payload = yaml.safe_load(
        (REPO_ROOT / "governance/ci-authority.yml").read_text(encoding="utf-8")
    )

    assert "job_roles" not in payload["workflow_registry"]["admission"]
    assert payload["admission_jobs"] == [
        {"job_id": "Authenticate exact-main admission and publish pending authority"}
    ]
    assert [value["producer_id"] for value in payload["producers"]] == [
        "governance", "governance-pack"
    ]
