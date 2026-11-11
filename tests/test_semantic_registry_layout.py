"""Closed indexed registry source and flat parity controls."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.semantic_authority_migrations import _git_registry
from bcf_governance.tooling.semantic_ownership_deconstruct import deconstruct
from bcf_governance.tooling.semantic_ownership_layout import registry_digest
from bcf_governance.tooling.semantic_ownership_registry import (
    SemanticOwnershipRegistryError,
    load_registry,
)

ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path) -> tuple[Path, dict]:
    repo = tmp_path / "repo"
    for relative in (
        "governance/canonical-representations.yml",
        "governance/artifact-manifest.yml",
        "schemas/canonical-representations.schema.json",
    ):
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    root = yaml.safe_load((repo / "governance/canonical-representations.yml").read_text())
    return repo, root


def _indexed(repo: Path, root: dict) -> Path:
    row = root.pop("representations")[0]
    root.pop("secondary_representations", None)
    root["representation_sources"] = ["governance/canonical-representations/one.yml"]
    # The fixture retains one declared blocking identity and its original facts.
    root["enforcement"]["blocking_semantic_ids"] = [row["semantic_id"]]
    source = repo / root["representation_sources"][0]
    source.parent.mkdir()
    source.write_text(yaml.safe_dump({
        "document": {"kind": "canonical_representation_source", "id": "one", "version": "1.0.0", "status": "active", "path": root["representation_sources"][0], "family": row["family"]},
        "representations": [row],
    }, sort_keys=False))
    (repo / "governance/canonical-representations.yml").write_text(yaml.safe_dump(root, sort_keys=False))
    return source


def test_indexed_source_loads_exact_facts_and_binds_bytes(tmp_path: Path) -> None:
    repo, root = _fixture(tmp_path)
    source = _indexed(repo, root)
    loaded = load_registry(repo)
    assert len(loaded.entries) == 1
    assert loaded.entries[0].raw == yaml.safe_load(source.read_text())["representations"][0]
    before = registry_digest((repo / "governance/canonical-representations.yml").read_bytes(), loaded.source_digests)
    source.write_bytes(source.read_bytes() + b"\n")
    after = load_registry(repo)
    assert after.entries == loaded.entries
    assert registry_digest((repo / "governance/canonical-representations.yml").read_bytes(), after.source_digests) != before


@pytest.mark.parametrize("mutation, expected", [
    ("missing", "missing representation source"),
    ("orphan", "undeclared or missing"),
    ("symlink", "unsafe or missing"),
    ("duplicate-key", "invalid representation source"),
    ("family", "representation family mismatch"),
    ("nested", "invalid representation source"),
    ("path", "representation source path mismatch"),
    ("budget", "exceeds context budget"),
])
def test_indexed_source_failures_are_closed(tmp_path: Path, mutation: str, expected: str) -> None:
    repo, root = _fixture(tmp_path)
    source = _indexed(repo, root)
    if mutation == "missing":
        source.unlink()
    elif mutation == "orphan":
        source.with_name("orphan.yml").write_text("document: {}\n")
    elif mutation == "symlink":
        raw = source.read_bytes()
        source.unlink()
        outside = tmp_path / "outside.yml"
        outside.write_bytes(raw)
        source.symlink_to(outside)
    elif mutation == "duplicate-key":
        source.write_bytes(source.read_bytes() + b"document: {}\n")
    elif mutation == "family":
        value = yaml.safe_load(source.read_text())
        value["representations"][0]["family"] = "other_family"
        source.write_text(yaml.safe_dump(value, sort_keys=False))
    elif mutation == "nested":
        source.write_bytes(source.read_bytes() + b"representation_sources: [governance/canonical-representations/other.yml]\n")
    elif mutation == "path":
        value = yaml.safe_load(source.read_text())
        value["document"]["path"] = "governance/canonical-representations/other.yml"
        source.write_text(yaml.safe_dump(value, sort_keys=False))
    elif mutation == "budget":
        source.write_bytes(source.read_bytes() + b"#" + b"x" * 65536 + b"\n")
    with pytest.raises(SemanticOwnershipRegistryError, match=expected):
        load_registry(repo)


def test_indexed_root_rejects_duplicate_key_and_traversal(tmp_path: Path) -> None:
    repo, root = _fixture(tmp_path)
    _indexed(repo, root)
    path = repo / "governance/canonical-representations.yml"
    path.write_bytes(path.read_bytes() + b"representation_sources: []\n")
    with pytest.raises(SemanticOwnershipRegistryError, match="duplicate YAML key"):
        load_registry(repo)
    path.write_bytes(path.read_bytes().split(b"representation_sources: []\n")[0])
    payload = yaml.safe_load(path.read_text())
    payload["representation_sources"] = ["governance/canonical-representations/../escape.yml"]
    path.write_text(yaml.safe_dump(payload, sort_keys=False))
    with pytest.raises(SemanticOwnershipRegistryError, match="representation_sources"):
        load_registry(repo)


def test_flat_digest_remains_exact_root_sha(tmp_path: Path) -> None:
    repo, _ = _fixture(tmp_path)
    loaded = load_registry(repo)
    import hashlib
    raw = (repo / "governance/canonical-representations.yml").read_bytes()
    assert registry_digest(raw, loaded.source_digests) == hashlib.sha256(raw).hexdigest()


def test_git_backed_deconstruction_preserves_logical_registry(tmp_path: Path) -> None:
    import subprocess

    repo, _ = _fixture(tmp_path)
    before = load_registry(repo).raw
    for args in (("init",), ("config", "user.email", "layout@example.test"),
                 ("config", "user.name", "Layout Test"), ("add", "."),
                 ("commit", "-m", "flat registry")):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    preview = deconstruct(repo, apply=False)
    assert 1 <= preview["source_count"] <= len(before["representations"]) + len(before.get("secondary_representations", []))
    result = deconstruct(repo, apply=True)
    assert result["paths"] == preview["paths"]
    assert load_registry(repo).raw == before
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "indexed registry"], cwd=repo, check=True, capture_output=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    (repo / result["paths"][1]).unlink()
    assert _git_registry(repo, sha) == before


def test_128_independent_families_fit_closed_source_index(tmp_path: Path) -> None:
    import copy

    repo, root = _fixture(tmp_path)
    seed = root.pop("representations")[0]
    root.pop("secondary_representations", None)
    paths = []
    families = []
    for number in range(128):
        family = f"family_{number:03d}"
        relative = f"governance/canonical-representations/family-{number:03d}.yml"
        row = copy.deepcopy(seed)
        old_owner = row["authoritative_owner"]["symbol"]
        new_owner = f"fixture/owner.py::owner_{number:03d}"
        row["semantic_id"] = f"fixture.family-{number:03d}.v1"
        row["family"] = family
        row["canonical_type"]["symbol"] = f"fixture/types.py::Type_{number:03d}"
        row["authoritative_owner"]["symbol"] = new_owner
        row["authorized_constructors_and_factories"] = [
            new_owner if value == old_owner else value
            for value in row["authorized_constructors_and_factories"]
        ]
        source = repo / relative
        source.parent.mkdir(exist_ok=True)
        source.write_text(yaml.safe_dump({
            "document": {"kind": "canonical_representation_source", "id": f"family-{number:03d}", "version": "1.0.0", "status": "active", "path": relative, "family": family},
            "representations": [row],
        }, sort_keys=False))
        paths.append(relative)
        families.append(family)
    root["enforcement"]["declared_families"] = families
    root["enforcement"]["blocking_semantic_ids"] = []
    root["representation_sources"] = paths
    base = yaml.safe_dump({key: value for key, value in root.items() if key != "representation_sources"}, sort_keys=False)
    (repo / "governance/canonical-representations.yml").write_text(
        base + "representation_sources: [" + ", ".join(paths) + "]\n"
    )
    loaded = load_registry(repo)
    assert len(loaded.entries) == len(loaded.source_digests) == 128
