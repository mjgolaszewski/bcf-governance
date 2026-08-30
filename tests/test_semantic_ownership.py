from __future__ import annotations

import dataclasses
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import semantic_ownership_inventory as inventory
from bcf_governance.tooling import semantic_ownership_scan as scan
from bcf_governance.tooling.semantic_ownership_registry import (
    Registry,
    SemanticOwnershipRegistryError,
    load_registry,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


def _current_inventory_and_registry() -> tuple[dict[str, object], Registry]:
    return inventory.discover_python_source(REPO_ROOT), load_registry(REPO_ROOT)


def test_source_discovery_precedes_registry_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    source = {
        "files": [],
        "types": [],
        "functions": [],
        "constructors": [],
        "normalizations": [],
        "unresolved": [],
    }
    registry = Registry(
        phase="P04",
        mode="report_only",
        unresolved_dynamic_policy="report",
        authoritative_python_roots=("src",),
        generated_mirror_roots=(),
        entries=(),
        raw={},
    )
    monkeypatch.setattr(
        scan, "discover_python_source", lambda _: (events.append("discovery") or source)
    )
    monkeypatch.setattr(
        scan, "load_registry", lambda _: (events.append("registry") or registry)
    )

    report = scan.run_scan(tmp_path)

    assert events == ["discovery", "registry"]
    assert report["subject"]["discovery_preceded_registry_load"] is True


def test_tracked_source_inventory_excludes_untracked_python(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "owned.py").write_text("def owned() -> str:\n    return 'owned'\n", encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "soip@example.test")
    _git(repo, "config", "user.name", "SOIP Test")
    _git(repo, "add", "owned.py")
    _git(repo, "commit", "-m", "owned source")
    (repo / "untracked.py").write_text("def hidden():\n    pass\n", encoding="utf-8")

    discovered = inventory.discover_python_source(repo)

    assert [value["path"] for value in discovered["files"]] == ["owned.py"]


def test_current_bcf_registry_is_conformant_and_report_is_compact(tmp_path: Path) -> None:
    report = scan.run_scan(REPO_ROOT)
    encoded = json.dumps(report, sort_keys=True).encode()

    assert report["verdict"] == "conformant"
    assert report["blocking_violation_count"] == 0
    assert len(report["registry_coverage"]) == 3
    assert len(encoded) < 1024 * 1024


def test_unauthorized_constructor_is_causal() -> None:
    discovered, registry = _current_inventory_and_registry()
    entry = registry.entries[0]
    discovered["constructors"].append(
        {
            "caller": "bcf_governance/tooling/rogue.py::forge",
            "constructed_symbol": entry.canonical_symbol,
            "line": 7,
        }
    )

    report = scan.evaluate_discovery(discovered, registry)

    assert any(
        value["kind"] == "unauthorized_constructor"
        and value["symbol"] == "bcf_governance/tooling/rogue.py::forge"
        for value in report["violations"]
    )


def test_downstream_normalization_is_causal() -> None:
    discovered, registry = _current_inventory_and_registry()
    entry = registry.entries[0]
    symbol = "bcf_governance/tooling/rogue.py::repair"
    discovered["functions"].append(
        {
            "symbol": symbol,
            "parameters": {"value": entry.canonical_symbol.rsplit("::", 1)[-1]},
            "return_annotation": "None",
            "return_fingerprints": [],
        }
    )
    discovered["normalizations"].append(
        {
            "caller": symbol,
            "call_name": "strip",
            "parameter_origins": ["parameter:value"],
            "line": 9,
        }
    )

    report = scan.evaluate_discovery(discovered, registry)

    assert any(
        value["kind"] == "downstream_normalization" and value["symbol"] == symbol
        for value in report["violations"]
    )


def test_fail_closed_dynamic_flow_is_causal() -> None:
    discovered, registry = _current_inventory_and_registry()
    discovered["unresolved"].append(
        {
            "kind": "dynamic_call",
            "symbol": "bcf_governance/tooling/rogue.py::execute",
            "line": 3,
        }
    )
    strict = dataclasses.replace(registry, unresolved_dynamic_policy="fail_closed")

    report = scan.evaluate_discovery(discovered, strict)

    assert any(
        value["semantic_id"] == "unresolved.dynamic-flow.v1"
        and value["kind"] == "dynamic_call"
        for value in report["violations"]
    )


def test_registry_rejects_competing_semantic_ids(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / "schemas").mkdir()
    payload = yaml.safe_load(
        (REPO_ROOT / "governance/canonical-representations.yml").read_text(
            encoding="utf-8"
        )
    )
    duplicate = dict(payload["representations"][0])
    duplicate["semantic_id"] = "governance.duplicate-session.v1"
    duplicate["family"] = "evidence_session_identity"
    payload["representations"].append(duplicate)
    (repo / "governance/canonical-representations.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )
    (repo / "schemas/canonical-representations.schema.json").write_bytes(
        (REPO_ROOT / "schemas/canonical-representations.schema.json").read_bytes()
    )

    with pytest.raises(SemanticOwnershipRegistryError, match="competing semantic IDs"):
        load_registry(repo)


def test_registry_owner_mutation_fails_for_declared_cause() -> None:
    discovered, registry = _current_inventory_and_registry()
    first = dataclasses.replace(
        registry.entries[0],
        owner_symbol="bcf_governance/tooling/missing.py::owner",
        authorized_constructors=frozenset(
            {"bcf_governance/tooling/missing.py::owner"}
        ),
    )
    mutated = dataclasses.replace(registry, entries=(first, *registry.entries[1:]))

    report = scan.evaluate_discovery(discovered, mutated)

    assert any(
        value["kind"] == "registry_owner_not_discovered"
        and value["symbol"] == "bcf_governance/tooling/missing.py::owner"
        for value in report["violations"]
    )


def test_standard_declared_family_requires_enforced_blocking_entry() -> None:
    discovered, registry = _current_inventory_and_registry()
    first = dataclasses.replace(registry.entries[0], lifecycle="planned")
    mutated = dataclasses.replace(registry, entries=(first, *registry.entries[1:]))

    report = scan.evaluate_discovery(discovered, mutated)

    assert any(
        value["kind"] == "declared_family_not_enforced"
        and value["semantic_id"] == first.semantic_id
        for value in report["violations"]
    )


def test_repository_wide_mode_requires_every_discovered_type() -> None:
    discovered, registry = _current_inventory_and_registry()
    unregistered = "bcf_governance/tooling/rogue.py::UnregisteredSemanticType"
    discovered["types"].append(unregistered)
    strict = dataclasses.replace(registry, mode="repository_wide_blocking")

    report = scan.evaluate_discovery(discovered, strict)

    assert any(
        value["kind"] == "unregistered_canonical_type"
        and value["symbol"] == unregistered
        for value in report["violations"]
    )
