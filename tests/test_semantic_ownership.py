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
        "files": [{"path": "fixture.py", "sha256": "0" * 64}],
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
        raw={"source_authority": {"typescript_engine": "not_applicable_until_declared_by_consumer"}},
    )
    monkeypatch.setattr(
        scan, "discover_python_source", lambda _: (events.append("discovery") or source)
    )
    monkeypatch.setattr(
        scan, "load_registry", lambda _: (events.append("registry") or registry)
    )
    monkeypatch.setattr(
        scan,
        "resolve_python_imports",
        lambda _root, value, _roots: (events.append("import-root-resolution") or value),
    )
    monkeypatch.setattr(
        scan,
        "tracked_typescript_files",
        lambda _: (events.append("typescript-discovery") or []),
    )

    report = scan.run_scan(tmp_path)

    assert events == [
        "discovery",
        "typescript-discovery",
        "registry",
        "import-root-resolution",
    ]
    assert report["subject"]["discovery_preceded_registry_load"] is True


def test_candidate_source_inventory_includes_additions_and_excludes_deletions(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "owned.py").write_text("def owned() -> str:\n    return 'owned'\n", encoding="utf-8")
    (repo / "retired.py").write_text("def retired():\n    pass\n", encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "soip@example.test")
    _git(repo, "config", "user.name", "SOIP Test")
    _git(repo, "add", "owned.py", "retired.py")
    _git(repo, "commit", "-m", "owned source")
    (repo / "untracked.py").write_text("def hidden():\n    pass\n", encoding="utf-8")
    (repo / "retired.py").unlink()

    discovered = inventory.discover_python_source(repo)

    assert [value["path"] for value in discovered["files"]] == [
        "owned.py",
        "untracked.py",
    ]


def test_current_bcf_registry_is_conformant_and_report_is_compact(tmp_path: Path) -> None:
    report = scan.run_scan(REPO_ROOT)
    registry = load_registry(REPO_ROOT)
    encoded = json.dumps(report, sort_keys=True).encode()

    assert report["verdict"] == "conformant"
    assert report["blocking_violation_count"] == 0
    assert {value["semantic_id"] for value in report["registry_coverage"]} == {
        entry.semantic_id for entry in registry.entries
    }
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


def test_primary_semantic_violation_precedes_derived_lock_freshness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovered, registry = _current_inventory_and_registry()
    evaluation = scan.evaluate_discovery(discovered, registry)
    evaluation = {
        **evaluation,
        "verdict": "non_conformant",
        "blocking_violation_count": 1,
        "violations": [
            {
                "semantic_id": registry.entries[0].semantic_id,
                "kind": "downstream_normalization",
                "blocking": True,
            }
        ],
    }
    observed_lock_requirements: list[bool] = []
    original_validate = scan.validate_semantic_authority

    monkeypatch.setattr(scan, "evaluate_discovery", lambda *_args: evaluation)

    def validate(*args: object, require_lock: bool = True, **kwargs: object):
        observed_lock_requirements.append(require_lock)
        return original_validate(*args, require_lock=False, **kwargs)

    monkeypatch.setattr(scan, "validate_semantic_authority", validate)

    report = scan.run_scan(REPO_ROOT)

    assert report["verdict"] == "non_conformant"
    assert observed_lock_requirements == [False]


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


def test_retry_executor_context_authorization_is_declared_and_causal():
    registry = load_registry(REPO_ROOT)
    semantic_id = 'governance.local-pr-context.v1'
    entry = next(row for row in registry.entries if row.semantic_id == semantic_id)
    consumer = 'bcf_governance/tooling/candidate_provider_recovery.py::execute_candidate_provider_recovery'
    assert consumer in entry.raw['declared_consumer_layers_and_sinks']['authorization']
    assert consumer not in entry.authorized_constructors | entry.authorized_delegates
    assert entry.raw['narrow_suppressions'] == []
    files = [REPO_ROOT / 'bcf_governance/tooling/local_pr_context.py',
             REPO_ROOT / 'bcf_governance/tooling/candidate_provider_recovery.py']
    discovered = inventory.discover_python_source(REPO_ROOT, files=files)
    selected = dataclasses.replace(registry, entries=(entry,))
    assert not [v for v in scan.evaluate_discovery(discovered, selected)['violations']
                if v['kind'] == 'downstream_normalization' and v['symbol'] == consumer]
    import copy
    removed = copy.deepcopy(entry.raw)
    removed['declared_consumer_layers_and_sinks']['authorization'].remove(consumer)
    without = dataclasses.replace(selected, entries=(dataclasses.replace(entry, raw=removed),))
    violations = scan.evaluate_discovery(discovered, without)['violations']
    assert any(v['kind'] == 'downstream_normalization' and v['symbol'] == consumer for v in violations)


def test_authored_semantic_scan_checks_ownership_without_generated_lock(tmp_path, monkeypatch):
    (tmp_path / 'governance').mkdir()
    (tmp_path / 'governance/canonical-representations.yml').write_text('declared')
    sentinel = ({}, {}, {}, object())
    monkeypatch.setattr(scan, '_discover_ownership_inputs', lambda root, **kwargs: sentinel, raising=False)
    monkeypatch.setattr(scan, 'evaluate_discovery', lambda *args: {'verdict': 'conformant', 'blocking_violation_count': 0, 'violations': []})
    monkeypatch.setattr(scan, 'validate_semantic_authority', lambda *_a, **_k: pytest.fail('checked stale generated lock before generation'))
    report = scan.validate_authored_semantic_ownership(tmp_path)
    assert report['authority'] is False and report['execution_qualified'] is False
    assert report['scope'] == 'authored_python_semantic_ownership_only'


def test_authored_semantic_scan_rejects_unregistered_source_consumer(tmp_path, monkeypatch):
    (tmp_path / 'governance').mkdir()
    (tmp_path / 'governance/canonical-representations.yml').write_text('declared')
    monkeypatch.setattr(scan, '_discover_ownership_inputs', lambda root, **kwargs: ({}, {}, {}, object()), raising=False)
    monkeypatch.setattr(scan, 'evaluate_discovery', lambda *args: {'verdict': 'non_conformant',
        'blocking_violation_count': 1, 'violations': [{'kind': 'downstream_normalization', 'symbol': 'actual::consumer', 'blocking': True}]})
    with pytest.raises(SemanticOwnershipRegistryError, match='downstream_normalization:actual::consumer'):
        scan.validate_authored_semantic_ownership(tmp_path)


def test_authored_python_scope_preserves_full_registry_and_needs_no_typescript_toolchain(monkeypatch):
    registry = load_registry(REPO_ROOT)
    python_entry = next(entry for entry in registry.entries if entry.raw['canonical_type']['language'] == 'python')
    ts_entry = dataclasses.replace(python_entry, semantic_id='fixture.typescript',
        canonical_symbol='src/domain.ts::Message', raw={'canonical_type': {'language': 'typescript'}})
    mixed = dataclasses.replace(registry, entries=(python_entry, ts_entry))
    python = {'files': [], 'functions': [], 'constructors': [], 'normalizations': [], 'types': []}
    monkeypatch.setattr(scan, 'discover_python_source', lambda root: python)
    monkeypatch.setattr(scan, 'load_registry', lambda root: mixed)
    monkeypatch.setattr(scan, 'resolve_python_imports', lambda root, data, roots: data)
    monkeypatch.setattr(scan, 'tracked_typescript_files', lambda *_a: pytest.fail('required unavailable TypeScript before admission'))
    monkeypatch.setattr(scan, 'discover_source', lambda *_a, **_k: pytest.fail('compiled TypeScript before toolchain admission'))
    _, observed, typescript, qualified = scan._discover_ownership_inputs(REPO_ROOT, python_only=True)
    assert observed is python and typescript == {}
    assert qualified.entries == (python_entry,)
    assert mixed.entries == (python_entry, ts_entry)


def test_protected_merge_context_authorization_is_declared_and_causal():
    registry = load_registry(REPO_ROOT)
    semantic_id = 'governance.local-pr-context.v1'
    entry = next(row for row in registry.entries if row.semantic_id == semantic_id)
    consumer = 'bcf_governance/tooling/ci_authority_submit.py::_request_protected_auto_merge'
    assert consumer in entry.raw['declared_consumer_layers_and_sinks']['authorization']
    assert consumer not in entry.authorized_constructors | entry.authorized_delegates
    assert entry.raw['narrow_suppressions'] == []
    files = [REPO_ROOT / 'bcf_governance/tooling/local_pr_context.py',
             REPO_ROOT / 'bcf_governance/tooling/ci_authority_submit.py']
    discovered = inventory.discover_python_source(REPO_ROOT, files=files)
    selected = dataclasses.replace(registry, entries=(entry,))
    assert not [v for v in scan.evaluate_discovery(discovered, selected)['violations']
                if v['kind'] == 'downstream_normalization' and v['symbol'] == consumer]
    import copy
    removed = copy.deepcopy(entry.raw)
    removed['declared_consumer_layers_and_sinks']['authorization'].remove(consumer)
    without = dataclasses.replace(selected, entries=(dataclasses.replace(entry, raw=removed),))
    violations = scan.evaluate_discovery(discovered, without)['violations']
    assert any(v['kind'] == 'downstream_normalization' and v['symbol'] == consumer for v in violations)


def test_normalization_context_authorization_is_declared_and_causal():
    registry = load_registry(REPO_ROOT)
    semantic_id = 'governance.local-pr-context.v1'
    entry = next(row for row in registry.entries if row.semantic_id == semantic_id)
    consumer = 'bcf_governance/tooling/ci_authority_submit.py::_normalize_submission'
    assert consumer in entry.raw['declared_consumer_layers_and_sinks']['authorization']
    assert consumer not in entry.authorized_constructors | entry.authorized_delegates
    assert entry.raw['narrow_suppressions'] == []
    files = [REPO_ROOT / 'bcf_governance/tooling/local_pr_context.py',
             REPO_ROOT / 'bcf_governance/tooling/ci_authority_submit.py']
    discovered = inventory.discover_python_source(REPO_ROOT, files=files)
    selected = dataclasses.replace(registry, entries=(entry,))
    assert not [v for v in scan.evaluate_discovery(discovered, selected)['violations']
                if v['kind'] == 'downstream_normalization' and v['symbol'] == consumer]
    import copy
    removed = copy.deepcopy(entry.raw)
    removed['declared_consumer_layers_and_sinks']['authorization'].remove(consumer)
    without = dataclasses.replace(selected, entries=(dataclasses.replace(entry, raw=removed),))
    violations = scan.evaluate_discovery(discovered, without)['violations']
    assert any(v['kind'] == 'downstream_normalization' and v['symbol'] == consumer for v in violations)
