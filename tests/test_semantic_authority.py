from __future__ import annotations

import copy
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import semantic_authority_migrations as migrations
from bcf_governance.tooling import semantic_authority_commands as commands
from bcf_governance.tooling import semantic_ownership_scan as scan
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from bcf_governance.tooling.semantic_ownership_registry import load_registry


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_contracts():
    module_path = os.environ.get("BCF_SEMANTIC_AUTHORITY_MODULE_PATH")
    if module_path is None:
        from bcf_governance.tooling import semantic_authority_contracts

        return semantic_authority_contracts
    spec = importlib.util.spec_from_file_location(
        "semantic_authority_contracts", Path(module_path)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load semantic authority module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contracts = _load_contracts()
SemanticAuthorityError = contracts.SemanticAuthorityError


def _yaml(relative: str) -> dict:
    return yaml.safe_load((REPO_ROOT / relative).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def source_inventory() -> dict:
    return discover_python_source(REPO_ROOT)


def test_bcf_declares_every_semantic_family_and_public_operation_once(
    source_inventory: dict,
) -> None:
    registry = load_registry(REPO_ROOT)

    structure = contracts.validate_semantic_contract_structure(REPO_ROOT, registry)
    evaluation = contracts.validate_semantic_authority(
        REPO_ROOT, source_inventory, registry
    )

    assert structure == {"families": 21, "operations": 19}
    assert evaluation.family_count == 21
    assert evaluation.operation_count == 19
    assert evaluation.derived_count == 60
    assert evaluation.exception_count == 0


def test_omitted_family_is_rejected(source_inventory: dict) -> None:
    payload = _yaml("governance/semantic-families.yml")
    payload["families"].pop()

    with pytest.raises(SemanticAuthorityError, match="outside semantic families"):
        contracts._validate_families(
            REPO_ROOT, payload, load_registry(REPO_ROOT), source_inventory
        )


def test_duplicate_family_is_rejected(source_inventory: dict) -> None:
    payload = _yaml("governance/semantic-families.yml")
    payload["families"].append(copy.deepcopy(payload["families"][0]))

    with pytest.raises(SemanticAuthorityError, match="semantic family IDs must be unique"):
        contracts._validate_families(
            REPO_ROOT, payload, load_registry(REPO_ROOT), source_inventory
        )


def test_contradictory_family_significance_is_rejected(source_inventory: dict) -> None:
    payload = _yaml("governance/semantic-families.yml")
    payload["families"][0]["id"] = "wrong_family"

    with pytest.raises(SemanticAuthorityError, match="contradicts"):
        contracts._validate_families(
            REPO_ROOT, payload, load_registry(REPO_ROOT), source_inventory
        )


def test_unclassified_operation_is_rejected(source_inventory: dict) -> None:
    payload = _yaml("governance/application-operations.yml")
    payload["operations"].pop()

    with pytest.raises(SemanticAuthorityError, match="unclassified public application operations"):
        contracts._validate_operations(REPO_ROOT, payload, source_inventory)


def test_multiply_classified_operation_is_rejected(source_inventory: dict) -> None:
    payload = _yaml("governance/application-operations.yml")
    duplicate = copy.deepcopy(payload["operations"][0])
    duplicate["id"] = "governance.cli.duplicate.v1"
    payload["operations"].append(duplicate)

    with pytest.raises(SemanticAuthorityError, match="multiply classified"):
        contracts._validate_operations(REPO_ROOT, payload, source_inventory)


def test_stale_operation_is_rejected(source_inventory: dict) -> None:
    payload = _yaml("governance/application-operations.yml")
    payload["operations"][0]["population_key"] = "removed-command"

    with pytest.raises(SemanticAuthorityError, match="is stale"):
        contracts._validate_operations(REPO_ROOT, payload, source_inventory)


@pytest.mark.parametrize("operation_id", ["governance.cli.doctor.v1", "governance.cli.publish-audit.v1"])
def test_read_side_cannot_mutate_or_confer_authority(
    operation_id: str, source_inventory: dict
) -> None:
    payload = _yaml("governance/application-operations.yml")
    operation = next(row for row in payload["operations"] if row["id"] == operation_id)
    operation["authority_conferral"] = True

    with pytest.raises(SemanticAuthorityError, match="cannot mutate or confer authority"):
        contracts._validate_operations(REPO_ROOT, payload, source_inventory)


def test_model_callable_operation_cannot_confer_authority(source_inventory: dict) -> None:
    payload = _yaml("governance/application-operations.yml")
    operation = next(row for row in payload["operations"] if row["id"] == "governance.cli.ci-github.v1")
    operation["model_callable"] = True

    with pytest.raises(SemanticAuthorityError, match="model-callable operation"):
        contracts._validate_operations(REPO_ROOT, payload, source_inventory)


def test_command_mutation_requires_declared_port(source_inventory: dict) -> None:
    payload = _yaml("governance/application-operations.yml")
    operation = next(row for row in payload["operations"] if row["id"] == "governance.cli.install.v1")
    operation["allowed_mutation_ports"] = []

    with pytest.raises(SemanticAuthorityError, match="requires a declared mutation port"):
        contracts._validate_operations(REPO_ROOT, payload, source_inventory)


def test_declared_operation_port_must_be_reachable(source_inventory: dict) -> None:
    payload = _yaml("governance/application-operations.yml")
    operation = next(
        row for row in payload["operations"] if row["id"] == "governance.cli.install.v1"
    )
    operation["allowed_mutation_ports"] = [
        "bcf_governance/tooling/install_governance_pack.py::missing_port"
    ]

    with pytest.raises(SemanticAuthorityError, match="unreachable effect ports"):
        contracts._validate_operations(REPO_ROOT, payload, source_inventory)


def test_query_implementation_cannot_hide_a_write(source_inventory: dict) -> None:
    payload = _yaml("governance/application-operations.yml")
    mutated = copy.deepcopy(source_inventory)
    function = next(
        row for row in mutated["functions"]
        if row["symbol"] == "bcf_governance/tooling/doctor_governance_pack.py::main"
    )
    function["calls"].append({
        "called_symbol": "bcf_governance/tooling/doctor_governance_pack.py::state.write_text",
        "call_name": "write_text",
    })

    with pytest.raises(SemanticAuthorityError, match="undeclared write effects"):
        contracts._validate_operations(REPO_ROOT, payload, mutated)


def test_query_cannot_hide_a_write_behind_an_imported_helper(
    source_inventory: dict,
) -> None:
    payload = _yaml("governance/application-operations.yml")
    mutated = copy.deepcopy(source_inventory)
    function = next(
        row for row in mutated["functions"]
        if row["symbol"] == "bcf_governance/tooling/doctor_governance_pack.py::main"
    )
    helper_symbol = "bcf_governance/tooling/query_fixture_helper.py::inspect"
    function["calls"].append({"called_symbol": helper_symbol, "call_name": "inspect"})
    mutated["functions"].append({
        "symbol": helper_symbol,
        "calls": [{
            "called_symbol": "bcf_governance/tooling/query_fixture_helper.py::state.write_text",
            "call_name": "write_text",
        }],
        "unresolved": [],
    })

    with pytest.raises(SemanticAuthorityError, match="undeclared write effects"):
        contracts._validate_operations(REPO_ROOT, payload, mutated)


def test_projection_implementation_cannot_confer_authority(
    source_inventory: dict,
) -> None:
    payload = _yaml("governance/application-operations.yml")
    mutated = copy.deepcopy(source_inventory)
    function = next(
        row for row in mutated["functions"]
        if row["symbol"] == "bcf_governance/tooling/publish_audit.py::main"
    )
    function["calls"].append({
        "called_symbol": "bcf_governance/tooling/publish_audit.py::publish_status",
        "call_name": "publish_status",
    })

    with pytest.raises(SemanticAuthorityError, match="undeclared authority effects"):
        contracts._validate_operations(REPO_ROOT, payload, mutated)


def test_dynamic_operation_path_fails_closed(source_inventory: dict) -> None:
    payload = _yaml("governance/application-operations.yml")
    mutated = copy.deepcopy(source_inventory)
    function = next(
        row for row in mutated["functions"]
        if row["symbol"] == "bcf_governance/tooling/doctor_governance_pack.py::main"
    )
    function["unresolved"].append({"kind": "dynamic_call", "line": 1})

    with pytest.raises(SemanticAuthorityError, match="unresolved dynamic call path"):
        contracts._validate_operations(REPO_ROOT, payload, mutated)


def test_source_population_cannot_be_evaded_by_path_placement(
    source_inventory: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _yaml("governance/application-operations.yml")
    original = contracts._discover_population

    def discover(repo_root: Path, population: dict) -> dict[str, str]:
        found = original(repo_root, population)
        return {**found, "path-hidden-command": "bcf_governance/tooling/doctor_governance_pack.py::main"}

    monkeypatch.setattr(contracts, "_discover_population", discover)
    with pytest.raises(SemanticAuthorityError, match="path-hidden-command"):
        contracts._validate_operations(REPO_ROOT, payload, source_inventory)


@pytest.mark.parametrize(
    ("adapter", "source_text", "extra", "expected"),
    [
        (
            "python_decorators",
            "def governed(fn): return fn\n@governed\ndef execute(): pass\n",
            {"decorators": ["governed"]},
            {"execute"},
        ),
        (
            "python_module_exports",
            "__all__ = ['execute']\ndef execute(): pass\ndef _private(): pass\n",
            {},
            {"execute"},
        ),
        (
            "canonical_yaml_catalog",
            "operations:\n  execute: application.execute\n",
            {"catalog_path": ["operations"]},
            {"execute"},
        ),
        (
            "typescript_exports",
            "export function execute(): void {}\nconst hidden = 1;\n",
            {
                "tsconfig": "tsconfig.json",
                "package_lock": "package-lock.json",
                "node_executable": "node",
            },
            {"execute"},
        ),
    ],
)
def test_operation_population_adapters_are_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter: str,
    source_text: str,
    extra: dict,
    expected: set[str],
) -> None:
    suffix = ".yml" if adapter == "canonical_yaml_catalog" else (
        ".ts" if adapter == "typescript_exports" else ".py"
    )
    source = tmp_path / f"operations{suffix}"
    source.write_text(source_text, encoding="utf-8")
    if adapter == "typescript_exports":
        (tmp_path / "tsconfig.json").write_text("{}\n", encoding="utf-8")
        (tmp_path / "package-lock.json").write_text(
            json.dumps({
                "packages": {"node_modules/typescript": {"version": "6.0.3"}}
            }) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "bcf_governance.tooling.semantic_operation_typescript.discover_typescript_source",
            lambda *_args, **_kwargs: {
                "public_exports": [{
                    "name": "execute",
                    "symbol": "operations.ts::execute",
                }]
            },
        )
    population = {
        "id": "fixture",
        "adapter": adapter,
        "source": source.name,
        "symbol": "__all__",
        "public_only": True,
        **extra,
    }

    assert set(contracts._discover_population(tmp_path, population)) == expected


@pytest.mark.parametrize(
    ("adapter", "source_name", "source_text", "extra"),
    [
        (
            "python_decorators",
            "operations.py",
            "def governed(fn): return fn\n@governed\ndef execute(): pass\n@governed\ndef execute(): pass\n",
            {"decorators": ["governed"]},
        ),
        (
            "python_module_exports",
            "operations.py",
            "__all__ = ['execute', 'execute']\ndef execute(): pass\n",
            {},
        ),
        (
            "canonical_yaml_catalog",
            "operations.yml",
            "operations:\n- {id: execute, entrypoint: first}\n- {id: execute, entrypoint: second}\n",
            {"catalog_path": ["operations"]},
        ),
    ],
)
def test_operation_population_adapters_reject_duplicate_public_identities(
    tmp_path: Path,
    adapter: str,
    source_name: str,
    source_text: str,
    extra: dict,
) -> None:
    (tmp_path / source_name).write_text(source_text, encoding="utf-8")
    population = {
        "id": "fixture",
        "adapter": adapter,
        "source": source_name,
        "symbol": "__all__",
        "public_only": True,
        **extra,
    }

    with pytest.raises(SemanticAuthorityError, match="duplicates|must be unique"):
        contracts._discover_population(tmp_path, population)


def test_yaml_operation_population_rejects_duplicate_mapping_keys(
    tmp_path: Path,
) -> None:
    (tmp_path / "operations.yml").write_text(
        "operations:\n  execute: first\n  execute: second\n", encoding="utf-8"
    )

    with pytest.raises(SemanticAuthorityError, match="duplicate YAML key: execute"):
        contracts._discover_population(
            tmp_path,
            {
                "id": "fixture",
                "adapter": "canonical_yaml_catalog",
                "source": "operations.yml",
                "symbol": "catalog",
                "public_only": True,
                "catalog_path": ["operations"],
            },
        )


def test_typescript_population_rejects_duplicate_public_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "operations.ts").write_text(
        "export function execute(): void {}\n", encoding="utf-8"
    )
    (tmp_path / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/typescript": {"version": "6.0.3"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.semantic_operation_typescript.discover_typescript_source",
        lambda *_args, **_kwargs: {
            "public_exports": [
                {"name": "execute", "symbol": "operations.ts::first"},
                {"name": "execute", "symbol": "operations.ts::second"},
            ]
        },
    )

    with pytest.raises(SemanticAuthorityError, match="duplicates execute"):
        contracts._discover_population(
            tmp_path,
            {
                "id": "fixture",
                "adapter": "typescript_exports",
                "source": "operations.ts",
                "symbol": "exports",
                "public_only": True,
                "tsconfig": "tsconfig.json",
                "package_lock": "package-lock.json",
                "node_executable": "node",
            },
        )


def test_semantic_scaffold_is_explicitly_non_authoritative(tmp_path: Path) -> None:
    output = tmp_path / "candidate.yml"

    commands._scaffold(REPO_ROOT, output)

    payload = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert payload["document"]["authority"] == (
        "non_authoritative_until_complete_adoption"
    )
    assert set(payload["contracts"]) == {
        "semantic_families",
        "application_operations",
        "canonical_representations",
    }


def test_stale_generated_projection_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    mirror = tmp_path / "mirror.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    mirror.write_text("VALUE = 2\n", encoding="utf-8")
    registry = load_registry(REPO_ROOT)
    entry = dataclasses.replace(
        registry.entries[0],
        raw={
            **registry.entries[0].raw,
            "generated_source_authority": {
                "authoritative_roots": ["source.py"],
                "generated_mirrors": ["mirror.py"],
                "generator": "generator",
                "parity_proof": "parity",
            },
        },
    )

    with pytest.raises(contracts.SemanticDerivationError, match="stale generated projection"):
        contracts._legacy_generated_projections(
            tmp_path, dataclasses.replace(registry, entries=(entry,))
        )


def test_competing_generated_provenance_is_rejected(tmp_path: Path) -> None:
    for name in ("one.py", "two.py", "mirror.py"):
        (tmp_path / name).write_text("VALUE = 1\n", encoding="utf-8")
    registry = load_registry(REPO_ROOT)
    entries = []
    for source, generator, original in zip(
        ("one.py", "two.py"), ("one", "two"), registry.entries[:2], strict=True
    ):
        entries.append(dataclasses.replace(original, raw={
            **original.raw,
            "generated_source_authority": {
                "authoritative_roots": [source], "generated_mirrors": ["mirror.py"],
                "generator": generator, "parity_proof": "parity",
            },
        }))

    with pytest.raises(contracts.SemanticDerivationError, match="competing provenance"):
        contracts._legacy_generated_projections(
            tmp_path, dataclasses.replace(registry, entries=tuple(entries))
        )


def _tracked_derivation_registry(tmp_path: Path):
    (tmp_path / "source.json").write_text('{"value": 1}\n', encoding="utf-8")
    (tmp_path / "generate.py").write_text(
        """import json
from pathlib import Path
value = json.loads(Path('source.json').read_text(encoding='utf-8'))
Path('projection.json').write_text(json.dumps(value, sort_keys=True) + '\\n', encoding='utf-8')
""",
        encoding="utf-8",
    )
    (tmp_path / "projection.json").write_text('{"value": 1}\n', encoding="utf-8")
    registry = load_registry(REPO_ROOT)
    raw = copy.deepcopy(registry.raw)
    raw["secondary_representations"] = [{
        "id": "governance.test-projection.v1",
        "classification": "derived",
        "canonical_semantic_id": registry.entries[0].semantic_id,
        "derivation_kind": "exact_generated_projection",
        "source_inputs": ["source.json"],
        "outputs": ["projection.json"],
        "recipe": {"kind": "tracked_command", "argv": ["python3", "generate.py"]},
        "migration_owner": "test-maintainer",
        "direct_edit_policy": "prohibited",
    }]
    return dataclasses.replace(registry, raw=raw)


def test_tracked_derivation_reproduces_declared_output(tmp_path: Path) -> None:
    registry = _tracked_derivation_registry(tmp_path)

    projections, derived_count, exception_count = contracts._validate_explicit_provenance(
        tmp_path, registry, {"functions": []}
    )

    assert [row["path"] for row in projections] == ["projection.json"]
    assert derived_count == 1
    assert exception_count == 0


def test_direct_edit_to_derived_projection_is_rejected(tmp_path: Path) -> None:
    registry = _tracked_derivation_registry(tmp_path)
    (tmp_path / "projection.json").write_text('{"value":2}\n', encoding="utf-8")

    with pytest.raises(contracts.SemanticDerivationError, match="cannot reproduce projection.json"):
        contracts._validate_explicit_provenance(tmp_path, registry, {"functions": []})


def test_material_secondary_representation_requires_provenance(source_inventory: dict) -> None:
    families = _yaml("governance/semantic-families.yml")
    families["families"][0]["material_selectors"]["secondary_paths"] = ["README.md"]
    registry = load_registry(REPO_ROOT)
    provenance = contracts.collect_representation_provenance(
        REPO_ROOT, registry, source_inventory
    )

    with pytest.raises(SemanticAuthorityError, match="lacks derivation provenance"):
        contracts._validate_secondary_coverage(families, registry, provenance)


def test_unsafe_generator_argv_is_rejected(source_inventory: dict) -> None:
    registry = load_registry(REPO_ROOT)
    registry.raw["secondary_representations"] = [{
        "id": "governance.unsafe-projection.v1",
        "classification": "derived",
        "canonical_semantic_id": registry.entries[0].semantic_id,
        "derivation_kind": "exact_generated_projection",
        "source_inputs": ["README.md"],
        "outputs": ["CHANGELOG.md"],
        "recipe": {"kind": "tracked_command", "argv": ["../escape.py"]},
        "migration_owner": "maintainer",
        "direct_edit_policy": "prohibited",
    }]

    with pytest.raises(contracts.SemanticDerivationError, match="program must be repository-relative"):
        contracts._validate_explicit_provenance(REPO_ROOT, registry, source_inventory)


def test_expired_representation_exception_is_rejected(source_inventory: dict) -> None:
    registry = load_registry(REPO_ROOT)
    registry.raw["secondary_representations"] = [{
        "id": "governance.expired-copy.v1",
        "classification": "exception",
        "locations": ["README.md"],
        "rationale": "temporary test exception",
        "accountable_owner": "test-maintainer",
        "issue": "https://example.invalid/expired-copy",
        "expires_on": "2000-01-01",
    }]

    with pytest.raises(contracts.SemanticDerivationError, match="is expired"):
        contracts._validate_explicit_provenance(REPO_ROOT, registry, source_inventory)


def test_secondary_exception_locations_have_one_owner(source_inventory: dict) -> None:
    registry = load_registry(REPO_ROOT)
    exception = {
        "id": "governance.first-copy.v1",
        "classification": "exception",
        "locations": ["README.md"],
        "rationale": "temporary test exception",
        "accountable_owner": "test-maintainer",
        "issue": "https://example.invalid/first-copy",
        "re_review_trigger": "next release",
    }
    duplicate = {**exception, "id": "governance.second-copy.v1"}
    registry.raw["secondary_representations"] = [exception, duplicate]

    with pytest.raises(contracts.SemanticDerivationError, match="owned by both"):
        contracts._validate_explicit_provenance(REPO_ROOT, registry, source_inventory)


def test_legacy_and_explicit_provenance_cannot_claim_the_same_output(
    tmp_path: Path,
) -> None:
    registry = _tracked_derivation_registry(tmp_path)
    entries = list(registry.entries)
    entries[0] = dataclasses.replace(
        entries[0],
        raw={
            **entries[0].raw,
            "generated_source_authority": {
                "authoritative_roots": ["source.json"],
                "generated_mirrors": ["projection.json"],
                "generator": "legacy-generator",
                "parity_proof": "byte parity",
            },
        },
    )

    with pytest.raises(SemanticAuthorityError, match="competing legacy"):
        contracts.collect_representation_provenance(
            tmp_path,
            dataclasses.replace(registry, entries=(entries[0],)),
            {"functions": []},
        )


def test_overbroad_representation_exception_path_is_rejected(
    source_inventory: dict,
) -> None:
    registry = load_registry(REPO_ROOT)
    registry.raw["secondary_representations"] = [{
        "id": "governance.overbroad-copy.v1",
        "classification": "exception",
        "locations": ["docs"],
        "rationale": "temporary test exception",
        "accountable_owner": "test-maintainer",
        "issue": "https://example.invalid/overbroad-copy",
        "re_review_trigger": "next release",
    }]

    with pytest.raises(contracts.SemanticDerivationError, match="regular file"):
        contracts._validate_explicit_provenance(REPO_ROOT, registry, source_inventory)


def test_runtime_derivation_requires_an_authorized_source_first_role(
    tmp_path: Path,
) -> None:
    (tmp_path / "canonical.txt").write_text("canonical\n", encoding="utf-8")
    (tmp_path / "runtime.txt").write_text("runtime\n", encoding="utf-8")
    registry = load_registry(REPO_ROOT)
    canonical = registry.entries[0]
    raw = copy.deepcopy(registry.raw)
    raw["secondary_representations"] = [{
        "id": "governance.runtime-copy.v1",
        "classification": "derived",
        "canonical_semantic_id": canonical.semantic_id,
        "derivation_kind": "runtime_constructor",
        "source_inputs": ["canonical.txt"],
        "outputs": ["runtime.txt"],
        "recipe": {
            "kind": "runtime_symbol",
            "symbol": "example/runtime.py::unauthorized_constructor",
        },
        "migration_owner": "test-maintainer",
        "direct_edit_policy": "prohibited",
    }]
    test_registry = dataclasses.replace(
        registry, entries=(canonical,), raw=raw
    )
    inventory = {
        "functions": [{"symbol": "example/runtime.py::unauthorized_constructor"}]
    }

    with pytest.raises(contracts.SemanticDerivationError, match="not an authorized"):
        contracts._validate_explicit_provenance(tmp_path, test_registry, inventory)


def test_semantic_lock_is_idempotent_and_source_bound(source_inventory: dict) -> None:
    registry = load_registry(REPO_ROOT)
    evaluation = contracts.validate_semantic_authority(
        REPO_ROOT, source_inventory, registry, require_lock=False
    )

    first = contracts.build_semantic_lock(REPO_ROOT, source_inventory, evaluation.projection_outputs)
    second = contracts.build_semantic_lock(REPO_ROOT, source_inventory, evaluation.projection_outputs)

    assert first == second
    assert first["source_inventory_sha256"] == hashlib.sha256(
        json.dumps(
            contracts._semantic_source_rows(REPO_ROOT),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def test_scan_builds_the_python_inventory_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    original = scan.discover_python_source

    def discover(repo_root: Path) -> dict:
        nonlocal calls
        calls += 1
        return original(repo_root)

    monkeypatch.setattr(scan, "discover_python_source", discover)
    report = scan.run_scan(REPO_ROOT)

    assert report["verdict"] == "conformant"
    assert calls == 1


def _migration_key(
    kind: str, subject_id: str, change: str, base: str, previous: object, current: object
) -> tuple[str, ...]:
    return (
        kind,
        subject_id,
        change,
        base,
        migrations._stable_digest(previous),
        migrations._stable_digest(current),
    )


def test_family_downgrade_requires_exact_base_migration() -> None:
    base = "1" * 40
    previous = {
        "id": "family",
        "significance": "authoritative",
        "ownership_required": True,
        "canonical_semantic_ids": ["semantic.v1"],
    }
    current = {**previous, "significance": "descriptive"}
    old = {"families": [previous]}
    new = {"families": [current]}

    with pytest.raises(migrations.SemanticMigrationError, match="exact-base"):
        migrations._family_changes(old, new, set(), base)
    migrations._family_changes(
        old,
        new,
        {_migration_key("family", "family", "downgraded", base, previous, current)},
        base,
    )


def test_operation_effect_change_requires_exact_base_migration() -> None:
    base = "2" * 40
    previous = {
        "id": "operation.v1",
        "semantic_kind": "query",
        "authoritative_read": True,
        "authoritative_mutation": False,
        "authority_conferral": False,
        "produces_projection": False,
        "model_callable": False,
        "allowed_mutation_ports": [],
        "allowed_authority_ports": [],
    }
    current = {**previous, "authoritative_read": False}
    old = {"operations": [previous]}
    new = {"operations": [current]}

    with pytest.raises(migrations.SemanticMigrationError, match="exact-base"):
        migrations._operation_changes(old, new, set(), base)
    migrations._operation_changes(
        old,
        new,
        {
            _migration_key(
                "operation", "operation.v1", "effect_changed", base, previous, current
            )
        },
        base,
    )


def test_derivation_recipe_change_requires_exact_base_migration() -> None:
    base = "3" * 40
    previous = {"id": "projection", "classification": "derived", "recipe": "old"}
    current = {"id": "projection", "classification": "derived", "recipe": "new"}
    registry = load_registry(REPO_ROOT)
    changed_registry = dataclasses.replace(
        registry, raw={**registry.raw, "secondary_representations": [current]}
    )
    old = {"representations": [], "secondary_representations": [previous]}

    with pytest.raises(migrations.SemanticMigrationError, match="exact-base"):
        migrations._representation_changes(old, changed_registry, set(), base)
    migrations._representation_changes(
        old,
        changed_registry,
        {
            _migration_key(
                "representation", "projection", "recipe_changed", base, previous, current
            )
        },
        base,
    )
