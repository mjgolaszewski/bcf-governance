from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import semantic_authority_commands as commands
from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError, build_semantic_lock, validate_semantic_authority
from bcf_governance.tooling.semantic_ownership_scan import run_scan
from bcf_governance.tooling.semantic_source_discovery import compiler_contracts, discover_source
from semantic_typescript_fixture import dump, git, repository, write


@pytest.mark.parametrize("package,engine,ts_family", [("", True, True), ("frontend", True, True), ("frontend", False, False), ("", False, True)])
def test_real_compiler_lock_scan_and_transactional_adoption(tmp_path: Path, package: str, engine: bool, ts_family: bool) -> None:
    repository(tmp_path, package=package, registry_engine=engine, typescript_family=ts_family)
    combined, python, typescript, registry = discover_source(tmp_path)
    assert python["functions"]
    assert len(compiler_contracts(tmp_path, registry)) == 1
    assert typescript["compiler_version"] == "6.0.3"
    prefix = package + "/" if package else ""
    assert {prefix + "src/value.ts::" + name for name in ("Value", "Shape", "ValueAlias")} <= set(combined["types"])
    commands._lock(tmp_path, apply=True)
    assert yaml.safe_load((tmp_path / "governance/semantic-lock.yml").read_text())["projection_outputs"] == []
    assert run_scan(tmp_path)["verdict"] == "conformant"
    before = {path: (tmp_path / path).read_bytes() for path in commands.MANAGED_PATHS}
    commands._adopt(tmp_path, tmp_path / "adopt.yml", apply=False)
    assert before == {path: (tmp_path / path).read_bytes() for path in commands.MANAGED_PATHS}
    commands._adopt(tmp_path, tmp_path / "adopt.yml", apply=True)
    commands._lock(tmp_path, apply=False)
    assert run_scan(tmp_path)["semantic_authority"]["operation_count"] == 1
    assert json.loads((tmp_path / prefix / "node_modules/@bcf-test/declared-types/package.json").read_text())["name"] == "@bcf-test/declared-types"


def test_alias_export_resolves_tracked_helper_and_method_identity(tmp_path: Path) -> None:
    payload = repository(tmp_path)
    write(tmp_path, "src/helper.ts", "class Service { read(): number { return 7; } }\nexport function internal(): number { return new Service().read(); }\n")
    write(tmp_path, "src/api.ts", "export { internal as query } from './helper.js';\n")
    payload["contracts"]["application_operations"]["operations"][0]["entrypoints"] = ["src/helper.ts::internal"]
    dump(tmp_path, "governance/application-operations.yml", payload["contracts"]["application_operations"])
    git(tmp_path, "add", "src", "governance/application-operations.yml")
    commands._lock(tmp_path, apply=True)
    combined, _, _, _ = discover_source(tmp_path)
    function = next(row for row in combined["functions"] if row["symbol"] == "src/helper.ts::internal")
    assert {row["called_symbol"] for row in function["calls"]} == {"src/helper.ts::Service.constructor", "src/helper.ts::Service.read"}
    assert run_scan(tmp_path)["verdict"] == "conformant"


@pytest.mark.parametrize("change", ["helper", "tsconfig", "lock", "exports"])
def test_typescript_lock_binds_full_source_and_compiler_inputs(tmp_path: Path, change: str) -> None:
    repository(tmp_path)
    write(tmp_path, "src/helper.ts", "export function helper(): number { return 1; }\n")
    git(tmp_path, "add", "src/helper.ts")
    commands._lock(tmp_path, apply=True)
    if change == "helper":
        write(tmp_path, "src/helper.ts", "export function helper(): number { return 2; }\n")
    elif change == "exports":
        write(tmp_path, "src/api.ts", "export function query(): number { return 1; }\nexport function extra(): number { return 2; }\n")
    else:
        path = tmp_path / ("tsconfig.json" if change == "tsconfig" else "package-lock.json")
        path.write_text(path.read_text() + "\n")
    with pytest.raises(SemanticAuthorityError, match="stale|unclassified public"):
        commands._lock(tmp_path, apply=False)


def test_missing_typescript_owner_and_failed_adoption_preserve_original_bytes(tmp_path: Path) -> None:
    payload = repository(tmp_path)
    commands._lock(tmp_path, apply=True)
    before = {path: hashlib.sha256((tmp_path / path).read_bytes()).hexdigest() for path in commands.MANAGED_PATHS}
    payload["contracts"]["application_operations"]["operations"][0]["entrypoints"] = ["src/api.ts::missing"]
    dump(tmp_path, "broken.yml", payload)
    with pytest.raises(SemanticAuthorityError, match="entrypoints must exactly match"):
        commands._adopt(tmp_path, tmp_path / "broken.yml", apply=True)
    assert before == {path: hashlib.sha256((tmp_path / path).read_bytes()).hexdigest() for path in commands.MANAGED_PATHS}
    raw = yaml.safe_load((tmp_path / "governance/semantic-families.yml").read_text())
    raw["families"][0]["material_selectors"]["symbols"] = ["src/value.ts::Missing"]
    dump(tmp_path, "governance/semantic-families.yml", raw)
    registry = yaml.safe_load((tmp_path / "governance/canonical-representations.yml").read_text())
    registry["representations"][0]["canonical_type"]["symbol"] = "src/value.ts::Missing"
    dump(tmp_path, "governance/canonical-representations.yml", registry)
    with pytest.raises(SemanticAuthorityError, match="absent from source inventory"):
        commands._lock(tmp_path, apply=True)


def test_population_and_registry_projects_are_composed_once_each(tmp_path: Path) -> None:
    from semantic_typescript_fixture import compiler
    payload = repository(tmp_path)
    nested = compiler(tmp_path, package="frontend")
    write(tmp_path, "frontend/src/api.ts", "export function query(): number { return 2; }\n")
    operations = payload["contracts"]["application_operations"]
    operations["populations"][0].update({key: nested[key] for key in ("node_executable", "tsconfig", "package_lock")})
    operations["populations"][0]["source"] = "frontend/src/api.ts"
    operations["operations"][0]["entrypoints"] = ["frontend/src/api.ts::query"]
    dump(tmp_path, "governance/application-operations.yml", operations)
    git(tmp_path, "add", ".")
    combined, _, typescript, registry = discover_source(tmp_path)
    assert len(compiler_contracts(tmp_path, registry)) == len(typescript["projects"]) == 2
    assert {"src/value.ts::Value", "frontend/src/api.ts::query"} <= set(combined["types"]) | {row["symbol"] for row in combined["functions"]}
    commands._lock(tmp_path, apply=True)
    assert run_scan(tmp_path)["verdict"] == "conformant"


def test_python_only_lock_material_keeps_existing_digest(tmp_path: Path) -> None:
    from bcf_governance.tooling.semantic_authority_contracts import _semantic_source_rows
    from bcf_governance.tooling.semantic_locking import stable_payload_digest
    payload = repository(tmp_path, registry_engine=False, typescript_family=False)
    operations = payload["contracts"]["application_operations"]
    operations["populations"] = [{"id": "api", "adapter": "python_module_exports", "source": "api.py", "symbol": "__all__", "public_only": True}]
    operations["operations"][0]["entrypoints"] = ["api.py::query"]
    write(tmp_path, "api.py", "def query() -> int:\n    return 1\n")
    dump(tmp_path, "governance/application-operations.yml", operations)
    git(tmp_path, "add", ".")
    inventory, _, ts, _ = discover_source(tmp_path)
    assert ts["files"] == []
    assert build_semantic_lock(tmp_path, inventory, ())["source_inventory_sha256"] == stable_payload_digest(_semantic_source_rows(tmp_path))
    commands._lock(tmp_path, apply=True)
    assert run_scan(tmp_path)["verdict"] == "conformant"


def test_typescript_family_with_python_public_operation(tmp_path: Path) -> None:
    payload = repository(tmp_path)
    operations = payload["contracts"]["application_operations"]
    operations["populations"] = [{"id": "api", "adapter": "python_module_exports", "source": "api.py", "symbol": "__all__", "public_only": True}]
    operations["operations"][0]["entrypoints"] = ["api.py::query"]
    write(tmp_path, "api.py", "def query() -> int:\n    return 1\n")
    dump(tmp_path, "governance/application-operations.yml", operations)
    git(tmp_path, "add", ".")
    commands._lock(tmp_path, apply=True)
    assert run_scan(tmp_path)["verdict"] == "conformant"


def test_public_constructor_exports_are_declaration_bound(tmp_path: Path) -> None:
    payload = repository(tmp_path)
    write(tmp_path, "src/api.ts", "export interface Metadata { value: number; }\nexport type Alias = Metadata;\nexport const count = 1;\nexport class Query { constructor(readonly value: number) {} }\n")
    operation = payload["contracts"]["application_operations"]["operations"][0]
    operation.update(population_key="Query", entrypoints=["src/api.ts::Query.constructor"])
    dump(tmp_path, "governance/application-operations.yml", payload["contracts"]["application_operations"])
    commands._lock(tmp_path, apply=True)
    assert run_scan(tmp_path)["semantic_authority"]["operation_count"] == 1


@pytest.mark.parametrize("kind", ["imported", "exporting"])
def test_module_initialization_cannot_hide_effects_behind_export_alias(tmp_path: Path, kind: str) -> None:
    payload = repository(tmp_path)
    write(tmp_path, "src/helper.ts", "export function internal(): number { return 1; }\n")
    write(tmp_path, "src/api.ts", "export { internal as query } from './helper.js';\n")
    target = "src/helper.ts" if kind == "imported" else "src/api.ts"
    with (tmp_path / target).open("a") as stream:
        stream.write("const state = { value: 0 }; state.value++;\n")
    payload["contracts"]["application_operations"]["operations"][0]["entrypoints"] = ["src/helper.ts::internal"]
    dump(tmp_path, "governance/application-operations.yml", payload["contracts"]["application_operations"])
    git(tmp_path, "add", "src")
    with pytest.raises(SemanticAuthorityError, match="undeclared write"):
        commands._lock(tmp_path, apply=True)
    assert not (tmp_path / "governance/semantic-lock.yml").exists()


def test_real_public_source_cli_complete_and_hidden_write_rejection(tmp_path: Path) -> None:
    import sys
    from semantic_typescript_fixture import ROOT, exercise_consumer
    repository(tmp_path, package="frontend")
    records = exercise_consumer(tmp_path, Path(sys.executable), ROOT / "scripts/semantic_ownership.py")
    assert [row["returncode"] for row in records] == [0, 0, 0, 0, 0, 1]


def test_original_dependency_drift_aborts_adoption_promotion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from bcf_governance.tooling.semantic_adoption_dependencies import SemanticDependencyError
    repository(tmp_path)
    commands._lock(tmp_path, apply=True)
    before = {path: (tmp_path / path).read_bytes() for path in commands.MANAGED_PATHS}
    original = commands.validate_adoption_repository
    def validate_and_change_dependency(root, inventory, registry):
        original(root, inventory, registry)
        with (tmp_path / "node_modules/@bcf-test/declared-types/index.d.ts").open("a") as stream:
            stream.write("\n// concurrent package change\n")
    monkeypatch.setattr(commands, "validate_adoption_repository", validate_and_change_dependency)
    with pytest.raises(SemanticDependencyError, match="dependencies changed"):
        commands._adopt(tmp_path, tmp_path / "adopt.yml", apply=True)
    assert before == {path: (tmp_path / path).read_bytes() for path in commands.MANAGED_PATHS}


def test_lock_check_rejects_matching_but_schema_invalid_candidate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    import shutil
    from types import SimpleNamespace
    from semantic_typescript_fixture import ROOT
    (tmp_path / "schemas").mkdir()
    shutil.copyfile(ROOT / "schemas/semantic-lock.schema.json", tmp_path / "schemas/semantic-lock.schema.json")
    from test_semantic_locking import _payload
    malformed = _payload()
    malformed["source_inventory_sha256"] = "invalid"
    dump(tmp_path, "governance/semantic-lock.yml", malformed)
    monkeypatch.setattr(commands, "discover_source", lambda _: ({}, {}, {}, None))
    monkeypatch.setattr(commands, "validate_semantic_authority", lambda *args, **kwargs: SimpleNamespace(projection_outputs=()))
    monkeypatch.setattr(commands, "build_semantic_lock", lambda *args: malformed)
    with pytest.raises(SystemExit) as stopped:
        commands.main(["lock", "--check", "--repo-root", str(tmp_path)])
    assert stopped.value.code == 1
    assert "schema" in capsys.readouterr().out
