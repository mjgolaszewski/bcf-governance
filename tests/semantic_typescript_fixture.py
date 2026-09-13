"""Real, offline compiler fixture shared by source and installed-consumer tests."""
from __future__ import annotations

import copy
from functools import cache
import sys
import json
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = ROOT / "tests/fixtures/typescript-toolchain"


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def dump(root: Path, relative: str, payload: dict) -> None:
    write(root, relative, yaml.safe_dump(payload, sort_keys=False))


@cache
def bootstrap_compiler() -> None:
    completed = subprocess.run([sys.executable, str(ROOT / ".github/scripts/bootstrap_test_toolchain.py")], cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def compiler(root: Path, *, package: str = "") -> dict:
    bootstrap_compiler()
    target = root / package
    installed = TOOLCHAIN / "node_modules/typescript/package.json"
    assert installed.is_file(), "Run the declared offline TypeScript fixture bootstrap before tests"
    assert json.loads(installed.read_text())["version"] == "6.0.3"
    assert shutil.which("node"), "The declared Node toolchain is mandatory"
    target.mkdir(parents=True, exist_ok=True)
    for item in ("package.json", "package-lock.json"):
        shutil.copyfile(TOOLCHAIN / item, target / item)
    for item in ("node_modules", "declared-types"):
        shutil.copytree(TOOLCHAIN / item, target / item)
    config = {
        "compilerOptions": {"strict": True, "target": "ES2022", "module": "NodeNext", "moduleResolution": "NodeNext", "skipLibCheck": False},
        "include": ["src/**/*.ts"],
    }
    write(target, "tsconfig.json", json.dumps(config))
    prefix = package + "/" if package else ""
    return {"node_executable": "node", "tsconfig": prefix + "tsconfig.json", "package_lock": prefix + "package-lock.json", "source_roots": [prefix + "src"], "browser_contract_roots": []}


def repository(root: Path, *, package: str = "", registry_engine: bool = True, typescript_family: bool = True, install_schemas: bool = True) -> dict:
    engine = compiler(root, package=package)
    prefix = package + "/" if package else ""
    write(root, ".gitignore", "node_modules/\n.artifacts/\n")
    write(root, prefix + "src/value.ts", "import type { DeclaredValue } from '@bcf-test/declared-types';\nexport class Value implements DeclaredValue { constructor(readonly value: number) {} }\nexport interface Shape { readonly value: number; }\nexport type ValueAlias = Shape;\nexport function create(value: number): Value { return new Value(value); }\n")
    write(root, prefix + "src/api.ts", "export function query(): number { return 1; }\n")
    write(root, "model.py", "class Value:\n    pass\n\ndef create() -> Value:\n    return Value()\n")
    canonical = prefix + "src/value.ts::Value" if typescript_family else "model.py::Value"
    owner = prefix + "src/value.ts::create" if typescript_family else "model.py::create"
    registry = yaml.safe_load((ROOT / "governance/canonical-representations.yml").read_text())
    row = copy.deepcopy(registry["representations"][0])
    row.update({
        "semantic_id": "example.value.v1", "family": "example", "canonical_type": {"language": "typescript" if typescript_family else "python", "symbol": canonical},
        "authoritative_owner": {"symbol": owner, "owner_kind": "constructor"},
        "authorized_constructors_and_factories": [owner], "authorized_pure_delegates": [],
        "hostile_boundary_decoder": {"symbol": owner, "trust_boundary": "typed input"},
        "declared_consumer_layers_and_sinks": {key: [] for key in row["declared_consumer_layers_and_sinks"]},
        "generated_source_authority": {"authoritative_roots": [canonical.split("::")[0]], "generated_mirrors": [], "generator": "none", "parity_proof": "none"},
    })
    row["persistence_codec_and_envelope"].update({"codec_symbol": owner, "semantic_id": "example.value.v1"})
    row["migration_policy"]["owner"] = owner
    registry["representations"] = [row]
    registry["enforcement"].update({"declared_families": ["example"], "blocking_semantic_ids": ["example.value.v1"]})
    registry["source_authority"].update({"authoritative_python_roots": ["model.py"], "generated_mirror_roots": [], "typescript_engine": engine if registry_engine else "not_applicable_until_declared_by_consumer"})
    registry.pop("secondary_representations", None)
    families = {
        "schema_version": "1.0", "document": {"kind": "semantic_family_registry", "id": "fixture-families", "version": "1.0.0", "status": "active", "path": "governance/semantic-families.yml"},
        "families": [{"id": "example", "significance": "authoritative", "ownership_required": True, "canonical_semantic_ids": ["example.value.v1"], "material_selectors": {"source_paths": [canonical.split("::")[0]], "symbols": [canonical]}, "responsibilities": {"construction": [owner], "decoding": [], "transition": [], "projection": []}}], "migrations": [],
    }
    operations = {
        "schema_version": "1.0", "document": {"kind": "application_operation_registry", "id": "fixture-operations", "version": "1.0.0", "status": "active", "path": "governance/application-operations.yml"},
        "populations": [{"id": "api", "adapter": "typescript_exports", "source": prefix + "src/api.ts", "symbol": "exports", "public_only": True, **{key: engine[key] for key in ("node_executable", "tsconfig", "package_lock")}}],
        "operations": [{"id": "example.query.v1", "population": "api", "population_key": "query", "family": "example", "bounded_context": "example", "entrypoints": [prefix + "src/api.ts::query"], "semantic_kind": "query", "authoritative_read": True, "authoritative_mutation": False, "authority_conferral": False, "produces_projection": False, "model_callable": False, "allowed_mutation_ports": [], "allowed_authority_ports": [], "non_authoritative_output_effects": []}], "migrations": [],
    }
    for name in ("canonical-representations", "semantic-families", "application-operations", "semantic-lock"):
        path = root / f"schemas/{name}.schema.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if install_schemas:
            shutil.copyfile(ROOT / f"schemas/{name}.schema.json", path)
        else:
            assert path.is_file(), f"Installed schema missing: {path}"
    payload = {"contracts": {"semantic_families": families, "application_operations": operations, "canonical_representations": registry}, "unresolved_classifications": []}
    for key, name in (("semantic_families", "semantic-families"), ("application_operations", "application-operations"), ("canonical_representations", "canonical-representations")):
        dump(root, f"governance/{name}.yml", payload["contracts"][key])
    dump(root, "governance-profile.yml", {"profile_contract_version": "2.0", "profile": {"selected": "standard"}, "semantic_capabilities": {"semantic_family_completeness": "blocking", "application_operation_inventory": "blocking", "representation_provenance": "blocking"}})
    dump(root, "adopt.yml", payload)
    git(root, "init")
    git(root, "config", "user.email", "fixture@example.test")
    git(root, "config", "user.name", "Semantic fixture")
    git(root, "add", ".")
    git(root, "commit", "-m", "typed semantic fixture")
    return payload


def exercise_consumer(root: Path, python: Path, wrapper: Path) -> list[dict]:
    """Run the public installed/source entrypoint without repository import injection."""
    import os

    environment = {key: value for key, value in os.environ.items() if not key.startswith(("PYTHON", "BCF_", "GITHUB_"))}
    environment.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
    records = []
    for args in (
        ["lock", "--apply"], ["lock", "--check"],
        ["adopt", "--config", str(root / "adopt.yml"), "--check"],
        ["adopt", "--config", str(root / "adopt.yml"), "--apply"],
        ["scan", "--output", str(root / ".artifacts/semantic-report.json")],
    ):
        argv = [str(python), str(wrapper), *args, "--repo-root", str(root)]
        completed = subprocess.run(argv, cwd=root, env=environment, capture_output=True, text=True)
        records.append({"argv": argv, "returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr})
        assert completed.returncode == 0, records[-1]
    assert yaml.safe_load((root / "governance/semantic-lock.yml").read_text())["projection_outputs"] == []
    assert json.loads((root / ".artifacts/semantic-report.json").read_text())["verdict"] == "conformant"
    operations = yaml.safe_load((root / "governance/application-operations.yml").read_text())
    source = root / operations["populations"][0]["source"]
    original = source.read_bytes()
    source.write_text("const state = { value: 0 };\nexport function query(): number { state.value++; return state.value; }\n")
    argv = [str(python), str(wrapper), "lock", "--apply", "--repo-root", str(root)]
    try:
        completed = subprocess.run(argv, cwd=root, env=environment, capture_output=True, text=True)
    finally:
        source.write_bytes(original)
    records.append({"argv": argv, "returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr})
    assert completed.returncode == 1 and "undeclared write effects" in completed.stdout, records[-1]
    return records
