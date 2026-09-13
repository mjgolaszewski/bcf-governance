from __future__ import annotations

from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_source_discovery import discover_source
from semantic_typescript_fixture import git, repository, write


@pytest.fixture(scope="module")
def typed_effects(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("typescript-effects")
    repository(root)
    write(root, "src/helper.ts", "export const state = { value: 0 };\nexport function save(): number { state.value++; return state.value; }\nexport function publish(): number { return 1; }\n")
    write(root, "src/fs.d.ts", "declare module 'node:fs' { export function writeFileSync(path: string, data: string): void; }\n")
    write(root, "src/effects.ts", """
import { state, save, publish } from './helper.js';
import { writeFileSync } from 'node:fs';
const shared = new Map<string, number>();
let captured = 0;
class Store { read(): number { return save(); } }
class ConstructorWrite { constructor() { save(); } }
class Pure { constructor(readonly value: number) {} read(): number { return this.value; } }
export function pure(): number { let n = 1; n++; const x = { value: n }; x.value++; const a: number[] = []; a.push(x.value); return a.map(v => v + 1).reduce((a, b) => a + b, 0); }
export function pureConstructor(): number { return new Pure(3).read(); }
export function propertyWrite(): number { state.value = 2; return 1; }
export function updateWrite(): number { return state.value++; }
export function deleteWrite(value: { item?: number }): number { delete value.item; return 1; }
export function captureWrite(): number { captured++; return captured; }
export function collectionWrite(value: number[]): number { value.push(1); return 1; }
export function aliasWrite(value: number[]): number { const alias = value; alias.push(1); return 1; }
export function importedWrite(): number { return save(); }
export function methodWrite(): number { return new Store().read(); }
export function constructorWrite(): number { new ConstructorWrite(); return 1; }
export function callbackWrite(): number { return [1].map(() => save())[0]; }
export function functionCallbackWrite(): number { return [1].map(save)[0]; }
export function authority(): number { return publish(); }
export function filesystem(): number { writeFileSync('state', 'changed'); return 1; }
export function browserStorage(): number { localStorage.setItem('state', 'changed'); return 1; }
export function networkWrite(): Promise<Response> { return fetch('/state', { method: 'POST' }); }
export function dynamic(value: { one(): number }, key: 'one'): number { return value[key](); }
export function callbackParameter(callback: () => number): number { return callback(); }
export function external(value: { execute(): number }): number { return value.execute(); }
export function command(): number { return save(); }
""")
    git(root, "add", "src")
    inventory, _, _, _ = discover_source(root)
    return inventory


def operation(**overrides: object) -> dict:
    return {"id": "example.query.v1", "allowed_mutation_ports": [], "allowed_authority_ports": [], "non_authoritative_output_effects": [], **overrides}


@pytest.mark.parametrize("name", ["pure", "pureConstructor"])
def test_real_typescript_local_construction_and_collection_are_pure(typed_effects: dict, name: str) -> None:
    assert validate_operation_effects(operation(), f"src/effects.ts::{name}", typed_effects) == (0, 0)


@pytest.mark.parametrize("name", ["propertyWrite", "updateWrite", "deleteWrite", "captureWrite", "collectionWrite", "aliasWrite", "importedWrite", "methodWrite", "constructorWrite", "callbackWrite", "functionCallbackWrite", "filesystem", "browserStorage", "networkWrite"])
def test_real_typescript_cannot_hide_javascript_write(typed_effects: dict, name: str) -> None:
    with pytest.raises(SemanticOperationEffectError, match="undeclared write|unresolved effect"):
        validate_operation_effects(operation(), f"src/effects.ts::{name}", typed_effects)


def test_real_typescript_authority_requires_exact_reachable_port(typed_effects: dict) -> None:
    with pytest.raises(SemanticOperationEffectError, match="undeclared authority"):
        validate_operation_effects(operation(), "src/effects.ts::authority", typed_effects)
    assert validate_operation_effects(operation(allowed_authority_ports=["src/helper.ts::publish"]), "src/effects.ts::authority", typed_effects) == (0, 1)


@pytest.mark.parametrize("name", ["dynamic", "callbackParameter", "external"])
def test_real_typescript_dynamic_dispatch_cannot_be_declared_away(typed_effects: dict, name: str) -> None:
    function = next(row for row in typed_effects["functions"] if row["symbol"] == f"src/effects.ts::{name}")
    declared = [row["called_symbol"] for row in function["calls"]]
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect"):
        validate_operation_effects(operation(allowed_mutation_ports=declared), function["symbol"], typed_effects)


def test_real_typescript_effect_ports_are_exact_and_reachable(typed_effects: dict) -> None:
    assert validate_operation_effects(operation(allowed_mutation_ports=["src/helper.ts::save"]), "src/effects.ts::command", typed_effects) == (1, 0)
    with pytest.raises(SemanticOperationEffectError, match="unreachable"):
        validate_operation_effects(operation(allowed_mutation_ports=["src/helper.ts::absent"]), "src/effects.ts::pure", typed_effects)
