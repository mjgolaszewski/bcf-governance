"""Independent adversarial cases for compiler-resolved effects and lock inputs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_authority_contracts import build_semantic_lock
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_source_discovery import discover_source
from semantic_typescript_fixture import git, repository, write


@pytest.fixture(scope="module")
def reviewed_effects(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("typescript-independent-effects")
    repository(root)
    write(root, "src/review-helper.ts", "let state = 0;\nexport function save(): number { state++; return state; }\nexport function publish(): number { return 1; }\n")
    write(root, "src/review.ts", """
import { save, publish, publish as read } from './review-helper.js';
class ReviewBase { read(): number { return 1; } }
class ReviewDerived extends ReviewBase { read(): number { return save(); } }
const sharedState = { value: 0 };
class Map { value = 0; constructor() { return sharedState; } }
export function renamedAuthority(): number { return read(); }
export function callbackAuthority(): number { return [1].map(publish)[0]; }
export function arrayFromCallback(): number { return Array.from([1], () => save())[0]; }
export function freezeCaller(value: { state: number }): number { Object.freeze(value); return value.state; }
export function sealCaller(value: { state: number }): number { Object.seal(value); return value.state; }
export function jsonToJSON(): string { return JSON.stringify({ toJSON(): number { return save(); } }); }
export function jsonGetter(): string { return JSON.stringify({ get value(): number { return save(); } }); }
export function assignGetter(): number { return Object.assign({}, { get value(): number { return save(); } }).value; }
export function reassignedAssignSource(): number { let source: { value: number } = { value: 1 }; source = { get value(): number { return save(); } }; return Object.assign({}, source).value; }
export function assignTargetSetter(): number { Object.assign({ set value(v: number) { save(); } }, { value: 1 }); return 1; }
export function arrayFromIterator(): number { return Array.from({ *[Symbol.iterator]() { save(); yield 1; } })[0]; }
export function setterOnFreshObject(): number { const value = { set item(v: number) { save(); } }; value.item = 1; return 1; }
export function getterReturnsCallback(): number { const value = { get action(): () => number { return () => save(); } }; return value.action(); }
export function shadowedFreshness(input: number[]): number { const value: number[] = []; { const value = input; value.push(1); } return value.length; }
export function polymorphicLocal(): number { const value: ReviewBase = new ReviewDerived(); return value.read(); }
export function shadowedBuiltinConstructor(): number { const value = new Map(); return value.value++; }
export function pureLocalFreeze(): number { const value = { state: 1 }; Object.freeze(value); return value.state; }
""")
    git(root, "add", "src")
    return discover_source(root)[0]


def _operation(**overrides) -> dict:
    return {"id": "review.query.v1", "allowed_mutation_ports": [], "allowed_authority_ports": [],
            "non_authoritative_output_effects": [], **overrides}


@pytest.mark.parametrize("name", ["renamedAuthority", "callbackAuthority"])
def test_resolved_authority_identity_survives_aliases_and_callback_edges(reviewed_effects: dict, name: str) -> None:
    with pytest.raises(SemanticOperationEffectError, match="undeclared authority"):
        validate_operation_effects(_operation(), f"src/review.ts::{name}", reviewed_effects)
    assert validate_operation_effects(_operation(allowed_authority_ports=["src/review-helper.ts::publish"]),
                                      f"src/review.ts::{name}", reviewed_effects) == (0, 1)


@pytest.mark.parametrize("name", ["arrayFromCallback", "freezeCaller", "sealCaller", "jsonToJSON", "jsonGetter",
                                  "assignGetter", "reassignedAssignSource", "assignTargetSetter", "arrayFromIterator", "setterOnFreshObject", "getterReturnsCallback", "shadowedFreshness", "polymorphicLocal", "shadowedBuiltinConstructor"])
def test_implicit_dispatch_and_lexical_aliases_cannot_hide_mutation(reviewed_effects: dict, name: str) -> None:
    with pytest.raises(SemanticOperationEffectError, match="undeclared write|unresolved.*call|unresolved effect"):
        validate_operation_effects(_operation(), f"src/review.ts::{name}", reviewed_effects)


def test_freezing_fresh_owned_data_remains_pure(reviewed_effects: dict) -> None:
    assert validate_operation_effects(_operation(), "src/review.ts::pureLocalFreeze", reviewed_effects) == (0, 0)


def test_installed_extended_tsconfig_bytes_are_part_of_the_semantic_lock(tmp_path: Path) -> None:
    repository(tmp_path)
    relative = "node_modules/review-config/base.json"
    write(tmp_path, relative, '{"compilerOptions":{"strict":true}}\n')
    config = json.loads((tmp_path / "tsconfig.json").read_text())
    config["extends"] = "./" + relative
    write(tmp_path, "tsconfig.json", json.dumps(config))
    git(tmp_path, "add", "tsconfig.json")
    before = discover_source(tmp_path)[0]
    rows = {row["path"]: row["sha256"] for row in before["typescript_inputs"]}
    assert rows[relative] == hashlib.sha256((tmp_path / relative).read_bytes()).hexdigest()
    prior = build_semantic_lock(tmp_path, before, ())["source_inventory_sha256"]
    with (tmp_path / relative).open("a") as output: output.write("\n")
    after = discover_source(tmp_path)[0]
    assert build_semantic_lock(tmp_path, after, ())["source_inventory_sha256"] != prior
