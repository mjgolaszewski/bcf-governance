"""Real compiler coverage for syntax and native calls with implicit user dispatch."""
from __future__ import annotations

from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_source_discovery import discover_source
from semantic_typescript_fixture import git, repository, write


@pytest.fixture(scope="module")
def implicit_inventory(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("typescript-implicit")
    repository(root)
    write(root, "src/implicit.ts", """
let state = 0;
function save(): number { state++; return state; }
const object = { get value(): number { return save(); } };
const coercive = { toString(): string { save(); return '1'; }, valueOf(): number { return save(); } };
function iterable(): Iterable<number> { return { *[Symbol.iterator](): Generator<number, void, undefined> { save(); yield 1; } }; }
class Thenable { then(resolve: (value: number) => unknown): unknown { save(); return resolve(1); } }
function tag(strings: TemplateStringsArray): number { return save(); }
export function forOfHook(): number { for (const value of iterable()) { return value; } return 0; }
export function arraySpreadHook(): number { return [...iterable()][0]; }
export function objectSpreadHook(): number { return {...object}.value; }
export function objectDestructureHook(): number { const {value} = object; return value; }
export function objectRestHook(): number { const {...rest} = object; return rest.value; }
export function arrayDestructureHook(): number { const [value] = iterable(); return value; }
export function destructuredParameter({value}: {value: number}): number { return value; }
export function* yieldHook(): Generator<number, void, undefined> { yield* iterable(); }
export async function awaitHook(): Promise<number> { return await new Thenable(); }
export function resolveHook(): Promise<number> { return Promise.resolve(new Thenable()); }
export function templateHook(): string { return `${coercive}`; }
export function additionHook(): string { return '' + coercive; }
export function computedHook(): number { const value = {[`${coercive}`]: 1}; return Object.keys(value).length; }
export function defaultHook(value: number = save()): number { return value; }
export function tagHook(): number { return tag`value`; }
export function joinHook(): string { return [coercive].join(); }
export function stringMethodHook(): string { return 'x'.replace('x', coercive as unknown as string); }
export function mathHook(): number { return Math.max(coercive as unknown as number); }
export function parseHook(): number { return parseInt(coercive as unknown as string); }
export function dateHook(): number { return new Date(coercive as unknown as number).valueOf(); }
export function urlHook(): string { return new URL(coercive as unknown as string, 'https://example.test').href; }
export function urlParamsHook(): string { return new URLSearchParams({get value(): string { save(); return '1'; }}).toString(); }
export function regexpHook(): boolean { return new RegExp(coercive as unknown as string).test('1'); }
export function errorHook(): string { return new Error(coercive as unknown as string).message; }
export function typedArrayHook(values: number[]): number { return Array.from(values)[0]; }
export function typedMapHook(values: [string, number][]): number { return new Map(values).size; }
export function localAnyHook(): number { let value: any = coercive; return value++; }
export function pureLocalSyntax(): number { let total = 0; for (const value of [1, 2]) total += value; const {value} = {value: 1}; const [first] = [1]; return total + value + first + [...[1]].length + {...{value: 1}}.value; }
export async function pureAwait(): Promise<number> { return await Promise.resolve(1); }
export function pureNative(): string { const values = [1, 2]; return new URL('/path', 'https://example.test').pathname + values.join(',') + String(Math.max(1, 2)); }
""")
    git(root, "add", "src")
    return discover_source(root)[0]


def _operation() -> dict:
    return {"id": "implicit.query.v1", "allowed_mutation_ports": [], "allowed_authority_ports": [], "non_authoritative_output_effects": []}


@pytest.mark.parametrize("name", ["forOfHook", "arraySpreadHook", "objectSpreadHook", "objectDestructureHook", "objectRestHook", "arrayDestructureHook", "destructuredParameter", "yieldHook", "awaitHook", "resolveHook", "templateHook", "additionHook", "computedHook", "defaultHook", "tagHook", "joinHook", "stringMethodHook", "mathHook", "parseHook", "dateHook", "urlHook", "urlParamsHook", "regexpHook", "errorHook", "typedArrayHook", "typedMapHook", "localAnyHook"])
def test_implicit_user_dispatch_fails_closed(implicit_inventory: dict, name: str) -> None:
    with pytest.raises(SemanticOperationEffectError, match="undeclared write|unresolved"):
        validate_operation_effects(_operation(), f"src/implicit.ts::{name}", implicit_inventory)


@pytest.mark.parametrize("name", ["pureLocalSyntax", "pureAwait", "pureNative"])
def test_proven_local_syntax_and_native_primitives_remain_pure(implicit_inventory: dict, name: str) -> None:
    assert validate_operation_effects(_operation(), f"src/implicit.ts::{name}", implicit_inventory) == (0, 0)
