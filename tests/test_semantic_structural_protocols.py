"""Structural type annotations cannot prove JavaScript accessor/protocol purity."""

from __future__ import annotations

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_source_discovery import discover_source
from semantic_typescript_fixture import git, repository, write


@pytest.fixture(scope="module")
def structural_protocols(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("typescript-structural-protocols")
    repository(root)
    write(root, "src/structural.ts", """
let state = 0;
function save(): number { return ++state; }
function read(value: { value: number }): number { return value.value; }
function readElement(value: { value: number }): number { return value['value']; }
class Shape { value = 0; }
function readShape(value: Shape): number { return value.value; }
async function awaitTyped(value: Promise<number>): Promise<number> { return await value; }
class StructuralPromise implements Promise<number> {
  readonly [Symbol.toStringTag] = 'Promise';
  then<TResult1 = number, TResult2 = never>(
    onfulfilled?: ((value: number) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> { save(); throw new Error('fixture rejection after mutation'); }
  catch<TResult = never>(onrejected?: ((reason: unknown) => TResult | PromiseLike<TResult>) | null): Promise<number | TResult> {
    throw new Error('not invoked by await');
  }
  finally(onfinally?: (() => void) | null): Promise<number> { throw new Error('not invoked by await'); }
}
export function getterProperty(): number { return read({ get value(): number { return save(); } }); }
export function getterElement(): number { return readElement({ get value(): number { return save(); } }); }
export function getterClassField(): number { return readShape({ get value(): number { return save(); } }); }
export function nativeElementGetter(): number {
  const values = [1].map<Shape>(() => ({ get value(): number { return save(); } }));
  return values.find(() => true)!.value;
}
export function awaitStructural(): Promise<number> { return awaitTyped(new StructuralPromise()); }
export function literalProperty(): number { const value = { value: 1 }; return value.value; }
export async function nativePromise(): Promise<number> { return await Promise.resolve(1); }
""")
    git(root, "add", "src/structural.ts")
    return discover_source(root)[0]


def _operation() -> dict:
    return {"id": "structural.query.v1", "allowed_mutation_ports": [],
            "allowed_authority_ports": [], "non_authoritative_output_effects": []}


@pytest.mark.parametrize("name", ["getterProperty", "getterElement", "getterClassField", "nativeElementGetter", "awaitStructural"])
def test_structural_member_and_promise_annotations_cannot_hide_effects(structural_protocols: dict, name: str) -> None:
    with pytest.raises(SemanticOperationEffectError, match="undeclared write|unresolved.*call|unresolved effect"):
        validate_operation_effects(_operation(), f"src/structural.ts::{name}", structural_protocols)


@pytest.mark.parametrize("name", ["literalProperty", "nativePromise"])
def test_proven_local_data_and_native_promise_remain_pure(structural_protocols: dict, name: str) -> None:
    assert validate_operation_effects(_operation(), f"src/structural.ts::{name}", structural_protocols) == (0, 0)
