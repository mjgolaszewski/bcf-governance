"""Closed operation validation delegated by the semantic authority owner.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


def _validate_operation_semantics(operation: dict[str, Any]) -> str:
    from .semantic_authority_contracts import SemanticAuthorityError, READ_ONLY_KINDS, MUTATING_KINDS

    kind = str(operation["semantic_kind"])
    mutates = bool(operation["authoritative_mutation"])
    confers = bool(operation["authority_conferral"])
    if kind in READ_ONLY_KINDS and (mutates or confers):
        raise SemanticAuthorityError(f"{kind} operation {operation['id']} cannot mutate or confer authority")
    if kind == "projection" and not operation["produces_projection"]:
        raise SemanticAuthorityError(f"projection operation {operation['id']} must construct a read model")
    if kind not in MUTATING_KINDS and (operation["allowed_mutation_ports"] or operation["allowed_authority_ports"]):
        raise SemanticAuthorityError(f"non-mutating operation {operation['id']} cannot declare mutation or authority ports")
    if mutates and not operation["allowed_mutation_ports"]:
        raise SemanticAuthorityError(f"mutating operation {operation['id']} requires a declared mutation port")
    if confers and not operation["allowed_authority_ports"]:
        raise SemanticAuthorityError(f"authority operation {operation['id']} requires a declared authority port")
    if operation["model_callable"] and confers:
        raise SemanticAuthorityError(f"model-callable operation {operation['id']} cannot confer authority")
    return kind


def _validate_operations(
    repo_root: Path, payload: dict[str, Any], inventory: dict[str, Any], *,
    consumer_owned_schema: bool = False, source_language: str | None = None,
    require_runtime_context: bool = True,
) -> list[dict[str, Any]]:
    from .semantic_authority_contracts import (
        SemanticAuthorityError,
        _schema, _validate_operation_structure, _discover_population,
        _function_for_entrypoint, validated_operation_effect_inventory,
        SemanticOperationEffectError,
    )
    from .semantic_operation_python import _inventory_source_subject

    if not isinstance(require_runtime_context, bool) or (consumer_owned_schema and not require_runtime_context):
        raise SemanticAuthorityError("required operations cannot waive runtime effect context")
    _schema(repo_root, "application-operations.schema.json", payload, consumer_owned=consumer_owned_schema)
    _validate_operation_structure(payload)
    try:
        source_subject = _inventory_source_subject(inventory)
    except ValueError as exc:
        raise SemanticAuthorityError(str(exc)) from exc
    functions = {str(row["symbol"]): row for row in inventory.get("functions", [])}
    python_sources = {
        str(row["path"]) for row in inventory.get("files", [])
        if str(row["path"]).endswith(".py")
    }
    populations = []
    discovered: dict[str, dict[str, str]] = {}
    for row in payload["populations"]:
        if source_language == "python" and row["adapter"] == "typescript_exports":
            continue
        entries = _discover_population(repo_root, row, inventory, source_subject=source_subject)
        if source_language == "python" and row["adapter"] == "canonical_yaml_catalog":
            targets = [_function_for_entrypoint(repo_root, symbol, functions, source_subject=source_subject) for symbol in entries.values()]
            if any(
                (target is None and symbol.split("::", 1)[0] not in python_sources)
                or (target is not None and target.get("language", "python") != "python")
                for symbol, target in zip(entries.values(), targets)
            ):
                continue
        populations.append(row)
        discovered[str(row["id"])] = entries
    classified: dict[tuple[str, str], str] = {}
    admitted: list[tuple[dict[str, Any], str, str, dict[str, Any]]] = []
    for operation in payload["operations"]:
        population_id = str(operation["population"])
        key = str(operation["population_key"])
        slot = (population_id, key)
        if slot in classified:
            raise SemanticAuthorityError(
                f"public operation {population_id}:{key} is multiply classified by {classified[slot]} and {operation['id']}"
            )
        classified[slot] = str(operation["id"])
        if population_id not in discovered:
            _validate_operation_semantics(operation)
            continue
        actual_symbol = discovered[population_id].get(key)
        if actual_symbol is None:
            raise SemanticAuthorityError(f"operation {operation['id']} is stale; {population_id}:{key} is not discovered")
        if operation["entrypoints"] != [actual_symbol]:
            raise SemanticAuthorityError(
                f"operation {operation['id']} entrypoints must exactly match discovered {actual_symbol}"
            )
        kind = _validate_operation_semantics(operation)
        function = _function_for_entrypoint(repo_root, actual_symbol, functions, source_subject=source_subject)
        if function is None:
            raise SemanticAuthorityError(
                f"operation {operation['id']} entrypoint is absent from the shared source inventory"
            )
        admitted.append((operation, kind, actual_symbol, function))
    missing = sorted(
        f"{population_id}:{key}"
        for population_id, entries in discovered.items()
        for key in entries
        if (population_id, key) not in classified
    )
    if missing:
        raise SemanticAuthorityError("unclassified public application operations: " + ", ".join(missing))

    # Effects can be traversed only after the entire operation population admits.
    observations: list[dict[str, Any]] = []
    for operation, kind, actual_symbol, function in admitted:
        population_id = str(operation["population"])
        try:
            effect_ports = validated_operation_effect_inventory(
                operation, str(function["symbol"]), inventory,
                source_modules=tuple(str(row["source"]) for row in populations if row["id"] == population_id),
                require_runtime_context=require_runtime_context,
            )
        except SemanticOperationEffectError as exc:
            raise SemanticAuthorityError(str(exc)) from exc
        observations.append({
            "operation": operation["id"], "kind": kind, "entrypoint": actual_symbol,
            "write_effect_count": sum(role == "mutation" for role, _, _ in effect_ports),
            "authority_effect_count": sum(role == "authority" for role, _, _ in effect_ports),
            "effect_ports": [
                {"classification": role, "target_kind": kind, "symbol": symbol}
                for role, kind, symbol in effect_ports
            ],
        })
        if not require_runtime_context:
            observations[-1].update(
                effect_context_scope='source_only_runtime_unqualified',
                unresolved_effect_context_count=sum(role == 'unresolved' for role, _, _ in effect_ports),
            )
    return observations
