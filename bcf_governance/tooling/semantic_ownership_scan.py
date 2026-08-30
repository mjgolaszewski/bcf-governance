"""Evaluate source-first Python facts against one semantic owner registry.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .semantic_ownership_inventory import (
    SemanticInventoryError,
    discover_python_source,
)
from .semantic_ownership_registry import (
    Registry,
    RegistryEntry,
    SemanticOwnershipRegistryError,
    load_registry,
)
from .semantic_ownership_cross_language import build_endpoint_traces
from .semantic_ownership_typescript import (
    TypeScriptDiscoveryError,
    contract_from_mapping,
    discover_typescript_source,
    tracked_typescript_files,
)


def _path_in_roots(symbol: str, roots: tuple[str, ...]) -> bool:
    path = symbol.split("::", 1)[0]
    return any(path == root or path.startswith(root + "/") for root in roots)


def _authoritative(symbol: str, registry: Registry) -> bool:
    roots = list(registry.authoritative_python_roots)
    typescript = registry.raw.get("source_authority", {}).get("typescript_engine")
    if isinstance(typescript, dict) and isinstance(typescript.get("source_roots"), list):
        roots.extend(str(value) for value in typescript["source_roots"])
    return _path_in_roots(symbol, tuple(roots)) and not _path_in_roots(
        symbol, registry.generated_mirror_roots
    )


def _simple_symbol(symbol: str) -> str:
    return symbol.rsplit("::", 1)[-1].rsplit(".", 1)[-1]


def _annotation_mentions(annotation: object, canonical: str) -> bool:
    if not isinstance(annotation, str):
        return False
    simple = _simple_symbol(canonical)
    tokens = (
        annotation.replace("[", " ")
        .replace("]", " ")
        .replace("|", " ")
        .replace(",", " ")
        .split()
    )
    return simple in tokens


def _function_mentions(function: dict[str, Any], entry: RegistryEntry) -> bool:
    return _annotation_mentions(
        function.get("return_annotation", function.get("return_type")),
        entry.canonical_symbol,
    ) or any(
        _annotation_mentions(annotation, entry.canonical_symbol)
        for annotation in function.get("parameters", {}).values()
    )


def _declared_symbols(entry: RegistryEntry) -> set[str]:
    symbols = {
        entry.owner_symbol,
        *entry.authorized_constructors,
        *entry.authorized_delegates,
    }
    for field, key in (
        ("hostile_boundary_decoder", "symbol"),
        ("persistence_codec_and_envelope", "codec_symbol"),
    ):
        value = entry.raw.get(field)
        if isinstance(value, dict) and isinstance(value.get(key), str):
            symbols.add(value[key])
    consumers = entry.raw.get("declared_consumer_layers_and_sinks", {})
    if isinstance(consumers, dict):
        for values in consumers.values():
            if isinstance(values, list):
                symbols.update(str(value) for value in values)
    return symbols


def evaluate_discovery(
    inventory: dict[str, Any],
    registry: Registry,
    typescript_inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute ownership, normalization, and dynamic-flow claims."""
    inventories = (inventory, typescript_inventory or {})
    functions = {
        str(value["symbol"]): value
        for source in inventories
        for value in source.get("functions", [])
        if _authoritative(str(value["symbol"]), registry)
    }
    types = {
        str(value) for value in inventory["types"] if _authoritative(str(value), registry)
    }
    constructors = [
        value
        for source in inventories
        for value in source.get("constructors", [])
        if _authoritative(str(value.get("caller", "")), registry)
    ]
    violations: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    for entry in registry.entries:
        authorized = entry.authorized_constructors | entry.authorized_delegates
        declared = _declared_symbols(entry)
        facts = [
            fact
            for fact in constructors
            if fact.get("constructed_symbol") == entry.canonical_symbol
        ]
        unauthorized = [fact for fact in facts if fact.get("caller") not in authorized]
        for fact in unauthorized:
            violations.append(
                {
                    "semantic_id": entry.semantic_id,
                    "kind": "unauthorized_constructor",
                    "symbol": fact.get("caller"),
                    "line": fact.get("line"),
                    "blocking": entry.blocking,
                }
            )
        owner = functions.get(entry.owner_symbol)
        owner_discovered = owner is not None or entry.owner_symbol in types
        relevant = {
            symbol: function
            for symbol, function in functions.items()
            if _function_mentions(function, entry)
        }
        for source in inventories:
            for fact in source.get("normalizations", []):
                caller = str(fact.get("caller", ""))
                if caller not in relevant or caller in declared:
                    continue
                parameter_derived = bool(
                    fact.get("parameter_origins")
                    or fact.get("downstream_of_parameter") is True
                )
                if parameter_derived:
                    violations.append(
                        {
                            "semantic_id": entry.semantic_id,
                            "kind": "downstream_normalization",
                            "symbol": caller,
                            "operation": fact.get("call_name"),
                            "line": fact.get("line"),
                            "blocking": entry.blocking,
                        }
                    )
        duplicate_owners: set[str] = set()
        if owner is not None and owner.get("return_fingerprints"):
            fingerprints = set(owner["return_fingerprints"])
            for symbol, function in relevant.items():
                if symbol in authorized:
                    continue
                if fingerprints.intersection(function.get("return_fingerprints", [])):
                    duplicate_owners.add(symbol)
                    violations.append(
                        {
                            "semantic_id": entry.semantic_id,
                            "kind": "competing_normalizer",
                            "symbol": symbol,
                            "blocking": entry.blocking,
                        }
                    )
        covered = owner_discovered and bool(facts)
        coverage.append(
            {
                "semantic_id": entry.semantic_id,
                "family": entry.family,
                "lifecycle": entry.lifecycle,
                "blocking": entry.blocking,
                "canonical_symbol": entry.canonical_symbol,
                "owner_symbol": entry.owner_symbol,
                "owner_discovered": owner_discovered,
                "constructor_count": len(facts),
                "unauthorized_constructor_count": len(unauthorized),
                "competing_owner_count": len(duplicate_owners),
                "covered": covered,
            }
        )
        if entry.blocking and not owner_discovered:
            violations.append(
                {
                    "semantic_id": entry.semantic_id,
                    "kind": "registry_owner_not_discovered",
                    "symbol": entry.owner_symbol,
                    "blocking": True,
                }
            )
        if entry.blocking and not facts:
            violations.append(
                {
                    "semantic_id": entry.semantic_id,
                    "kind": "canonical_constructor_not_discovered",
                    "symbol": entry.canonical_symbol,
                    "blocking": True,
                }
            )
        if registry.mode in {"declared_families_blocking", "repository_wide_blocking"} and (
            entry.lifecycle != "enforced" or not entry.blocking
        ):
            violations.append(
                {
                    "semantic_id": entry.semantic_id,
                    "kind": "declared_family_not_enforced",
                    "symbol": entry.owner_symbol,
                    "blocking": True,
                }
            )
    if registry.mode == "repository_wide_blocking":
        registered_types = {entry.canonical_symbol for entry in registry.entries}
        for symbol in sorted(types - registered_types):
            violations.append(
                {
                    "semantic_id": "unregistered.canonical-type.v1",
                    "kind": "unregistered_canonical_type",
                    "symbol": symbol,
                    "blocking": True,
                }
            )
    unresolved = [
        value
        for source in inventories
        for value in source.get("unresolved", [])
        if _authoritative(str(value.get("symbol", "")), registry)
    ]
    if registry.unresolved_dynamic_policy == "fail_closed":
        for value in unresolved:
            violations.append(
                {
                    "semantic_id": "unresolved.dynamic-flow.v1",
                    "kind": value.get("kind", "unresolved_dynamic_flow"),
                    "symbol": value.get("symbol"),
                    "line": value.get("line"),
                    "blocking": True,
                }
            )
    violations.sort(
        key=lambda value: (
            str(value.get("semantic_id")),
            str(value.get("kind")),
            str(value.get("symbol")),
            int(value.get("line") or 0),
        )
    )
    blocking = [value for value in violations if value["blocking"]]
    return {
        "verdict": "conformant" if not blocking else "non_conformant",
        "blocking_violation_count": len(blocking),
        "violations": violations,
        "registry_coverage": coverage,
        "unresolved_dynamic_flows": unresolved,
    }


def _git(repo_root: Path, expression: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", expression],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def run_scan(repo_root: Path) -> dict[str, Any]:
    """Discover the exact source first, then make declarations available."""
    repo_root = repo_root.resolve()
    inventory = discover_python_source(repo_root)
    typescript_files = tracked_typescript_files(repo_root)
    registry = load_registry(repo_root)
    typescript_config = registry.raw["source_authority"]["typescript_engine"]
    typescript_inventory: dict[str, Any] = {
        "language": "typescript",
        "files": [],
        "functions": [],
        "constructors": [],
        "normalizations": [],
        "unresolved": [],
    }
    traces: list[dict[str, Any]] = []
    if isinstance(typescript_config, dict):
        contract = contract_from_mapping(typescript_config)
        typescript_inventory = discover_typescript_source(
            repo_root, contract, typescript_files
        )
        traces = build_endpoint_traces(
            inventory,
            typescript_inventory,
            browser_contract_roots=contract.browser_contract_roots,
        )
    evaluation = evaluate_discovery(inventory, registry, typescript_inventory)
    file_rows = [*inventory["files"], *typescript_inventory["files"]]
    file_material = "\n".join(
        f"{value['path']}:{value['sha256']}" for value in file_rows
    ).encode()
    return {
        "document": {
            "kind": "exact_tree_semantic_ownership_report",
            "version": "1.0.0",
            "phase": registry.phase,
        },
        "subject": {
            "commit_sha": _git(repo_root, "HEAD"),
            "tree_sha": _git(repo_root, "HEAD^{tree}"),
            "workspace_source_sha256": hashlib.sha256(file_material).hexdigest(),
            "discovery_preceded_registry_load": True,
        },
        "source_inventory": {
            "python": {
                "files": inventory["files"],
                "file_count": len(inventory["files"]),
                "type_count": len(inventory["types"]),
                "function_count": len(inventory["functions"]),
                "constructor_count": len(inventory["constructors"]),
                "normalization_count": len(inventory["normalizations"]),
                "unresolved_count": len(inventory["unresolved"]),
            },
            "typescript": {
                "files": typescript_inventory["files"],
                "file_count": len(typescript_inventory["files"]),
                "compiler_version": typescript_inventory.get("compiler_version"),
                "constructor_count": len(typescript_inventory["constructors"]),
                "normalization_count": len(typescript_inventory["normalizations"]),
                "unresolved_count": len(typescript_inventory["unresolved"]),
                "toolchain": typescript_inventory.get("toolchain"),
            },
            "cross_language_endpoint_traces": traces,
        },
        **evaluation,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Enforce semantic ownership invariants.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output", type=Path, default=Path(".artifacts/semantic-ownership/report.json")
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    output = args.output if args.output.is_absolute() else repo_root / args.output
    try:
        report = run_scan(repo_root)
    except (
        SemanticInventoryError,
        SemanticOwnershipRegistryError,
        TypeScriptDiscoveryError,
    ) as exc:
        report = {
            "document": {"kind": "exact_tree_semantic_ownership_report", "version": "1.0.0"},
            "verdict": "non_conformant",
            "blocking_violation_count": 1,
            "violations": [
                {
                    "semantic_id": "governance.architecture-verdict.v1",
                    "kind": "analysis_infrastructure_failure",
                    "diagnostic": str(exc),
                    "blocking": True,
                }
            ],
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) >= 1024 * 1024:
        raise SystemExit("semantic ownership report exceeds the 1 MiB compact-report limit")
    output.write_bytes(encoded)
    print(
        f"semantic-ownership-{report['verdict']}: "
        f"{report.get('blocking_violation_count', 0)} blocking violation(s)"
    )
    if report["verdict"] != "conformant":
        for violation in report.get("violations", []):
            if isinstance(violation, dict) and violation.get("diagnostic"):
                print(f"semantic-ownership-diagnostic: {violation['diagnostic']}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
