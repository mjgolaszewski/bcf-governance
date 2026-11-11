"""Pure CI-authority/tooling population queries for the existing compiler.

Canonical set serialization is shared with composition validation. Expected
populations still require protected authenticated inputs; these helpers grant
no behavioral or lifecycle authority.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from typing import Any, Iterable, Mapping, TYPE_CHECKING

from .ci_graph_errors import CIGraphError

if TYPE_CHECKING:
    from .ci_graph_contracts import CompiledCIGraph

Relationship = tuple[str, str, str]
Effect = tuple[str, str, str, str]


def _bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def edge_population_sha256(compiled_graph: CompiledCIGraph) -> str:
    """Bind semantics of all existing reachable and excluded CI edges."""

    population = sorted(
        (asdict(edge) for edge in compiled_graph.edge_contracts),
        key=lambda edge: (edge["producer"], edge["consumer"]),
    )
    return hashlib.sha256(_bytes(population)).hexdigest()


def lifecycle_effect_population(
    observations: Iterable[Mapping[str, Any]],
    *,
    expected_entrypoints: Mapping[str, str],
    effect_bindings: Mapping[tuple[str, str, str, str], frozenset[Relationship]],
) -> frozenset[Effect]:
    """Bind existing validated source-port facts to protected lifecycle contexts.

    The protected consumer supplies the independently complete operation and
    context populations. Proposed lifecycle rows are never read here. These
    facts are static source observations, not execution or provider authority.
    """

    if not expected_entrypoints or any(
        not isinstance(value, str) or not value
        for pair in expected_entrypoints.items() for value in pair
    ):
        raise CIGraphError("lifecycle source operation population is absent or invalid")
    operations: set[str] = set()
    ports: set[tuple[str, str, str, str]] = set()
    for observation in observations:
        operation = observation.get("operation")
        if (
            not isinstance(operation, str) or operation in operations
            or operation not in expected_entrypoints
            or observation.get("entrypoint") != expected_entrypoints[operation]
        ):
            raise CIGraphError("lifecycle source operation identity is absent duplicated or unbound")
        operations.add(operation)
        supplied = observation.get("effect_ports")
        if not isinstance(supplied, (list, tuple)):
            raise CIGraphError("lifecycle source requires compatible installed effect inventory")
        counts = {"mutation": 0, "authority": 0, "observation": 0}
        for row in supplied:
            if not isinstance(row, Mapping) or set(row) != {"classification", "target_kind", "symbol"}:
                raise CIGraphError("lifecycle source effect fact is malformed")
            role, kind, symbol = row["classification"], row["target_kind"], row["symbol"]
            if (
                not all(isinstance(value, str) and value for value in (role, kind, symbol))
                or role not in counts or kind not in {"function", "call"}
            ):
                raise CIGraphError("lifecycle source effect classification is invalid")
            port = (operation, role, kind, symbol)
            if port in ports:
                raise CIGraphError("lifecycle source effect population is duplicated")
            ports.add(port)
            counts[role] += 1
        for role, field in (("mutation", "write_effect_count"), ("authority", "authority_effect_count")):
            count = observation.get(field)
            if isinstance(count, bool) or not isinstance(count, int) or count != counts[role]:
                raise CIGraphError("lifecycle source effect role count is inconsistent")
    if operations != expected_entrypoints.keys():
        raise CIGraphError("lifecycle source operation population is incomplete")
    if ports != effect_bindings.keys():
        raise CIGraphError("lifecycle source effect bindings do not close the port population")
    effects: set[Effect] = set()
    for port, relationships in effect_bindings.items():
        if not relationships:
            raise CIGraphError("lifecycle source effect has no bound context consumer")
        for relationship in relationships:
            if (
                not isinstance(relationship, tuple) or len(relationship) != 3
                or any(not isinstance(value, str) or not value for value in relationship)
                or relationship[1] == relationship[2]
            ):
                raise CIGraphError("lifecycle source effect context binding is invalid")
            effects.add((*relationship, _bytes(port).decode()))
    return frozenset(effects)

def lifecycle_recovery_coverage(relationships) -> dict[str, Any]:
    """Close loaded-owner references, not context authority or runtime truth."""
    from .ci_recovery_frontier import recovery_edge_population

    population = recovery_edge_population()
    if (not population or any(not isinstance(row, tuple) or len(row) != 4
            or any(not isinstance(value, str) or not value for value in row)
            for row in population)
            or len({row[:2] for row in population}) != len(population)):
        raise CIGraphError("lifecycle recovery owner population is invalid")
    required = {(operation, state): (action, successor)
                for operation, state, action, successor in population}
    bindings: dict[tuple[str, str], set[Relationship]] = {}
    if not isinstance(relationships, list):
        raise CIGraphError("lifecycle recovery relationship population is invalid")
    for row in relationships:
        if not isinstance(row, Mapping):
            raise CIGraphError("lifecycle recovery relationship is malformed")
        contract = row.get("contract")
        if contract is None:
            continue
        pair = tuple(row.get(name) for name in ("context", "producer", "consumer"))
        if any(not isinstance(value, str) or not value for value in pair):
            raise CIGraphError("lifecycle recovery context reference is invalid")
        references = contract.get("recovery_edges") if isinstance(contract, Mapping) else None
        if not isinstance(references, list):
            raise CIGraphError("lifecycle recovery references are absent")
        seen = set()
        for reference in references:
            if (not isinstance(reference, Mapping)
                    or set(reference) != {"operation", "state"}
                    or any(not isinstance(value, str) or not value for value in reference.values())):
                raise CIGraphError("lifecycle recovery reference is malformed")
            identity = reference["operation"], reference["state"]
            if identity in seen or identity not in required:
                raise CIGraphError("lifecycle recovery population is duplicated or invented")
            seen.add(identity)
            bindings.setdefault(identity, set()).add(pair)
    if bindings.keys() != required.keys():
        raise CIGraphError("lifecycle recovery population is incomplete")
    return {
        "authority": False, "execution_qualified": False,
        "context_authority_qualified": False,
        "scope": "loaded_recovery_owner_reference_coverage",
        "owner_population_sha256": hashlib.sha256(_bytes(population)).hexdigest(),
        "edges_checked": len(required),
        "bindings": [
            {"operation": operation, "state": state,
             "action": required[operation, state][0],
             "successor": required[operation, state][1],
             "relationships": [list(pair) for pair in sorted(bindings[operation, state])]}
            for operation, state in sorted(required)
        ],
    }
