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
