"""Pure lifecycle composition over the existing compiled CI edge population.

The protected consumer supplies required populations and authenticated identity.
This compiler checks a proposed composition; it does not authenticate those inputs,
discover runtime effects, evaluate behavioral truth, or authorize an operation.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import html
import json
from typing import Any, Mapping, TYPE_CHECKING

from jsonschema import Draft202012Validator

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


def _canonical_contract(contract: dict[str, Any]) -> dict[str, Any]:
    # The schema defines these collections as sets. Preserve scalar semantics.
    return {
        key: sorted(value, key=_bytes) if isinstance(value, list) else value
        for key, value in contract.items()
    }


def compile_lifecycle_composition(
    payload: dict[str, Any],
    *,
    schema: dict[str, Any],
    compiled_graph: CompiledCIGraph,
    expected_source: Mapping[str, str],
    expected_populations: Mapping[str, tuple[str, ...]],
    expected_relationships: Mapping[Relationship, str | None],
    expected_effects: set[Effect] | frozenset[Effect],
) -> dict[str, Any]:
    """Check closed relationships against independently supplied populations.

    A ``None`` expected disposition denotes a structurally reachable pair.
    Otherwise the value is its exact canonical structural exclusion. A failed
    reachable guard must remain a rejection in its contract, never an exclusion.
    Callers must obtain both expected populations from protected canonical owners,
    independently of the proposed payload. No result confers truth authority.
    """

    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise CIGraphError(f"lifecycle composition schema violation: {errors[0].message}")
    if payload["source"] != dict(expected_source):
        raise CIGraphError("lifecycle composition source identity differs from authenticated inputs")
    source = payload["source"]
    if (
        source["graph_sha256"] != compiled_graph.graph_sha256
        or source["ci_edges_sha256"] != edge_population_sha256(compiled_graph)
    ):
        raise CIGraphError("lifecycle composition CI edge identity is stale")
    universe: set[Relationship] = set()
    if not expected_populations:
        raise CIGraphError("lifecycle composition requires an independent nonempty population")
    for context, nodes in expected_populations.items():
        if (
            not isinstance(context, str) or not context
            or len(nodes) < 2 or len(set(nodes)) != len(nodes)
            or any(not isinstance(node, str) or not node for node in nodes)
        ):
            raise CIGraphError("lifecycle composition independent node population is invalid")
        universe.update((context, producer, consumer) for producer in nodes for consumer in nodes if producer != consumer)
    if set(expected_relationships) != universe:
        raise CIGraphError("lifecycle composition independent relationship population is not closed")

    existing_edges = {
        (edge.producer, edge.consumer): edge
        for edge in compiled_graph.edge_contracts
    }
    observed: dict[Relationship, dict[str, Any]] = {}
    effects: set[Effect] = set()
    for row in payload["relationships"]:
        pair = (row["context"], row["producer"], row["consumer"])
        if row["producer"] == row["consumer"] or pair in observed:
            raise CIGraphError("lifecycle composition relationship population contains a duplicate or self pair")
        if pair not in expected_relationships:
            raise CIGraphError("lifecycle composition relationship population contains an unbound pair")
        expected_exclusion = expected_relationships[pair]
        if row["exclusion"] != expected_exclusion:
            raise CIGraphError("lifecycle composition exclusion differs from independent structure")
        contract = row["contract"]
        if contract is not None:
            facts = {fact["id"]: fact for fact in contract["facts"]}
            if len(facts) != len(contract["facts"]):
                raise CIGraphError("lifecycle composition fact producer resolution is ambiguous")
            if any(guard["fact_id"] not in facts for guard in contract["guards"]):
                raise CIGraphError("lifecycle composition guard references an undeclared fact")
            for reference in contract["ci_edges"]:
                edge = existing_edges.get((reference["producer"], reference["consumer"]))
                if edge is None or not edge.reachable:
                    raise CIGraphError("lifecycle composition CI edge reference is absent or unreachable")
            effects.update((*pair, effect) for effect in contract["effects"])
            contract = _canonical_contract(contract)
        observed[pair] = {**row, "contract": contract}
    if observed.keys() != expected_relationships.keys():
        raise CIGraphError("lifecycle composition relationship population is incomplete")
    if effects != expected_effects:
        raise CIGraphError("lifecycle composition runtime effect population differs from independent inventory")

    result = {
        "schema_version": payload["schema_version"],
        "authority": False,
        "source": dict(source),
        "relationships": [observed[key] for key in sorted(observed)],
    }
    result["composition_sha256"] = hashlib.sha256(_bytes(result)).hexdigest()
    # Detach nested collections from caller-owned mutable input snapshots.
    return json.loads(_bytes(result))


def render_lifecycle_composition(compiled: dict[str, Any]) -> str:
    """Project all compiled relationships and contract fields into a human view.

    This returns bytes-to-save as text; reconciliation retains ownership of writes.
    Diagram node IDs are derived from context-qualified states, never caller code.
    """

    content = {key: value for key, value in compiled.items() if key != "composition_sha256"}
    if (
        compiled.get("authority") is not False
        or hashlib.sha256(_bytes(content)).hexdigest() != compiled.get("composition_sha256")
    ):
        raise CIGraphError("lifecycle composition projection identity is invalid")

    def display(value: Any) -> str:
        text = value if isinstance(value, str) else _bytes(value).decode()
        return html.escape(text, quote=True).replace("|", "&#124;").replace("\n", "<br>")

    rows = compiled["relationships"]
    states = sorted({(row["context"], row[key]) for row in rows for key in ("producer", "consumer")})
    nodes = {state: f"n{index}" for index, state in enumerate(states)}
    lines = [
        "# Lifecycle composition", "",
        "Generated from the compiled machine contract; this view grants no authority.", "",
        f"Composition: `{compiled['composition_sha256']}`", "",
        "| Source identity | Value |", "| --- | --- |",
        *[f"| {display(key)} | {display(value)} |" for key, value in sorted(compiled["source"].items())],
        "", "```mermaid", "flowchart TD",
    ]
    for state in states:
        lines.append(f'  {nodes[state]}["{display(state[0])}: {display(state[1])}"]')
    for row in rows:
        if row["contract"] is not None:
            lines.append(
                f"  {nodes[(row['context'], row['producer'])]} --> "
                f"{nodes[(row['context'], row['consumer'])]}"
            )
    lines += ["```", "", "| Context | Producer | Consumer | Disposition |", "| --- | --- | --- | --- |"]
    for row in rows:
        disposition = row["exclusion"] if row["contract"] is None else "reachable"
        lines.append("| " + " | ".join(display(value) for value in (
            row["context"], row["producer"], row["consumer"], disposition,
        )) + " |")
    for row in rows:
        if row["contract"] is None:
            continue
        lines += [
            "", f"## {display(row['context'])}: {display(row['producer'])} → {display(row['consumer'])}",
            "", "| Contract field | Value |", "| --- | --- |",
            *[f"| {display(key)} | {display(value)} |" for key, value in sorted(row["contract"].items())],
        ]
    return "\n".join(lines) + "\n"
