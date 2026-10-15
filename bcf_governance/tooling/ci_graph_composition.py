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
from typing import Any, Iterable, Mapping, TYPE_CHECKING

from jsonschema import Draft202012Validator

from .ci_graph_errors import CIGraphError
from .semantic_operation_effects import (
    SemanticOperationEffectError, source_operation_call_population,
)

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
    Version 1.1 authored input omits runtime source identity; the complete bound
    envelope comes exclusively from the protected consumer in either version.
    Callers must obtain both expected populations from protected canonical owners,
    independently of the proposed payload. No result confers truth authority.
    """

    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise CIGraphError(f"lifecycle composition schema violation: {errors[0].message}")
    source_schema = schema.get("$defs", {}).get("source", schema["properties"]["source"])
    if not isinstance(expected_source, Mapping) or next(
        Draft202012Validator(source_schema).iter_errors(dict(expected_source)), None
    ) is not None:
        raise CIGraphError("lifecycle composition authenticated source identity is invalid")
    source = dict(expected_source)
    if payload["schema_version"] == "1.0" and payload["source"] != source:
        raise CIGraphError("lifecycle composition source identity differs from authenticated inputs")
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


def _validate_compiled_identity(compiled: dict[str, Any]) -> None:
    content = {key: value for key, value in compiled.items() if key != "composition_sha256"}
    if (
        compiled.get("authority") is not False
        or hashlib.sha256(_bytes(content)).hexdigest() != compiled.get("composition_sha256")
    ):
        raise CIGraphError("lifecycle composition projection identity is invalid")



def validate_lifecycle_bindings(
    compiled: dict[str, Any],
    *,
    expected_source: Mapping[str, str],
    source_inventory: dict[str, Any],
    collected_selectors: frozenset[str],
    required_negative_controls: Mapping[Relationship, Mapping[str, str]],
    required_call_edges: Mapping[Relationship, frozenset[tuple[str, str]]],
    required_fact_bindings: Mapping[Relationship, tuple[Mapping[str, str], ...]],
    required_operation_calls: Mapping[Relationship, Mapping[str, Mapping[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Resolve composition bindings against protected source/collection inputs.

    Use the existing semantic source inventory and verified pytest collection.
    Their authentication and completeness belong to the protected consumer, not
    this proposal. The independent control catalogue binds causes to exact test
    selectors for every reachable relationship. This checks static conformance;
    it never qualifies execution, freshness, or the behavior of a detector.
    Protected call obligations must resolve through the same source inventory;
    names alone cannot conceal a deleted call between retained functions.
    The protected fact catalogue binds every proposition and its source owners;
    candidate facts cannot choose their own verifier, authority, or freshness.
    When supplied by a protected caller, operation-call catalogues additionally
    bind exact discovered function closures through declared port boundaries.
    Their absence preserves the legacy query and establishes no reverse-effect
    completeness; even their presence cannot qualify execution or unknown effects.
    """

    _validate_compiled_identity(compiled)
    if compiled["source"] != dict(expected_source):
        raise CIGraphError("lifecycle binding source identity differs from authenticated inputs")
    functions: dict[str, dict[str, Any]] = {}
    for function in source_inventory.get("functions", []):
        symbol = function.get("symbol")
        if not isinstance(symbol, str) or not symbol or symbol in functions:
            raise CIGraphError("lifecycle binding runtime function inventory is ambiguous")
        functions[symbol] = function
    reachable = {
        (row["context"], row["producer"], row["consumer"]): row["contract"]
        for row in compiled["relationships"] if row["contract"] is not None
    }
    if reachable.keys() != required_negative_controls.keys():
        raise CIGraphError("lifecycle binding independent relationship population differs")
    if reachable.keys() != required_call_edges.keys():
        raise CIGraphError("lifecycle binding independent call population differs")
    if reachable.keys() != required_fact_bindings.keys():
        raise CIGraphError("lifecycle binding independent fact relationship population differs")
    if required_operation_calls is not None and (
        not isinstance(required_operation_calls, Mapping)
        or reachable.keys() != required_operation_calls.keys()
    ):
        raise CIGraphError("lifecycle binding independent operation call population differs")
    operation_populations_checked = 0
    fact_fields = {"id", "producer", "verifier", "subject_binding", "proposition", "authority", "freshness"}
    for pair, contract in reachable.items():
        expected_facts = required_fact_bindings[pair]
        if (
            not expected_facts
            or any(
                not isinstance(fact, Mapping) or set(fact) != fact_fields
                or any(not isinstance(value, str) or not value for value in fact.values())
                for fact in expected_facts
            )
            or len({fact["id"] for fact in expected_facts}) != len(expected_facts)
            or sorted(_bytes(dict(fact)) for fact in expected_facts) != sorted(_bytes(fact) for fact in contract["facts"])
        ):
            raise CIGraphError("lifecycle binding independent fact population differs or is invalid")
        for fact in expected_facts:
            for role in ("producer", "verifier"):
                if fact[role] not in functions:
                    raise CIGraphError(f"lifecycle binding fact source runtime function is absent: {fact[role]}")
        for field in ("implementation", "terminal_consumers"):
            for symbol in contract[field]:
                if symbol not in functions:
                    raise CIGraphError(f"lifecycle binding runtime function is absent: {symbol}")
        calls = required_call_edges[pair]
        if not calls and not contract["ci_edges"]:
            raise CIGraphError("lifecycle binding has no source call or CI transport")
        bound_functions = set(contract["implementation"]) | set(contract["terminal_consumers"])
        for caller, callee in calls:
            if caller not in bound_functions or callee not in bound_functions:
                raise CIGraphError("lifecycle binding source call endpoints are unbound")
            observed_calls = {
                call.get("called_symbol") for call in functions[caller].get("calls", [])
                if call.get("dispatch_resolution") != "unresolved"
            }
            if callee not in observed_calls:
                raise CIGraphError(f"lifecycle binding source call is absent or unresolved: {caller} -> {callee}")
        if required_operation_calls is not None:
            roots = bound_functions | {
                fact[role] for fact in expected_facts for role in ("producer", "verifier")
            }
            catalogue = required_operation_calls[pair]
            if not isinstance(catalogue, Mapping) or roots != catalogue.keys():
                raise CIGraphError("lifecycle binding independent operation call population roots differ")
            for root in sorted(roots):
                try:
                    observed = source_operation_call_population(root, source_inventory)
                    matches = _bytes(observed) == _bytes(catalogue[root])
                except (SemanticOperationEffectError, TypeError, ValueError) as exc:
                    raise CIGraphError("lifecycle binding operation call population is incompatible") from exc
                if not matches:
                    raise CIGraphError("lifecycle binding operation call population differs from protected source")
                operation_populations_checked += 1
        for field in ("positive_tests", "negative_tests"):
            for selector in contract[field]:
                if selector not in collected_selectors:
                    raise CIGraphError(f"lifecycle binding collected test is absent: {selector}")
        controls = required_negative_controls[pair]
        if (
            not controls
            or any(not isinstance(cause, str) or not cause for cause in controls)
            or any(not isinstance(selector, str) or not selector for selector in controls.values())
            or len(set(controls.values())) != len(controls)
            or set(controls.values()) != set(contract["negative_tests"])
        ):
            raise CIGraphError("lifecycle binding cause-specific negative-control population differs")
    result = {
        "authority": False,
        "execution_qualified": False,
        "composition_sha256": compiled["composition_sha256"],
        "reachable_relationships": len(reachable),
    }

    if required_operation_calls is not None:
        result["operation_call_populations_checked"] = operation_populations_checked
    return result


def render_lifecycle_composition(compiled: dict[str, Any], *, view: str = "bound") -> str:
    """Project complete compiled relationships into human or authored machine views.

    This returns bytes-to-save as text; reconciliation retains ownership of writes.
    Diagram node IDs are derived from context-qualified states, never caller code.
    The contract view is stable tracked material; exact subject and installed
    controller custody remain in the separately validated bound runtime envelope.
    """

    _validate_compiled_identity(compiled)
    if view not in {"bound", "contract", "machine"}:
        raise CIGraphError("lifecycle composition projection view is invalid")
    if view == "machine":
        return _bytes({
            "schema_version": "1.1", "relationships": compiled["relationships"],
        }).decode() + "\n"
    source = compiled["source"]
    identity = f"Composition: `{compiled['composition_sha256']}`"
    if view == "contract":
        source = {key: source[key] for key in ("graph_sha256", "ci_edges_sha256", "policy_sha256")}
        digest = hashlib.sha256(_bytes({
            "schema_version": compiled["schema_version"],
            "source": source,
            "relationships": compiled["relationships"],
        })).hexdigest()
        identity = f"Contract: `{digest}`; exact attempt custody remains in the bound runtime envelope."

    def display(value: Any) -> str:
        text = value if isinstance(value, str) else _bytes(value).decode()
        return html.escape(text, quote=True).replace("|", "&#124;").replace("\n", "<br>")

    rows = compiled["relationships"]
    states = sorted({(row["context"], row[key]) for row in rows for key in ("producer", "consumer")})
    nodes = {state: f"n{index}" for index, state in enumerate(states)}
    lines = [
        "# Lifecycle composition", "",
        "Generated from the compiled machine contract; this view grants no authority.", "",
        identity, "",
        "| Source identity | Value |", "| --- | --- |",
        *[f"| {display(key)} | {display(value)} |" for key, value in sorted(source.items())],
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
