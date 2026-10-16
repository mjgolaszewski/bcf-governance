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
import re
from pathlib import Path
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





def validate_backtrace_transition_references(
    transitions: Mapping[str, Mapping[str, Any]],
) -> int:
    """Resolve declared typed references through their existing single owner.

    Callers validate schema, duplicate identities and state populations first.
    Legacy rows without typed references retain their original readability.
    This is structural conformance, never guard or recovery authority.
    """

    for transition in transitions.values():
        if "guard_refs" not in transition:
            continue
        guards = transition["guard_refs"]
        if (not isinstance(guards, list) or not guards
                or any(not isinstance(value, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None
                       for value in guards)
                or len(set(guards)) != len(guards)):
            raise CIGraphError("lifecycle path guard reference population is malformed or duplicated")
    checked = 0
    for transition in transitions.values():
        for field, source_kind, target_kind in (
            ("rejection_transition", "success", "rejection"),
            ("retry_of", "recovery", "success"),
        ):
            if field not in transition:
                continue
            reference = transition[field]
            target = transitions.get(reference) if isinstance(reference, str) else None
            if (target is None or target["id"] == transition["id"]
                    or transition.get("kind") != source_kind or target.get("kind") != target_kind):
                raise CIGraphError("lifecycle path typed transition reference is undeclared self-referential or wrong-kind")
            if ("guard_refs" in transition or "guard_refs" in target) and (
                set(transition.get("guard_refs", [])) != set(target.get("guard_refs", []))
            ):
                raise CIGraphError("lifecycle path typed transition reference loses guard obligations")
            if field == "rejection_transition":
                if (transition["from"] != target["from"]
                        or not set(transition["invariants"]) <= set(target["invariants"])):
                    raise CIGraphError("lifecycle path typed transition reference loses rejection start or invariants")
            else:
                if not set(target["invariants"]) <= set(transition["invariants"]):
                    raise CIGraphError("lifecycle path typed transition reference loses recovery invariants")
                rejected_id = target.get("rejection_transition")
                rejection = transitions.get(rejected_id) if isinstance(rejected_id, str) else None
                if (rejection is None or rejection.get("kind") != "rejection"
                        or transition["from"] != rejection["to"] or transition["to"] != target["from"]):
                    raise CIGraphError("lifecycle path typed transition reference bypasses failed attempt")
            checked += 1
    return checked


def validate_lifecycle_paths(
    compiled: dict[str, Any],
    *,
    backtrace: dict[str, Any],
    expected_source: Mapping[str, str],
    expected_backtrace_sha256: str,
    required_states: Mapping[str, str],
    required_transition_bindings: Mapping[str, Relationship],
    required_recovery_limits: Mapping[str, int],
) -> dict[str, Any]:
    """Bind dormant paths to the existing backtrace and protected populations.

    The protected consumer authenticates the backtrace digest and independently
    reconstructs states, terminal classes, transition bindings and retry limits.
    This query neither invents those populations nor authenticates its caller.
    Legacy composition remains readable; untyped backtraces cannot pass here.
    Static path closure does not qualify runtime guards, effects or authority.
    """

    _validate_compiled_identity(compiled)
    if not isinstance(expected_source, Mapping) or compiled["source"] != dict(expected_source):
        raise CIGraphError("lifecycle path compiled source identity differs")
    if not isinstance(backtrace, Mapping):
        raise CIGraphError("lifecycle path backtrace is invalid")
    try:
        digest = hashlib.sha256(_bytes(backtrace)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise CIGraphError("lifecycle path backtrace is not canonical data") from exc
    if digest != expected_backtrace_sha256:
        raise CIGraphError("lifecycle path backtrace source identity differs")
    classes = {"none", "workitem", "phase", "release", "custody", "blocked"}
    if (
        not isinstance(required_states, Mapping) or not required_states
        or any(not isinstance(key, str) or not key or not isinstance(value, str) or value not in classes
               for key, value in required_states.items())
    ):
        raise CIGraphError("lifecycle path independent state population is invalid")
    state_rows = backtrace.get("states")
    transition_rows = backtrace.get("transitions")
    if not isinstance(state_rows, list) or not isinstance(transition_rows, list):
        raise CIGraphError("lifecycle path state or transition population is invalid")
    states: dict[str, Mapping[str, Any]] = {}
    for row in state_rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
            raise CIGraphError("lifecycle path state identity is invalid")
        identity = row["id"]
        if identity in states or identity not in required_states:
            raise CIGraphError("lifecycle path state population is duplicated or unbound")
        if row.get("terminal_class") != required_states[identity]:
            raise CIGraphError("lifecycle path terminal classification differs")
        states[identity] = row
    if states.keys() != required_states.keys():
        raise CIGraphError("lifecycle path state population is incomplete")
    reachable = {
        (row["context"], row["producer"], row["consumer"]): row["contract"]
        for row in compiled["relationships"] if row["contract"] is not None
    }
    if not isinstance(required_transition_bindings, Mapping) or not required_transition_bindings:
        raise CIGraphError("lifecycle path independent transition population is absent")
    for identity, pair in required_transition_bindings.items():
        if (not isinstance(identity, str) or not identity or not isinstance(pair, tuple)
                or len(pair) != 3 or any(not isinstance(v, str) for v in pair)
                or pair not in reachable):
            raise CIGraphError("lifecycle path transition relationship is unbound")
    transitions: dict[str, Mapping[str, Any]] = {}
    for row in transition_rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
            raise CIGraphError("lifecycle path transition identity is invalid")
        identity = row["id"]
        if identity in transitions or identity not in required_transition_bindings:
            raise CIGraphError("lifecycle path transition population is duplicated or unbound")
        if (not isinstance(row.get("kind"), str)
                or row["kind"] not in {"success", "rejection", "recovery"}
                or not isinstance(row.get("from"), str) or row["from"] not in states
                or not isinstance(row.get("to"), str) or row["to"] not in states):
            raise CIGraphError("lifecycle path transition kind or state reference is unbound")
        invariants = row.get("invariants")
        if (not isinstance(invariants, list) or not invariants
                or any(not isinstance(v, str) or not v for v in invariants)
                or len(set(invariants)) != len(invariants)):
            raise CIGraphError("lifecycle path transition invariants are invalid")
        transitions[identity] = row
    if transitions.keys() != required_transition_bindings.keys():
        raise CIGraphError("lifecycle path transition population is incomplete")
    validate_backtrace_transition_references(transitions)
    recoveries = {key: row for key, row in transitions.items() if row["kind"] == "recovery"}
    if not isinstance(required_recovery_limits, Mapping) or recoveries.keys() != required_recovery_limits.keys():
        raise CIGraphError("lifecycle path independent recovery population differs")
    guard_obligations_checked = 0
    successes: dict[Relationship, str] = {}
    claimed_rejections: set[str] = set()
    claimed_recoveries: set[str] = set()
    for identity, row in transitions.items():
        if row["kind"] != "success":
            continue
        pair = required_transition_bindings[identity]
        if pair in successes:
            raise CIGraphError("lifecycle path success population is ambiguous")
        successes[pair] = identity
        contract = reachable[pair]
        expected_guards = {
            "sha256:" + hashlib.sha256(_bytes(guard)).hexdigest()
            for guard in contract["guards"]
        }
        if set(row.get("guard_refs", [])) != expected_guards:
            raise CIGraphError("lifecycle path compiled guard obligation population differs")
        guard_obligations_checked += len(expected_guards)
        rejection_id = row.get("rejection_transition")
        rejection = transitions.get(rejection_id) if isinstance(rejection_id, str) else None
        if (rejection is None or rejection["kind"] != "rejection"
                or required_transition_bindings[rejection_id] != pair
                or rejection_id in claimed_rejections
                or required_states[rejection["to"]] != "blocked"):
            raise CIGraphError("lifecycle path rejection is absent ambiguous or unbound")
        claimed_rejections.add(rejection_id)
        if contract["successor"] != row["to"] or contract["rejection"] != rejection["to"]:
            raise CIGraphError("lifecycle path composition outcome is unbound")
        recovery_id = contract["recovery"]
        if recovery_id == "none":
            continue
        recovery = recoveries.get(recovery_id)
        if (recovery is None or recovery_id in claimed_recoveries
                or required_transition_bindings[recovery_id] != pair
                or recovery.get("retry_of") != identity):
            raise CIGraphError("lifecycle path recovery does not preserve its failed attempt")
        limit = recovery.get("max_attempts")
        approved = required_recovery_limits[recovery_id]
        if (isinstance(limit, bool) or not isinstance(limit, int) or limit < 1
                or isinstance(approved, bool) or not isinstance(approved, int)
                or limit != approved):
            raise CIGraphError("lifecycle path recovery attempt limit is unbound")
        claimed_recoveries.add(recovery_id)
    if successes.keys() != reachable.keys():
        raise CIGraphError("lifecycle path successful relationship population is incomplete")
    if claimed_rejections != {key for key, row in transitions.items() if row["kind"] == "rejection"}:
        raise CIGraphError("lifecycle path rejection population is incomplete")
    if claimed_recoveries != recoveries.keys():
        raise CIGraphError("lifecycle path recovery population is incomplete")
    # Removing bounded inter-attempt recovery must leave an acyclic attempt.
    outgoing: dict[str, list[str]] = {key: [] for key in states}
    indegree = {key: 0 for key in states}
    for row in transitions.values():
        if row["kind"] == "recovery":
            continue
        if required_states[row["from"]] != "none":
            raise CIGraphError("lifecycle path terminal has an outgoing attempt edge")
        outgoing[row["from"]].append(row["to"])
        indegree[row["to"]] += 1
    ready = [key for key in states if not indegree[key]]
    visited = 0
    while ready:
        node = ready.pop()
        visited += 1
        for successor in outgoing[node]:
            indegree[successor] -= 1
            if not indegree[successor]:
                ready.append(successor)
    if visited != len(states):
        raise CIGraphError("lifecycle path concrete attempt contains a cycle")
    return {
        "authority": False, "execution_qualified": False,
        "composition_sha256": compiled["composition_sha256"],
        "backtrace_sha256": digest, "states_checked": len(states),
        "transitions_checked": len(transitions), "recoveries_checked": len(recoveries),
        "guard_obligations_checked": guard_obligations_checked,
    }


def _binding_declarations(
    compiled, expected_source, collected_selectors, required_negative_controls,
    required_call_edges, required_fact_bindings, required_operation_calls,
):
    _validate_compiled_identity(compiled)
    if not isinstance(expected_source, Mapping) or compiled["source"] != dict(expected_source):
        raise CIGraphError("lifecycle binding source identity differs from authenticated inputs")
    reachable = {
        (row["context"], row["producer"], row["consumer"]): row["contract"]
        for row in compiled["relationships"] if row["contract"] is not None
    }
    if not isinstance(required_negative_controls, Mapping) or reachable.keys() != required_negative_controls.keys():
        raise CIGraphError("lifecycle binding independent relationship population differs")
    if not isinstance(required_call_edges, Mapping) or reachable.keys() != required_call_edges.keys():
        raise CIGraphError("lifecycle binding independent call population differs")
    if not isinstance(required_fact_bindings, Mapping) or reachable.keys() != required_fact_bindings.keys():
        raise CIGraphError("lifecycle binding independent fact relationship population differs")
    if required_operation_calls is not None and (
        not isinstance(required_operation_calls, Mapping)
        or reachable.keys() != required_operation_calls.keys()
    ):
        raise CIGraphError("lifecycle binding independent operation call population differs")
    if not isinstance(collected_selectors, (set, frozenset)) or any(
        not isinstance(selector, str) or not selector for selector in collected_selectors
    ):
        raise CIGraphError("lifecycle binding collected test population is malformed")
    fact_fields = {"id", "producer", "verifier", "subject_binding", "proposition", "authority", "freshness"}
    for pair, contract in reachable.items():
        expected_facts = required_fact_bindings[pair]
        if (
            not isinstance(expected_facts, (tuple, list)) or not expected_facts
            or any(
                not isinstance(fact, Mapping) or set(fact) != fact_fields
                or any(not isinstance(value, str) or not value for value in fact.values())
                for fact in expected_facts
            )
            or len({fact["id"] for fact in expected_facts}) != len(expected_facts)
            or sorted(_bytes(dict(fact)) for fact in expected_facts) != sorted(_bytes(fact) for fact in contract["facts"])
        ):
            raise CIGraphError("lifecycle binding independent fact population differs or is invalid")
        calls = required_call_edges[pair]
        bound_functions = set(contract["implementation"]) | set(contract["terminal_consumers"])
        if not isinstance(calls, (set, frozenset, tuple, list)) or any(
            not isinstance(edge, (tuple, list)) or len(edge) != 2
            or any(not isinstance(value, str) or value not in bound_functions for value in edge)
            for edge in calls
        ):
            raise CIGraphError("lifecycle binding source call endpoints are unbound or malformed")
        if not calls and not contract["ci_edges"]:
            raise CIGraphError("lifecycle binding has no source call or CI transport")
        for field in ("positive_tests", "negative_tests"):
            for selector in contract[field]:
                if selector not in collected_selectors:
                    raise CIGraphError(f"lifecycle binding collected test is absent: {selector}")
        controls = required_negative_controls[pair]
        if (
            not isinstance(controls, Mapping) or not controls
            or any(not isinstance(cause, str) or not cause for cause in controls)
            or any(not isinstance(selector, str) or not selector for selector in controls.values())
            or len(set(controls.values())) != len(controls)
            or set(controls.values()) != set(contract["negative_tests"])
        ):
            raise CIGraphError("lifecycle binding cause-specific negative-control population differs")
    return reachable


def _binding_operation_roots(contract):
    return set(contract["implementation"]) | set(contract["terminal_consumers"]) | {
        fact[role] for fact in contract["facts"] for role in ("producer", "verifier")
    }


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
    Protected initialization scopes additionally bind all discovered module facts.
    Their absence preserves the legacy query and establishes no reverse-effect
    completeness; even their presence cannot qualify execution or unknown effects.
    """

    reachable = _binding_declarations(
        compiled, expected_source, collected_selectors, required_negative_controls,
        required_call_edges, required_fact_bindings, required_operation_calls,
    )
    functions: dict[str, dict[str, Any]] = {}
    for function in source_inventory.get("functions", []):
        symbol = function.get("symbol")
        if not isinstance(symbol, str) or not symbol or symbol in functions:
            raise CIGraphError("lifecycle binding runtime function inventory is ambiguous")
        functions[symbol] = function
    operation_populations_checked = 0
    for pair, contract in reachable.items():
        expected_facts = required_fact_bindings[pair]
        for fact in expected_facts:
            for role in ("producer", "verifier"):
                if fact[role] not in functions:
                    raise CIGraphError(f"lifecycle binding fact source runtime function is absent: {fact[role]}")
        for field in ("implementation", "terminal_consumers"):
            for symbol in contract[field]:
                if symbol not in functions:
                    raise CIGraphError(f"lifecycle binding runtime function is absent: {symbol}")
        calls = required_call_edges[pair]
        for caller, callee in calls:
            observed_calls = {
                call.get("called_symbol") for call in functions[caller].get("calls", [])
                if call.get("dispatch_resolution") != "unresolved"
            }
            if callee not in observed_calls:
                raise CIGraphError(f"lifecycle binding source call is absent or unresolved: {caller} -> {callee}")
        if required_operation_calls is not None:
            roots = _binding_operation_roots(contract)
            catalogue = required_operation_calls[pair]
            if not isinstance(catalogue, Mapping) or roots != catalogue.keys():
                raise CIGraphError("lifecycle binding independent operation call population roots differ")
            for root in sorted(roots):
                try:
                    expected = catalogue[root]
                    include_initialization = isinstance(expected, Mapping) and expected.get("scope") == (
                        "discovered_python_functions_and_possible_initialization"
                    )
                    observed = source_operation_call_population(
                        root, source_inventory, include_initialization=include_initialization
                    )
                    matches = _bytes(observed) == _bytes(catalogue[root])
                except (SemanticOperationEffectError, TypeError, ValueError) as exc:
                    raise CIGraphError("lifecycle binding operation call population is incompatible") from exc
                if not matches:
                    raise CIGraphError("lifecycle binding operation call population differs from protected source")
                operation_populations_checked += 1
    result = {
        "authority": False,
        "execution_qualified": False,
        "composition_sha256": compiled["composition_sha256"],
        "reachable_relationships": len(reachable),
    }

    if required_operation_calls is not None:
        result["operation_call_populations_checked"] = operation_populations_checked
    return result



def validate_reconstructed_lifecycle_bindings(
    repo_root: Path, *, compiled: dict[str, Any], expected_source: Mapping[str, str],
    collected_selectors: frozenset[str],
    required_negative_controls: Mapping[Relationship, Mapping[str, str]],
    required_call_edges: Mapping[Relationship, frozenset[tuple[str, str]]],
    required_fact_bindings: Mapping[Relationship, tuple[Mapping[str, str], ...]],
    required_operation_calls: Mapping[Relationship, Mapping[str, Mapping[str, Any]]],
    source_import_roots: tuple[str, ...] = (".",),
    required_ci_graph: CompiledCIGraph | None = None,
    operation_policy_subject: Mapping[str, str] | None = None,
    required_public_operation_relationships: Mapping[str, frozenset[Relationship]] | None = None,
    required_effect_bindings: Mapping[tuple[str, str, str, str], frozenset[Relationship]] | None = None,
) -> dict[str, Any]:
    """Reconstruct exact source inputs; caller authenticates protected context."""
    from .semantic_ownership_inventory import (
        SemanticInventoryError, discover_python_source, resolve_python_imports, validate_python_import_roots,
    )

    reachable = _binding_declarations(
        compiled, expected_source, collected_selectors, required_negative_controls,
        required_call_edges, required_fact_bindings, required_operation_calls,
    )
    ci_coverage = validate_lifecycle_ci_edge_coverage(
        compiled, compiled_graph=required_ci_graph, expected_source=expected_source,
    ) if required_ci_graph is not None else None
    if required_operation_calls is None:
        raise CIGraphError("reconstructed binding requires complete operation populations")
    for pair, contract in reachable.items():
        catalogue = required_operation_calls[pair]
        if not isinstance(catalogue, Mapping) or catalogue.keys() != _binding_operation_roots(contract):
            raise CIGraphError("reconstructed binding operation source roots differ")
        if any(not isinstance(population, Mapping) or population.get("scope") != (
                "discovered_python_functions_and_possible_initialization"
        ) or population.get("authority") is not False
            or population.get("execution_qualified") is not False
            or population.get("completeness_qualified") is not False
            for population in catalogue.values()):
            raise CIGraphError("reconstructed binding requires initialization-aware source populations")
    try:
        source_import_roots = validate_python_import_roots(repo_root, source_import_roots)
    except (SemanticInventoryError, OSError, TypeError, ValueError) as exc:
        raise CIGraphError(f"lifecycle binding exact source reconstruction failed: {exc}") from exc
    from .ci_graph_composition_operations import capture_public_operation_bindings, validate_public_operation_capture

    capture = None
    if operation_policy_subject is not None or required_public_operation_relationships is not None:
        capture = capture_public_operation_bindings(
            repo_root, policy_subject=operation_policy_subject,
            required_relationships=required_public_operation_relationships,
            relationship_roots={pair: _binding_operation_roots(contract) for pair, contract in reachable.items()},
        )
    if required_effect_bindings is not None:
        from .ci_graph_composition_operations import validate_effect_binding_contexts

        validate_effect_binding_contexts(required_effect_bindings, capture, compiled)
    subject = {key: expected_source[key] for key in ("commit_sha", "tree_sha")}
    try:
        inventory = discover_python_source(
            repo_root, source_subject=subject, call_contracts_version="1.0",
            import_roots=source_import_roots,
            initialization_contracts_version="1.0",
        )
        inventory = resolve_python_imports(repo_root, inventory, source_import_roots)
    except (SemanticInventoryError, OSError, TypeError, ValueError) as exc:
        raise CIGraphError(f"lifecycle binding exact source reconstruction failed: {exc}") from exc
    public_operations = validate_public_operation_capture(repo_root, inventory, capture) if capture is not None else None
    result = validate_lifecycle_bindings(
        compiled, expected_source=expected_source, source_inventory=inventory,
        collected_selectors=collected_selectors, required_negative_controls=required_negative_controls,
        required_call_edges=required_call_edges, required_fact_bindings=required_fact_bindings,
        required_operation_calls=required_operation_calls,
    )
    if ci_coverage is not None:
        result["ci_edge_coverage"] = ci_coverage
    if public_operations is not None:
        result["public_operation_bindings"] = public_operations
    if required_effect_bindings is not None:
        from .ci_graph_composition_operations import validate_reconstructed_effects

        result["source_effect_bindings"] = validate_reconstructed_effects(
            compiled, public_operations, required_effect_bindings,
        )
    result["source_reconstruction"] = {
        "subject": dict(subject),
        "population_sha256": hashlib.sha256(_bytes(inventory["source_population"])).hexdigest(),
        "import_roots": tuple(sorted(source_import_roots)),
    }
    return result


def render_lifecycle_composition(compiled: dict[str, Any], *, view: str = "bound") -> str:
    """Project complete compiled relationships into human or authored machine views.

    This returns bytes-to-save as text; reconciliation retains ownership of writes.
    Diagram node IDs are derived from context-qualified states, never caller code.
    The contract view is stable tracked material; exact subject and installed
    controller custody remain in the separately validated bound runtime envelope.
    """

    _validate_compiled_identity(compiled)
    from .ci_graph_composition_views import _render_lifecycle_composition

    return _render_lifecycle_composition(compiled, view=view)


def validate_lifecycle_ci_edge_coverage(
    compiled: dict[str, Any], *, compiled_graph: CompiledCIGraph,
    expected_source: Mapping[str, str],
) -> dict[str, Any]:
    """Observe all canonical CI references; caller authenticates source/custody.

    Partial compilation remains readable. This explicit conformance requires all
    reachable edges and projects unreachable exclusions from the existing owner;
    neither a matching digest nor complete references qualify runtime authority.
    """
    _validate_compiled_identity(compiled)
    source = compiled["source"]
    if (not isinstance(expected_source, Mapping) or source != dict(expected_source)
            or source["graph_sha256"] != compiled_graph.graph_sha256
            or source["ci_edges_sha256"] != edge_population_sha256(compiled_graph)):
        raise CIGraphError("lifecycle CI edge coverage source identity differs")
    edges = {(edge.producer, edge.consumer): edge for edge in compiled_graph.edge_contracts}
    if len(edges) != len(compiled_graph.edge_contracts):
        raise CIGraphError("lifecycle CI edge coverage canonical population has duplicate pairs")
    if any(not isinstance(edge.reachable, bool) or (not edge.reachable and (
            not isinstance(edge.exclusion_reason, str) or not edge.exclusion_reason)) for edge in edges.values()):
        raise CIGraphError("lifecycle CI edge coverage canonical exclusion is ungrounded")
    required = {pair for pair, edge in edges.items() if edge.reachable}
    bindings: dict[tuple[str, str], set[Relationship]] = {}
    for row in compiled["relationships"]:
        if row["contract"] is None:
            continue
        for reference in row["contract"]["ci_edges"]:
            pair = reference["producer"], reference["consumer"]
            if pair not in required:
                raise CIGraphError("lifecycle CI edge coverage reference is absent or unreachable")
            bindings.setdefault(pair, set()).add((row["context"], row["producer"], row["consumer"]))
    if bindings.keys() != required:
        raise CIGraphError("lifecycle CI edge coverage is incomplete")
    return {
        "authority": False, "execution_qualified": False,
        "scope": "canonical_ci_edge_reference_coverage",
        "composition_sha256": compiled["composition_sha256"],
        "ci_edges_sha256": source["ci_edges_sha256"],
        "reachable_edges_checked": len(required),
        "ci_edge_bindings": tuple((producer, consumer, tuple(sorted(bindings[(producer, consumer)])))
                                  for producer, consumer in sorted(bindings)),
        "canonical_exclusions": tuple((producer, consumer, edge.exclusion_reason)
                                      for (producer, consumer), edge in sorted(edges.items()) if not edge.reachable),
    }
