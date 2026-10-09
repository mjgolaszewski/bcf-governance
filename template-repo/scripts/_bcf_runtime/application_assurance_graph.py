"""Compile one consumer-owned assurance graph into existing gate projections."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .affected_proof_closure import DEPENDENCY_CLASSES
from .evidence_planning import parse_claim_model


class ApplicationAssuranceGraphError(ValueError):
    """Raised when consumer assurance ownership is incomplete or ambiguous."""


def compile_legacy_gate_catalog(
    template: Mapping[str, Any], payload: Mapping[str, Any], raw_gates: Mapping[str, Any]
) -> dict[str, Any]:
    """Compile the legacy exact catalog path without allowing pack overrides."""

    configured = payload.get("gate_catalog", {})
    if not isinstance(configured, dict):
        raise ApplicationAssuranceGraphError(
            "profile config gate_catalog must be a mapping"
        )
    merged = deepcopy(dict(template))
    known_targets = {
        str(value.get("target"))
        for value in template.values()
        if isinstance(value, dict)
    }
    for gate_id, value in configured.items():
        if not isinstance(gate_id, str) or not gate_id or not isinstance(value, dict):
            raise ApplicationAssuranceGraphError(
                f"profile config gate_catalog entry {gate_id!r} is invalid or overrides a pack gate"
            )
        if gate_id in merged:
            if merged[gate_id] != value:
                raise ApplicationAssuranceGraphError(
                    f"profile config gate_catalog entry {gate_id!r} is invalid or overrides a pack gate"
                )
            continue
        target = value.get("target")
        if (
            not isinstance(target, str)
            or not target
            or target in known_targets
            or target not in raw_gates
            or value.get("status") != "required"
            or not isinstance(value.get("command_policy"), str)
            or not value.get("command_policy")
            or not isinstance(value.get("rationale"), str)
            or not value.get("rationale")
        ):
            raise ApplicationAssuranceGraphError(
                f"profile config gate_catalog entry {gate_id!r} is not an exact required custom gate"
            )
        merged[gate_id] = deepcopy(value)
        known_targets.add(target)
    return merged


def _string(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ApplicationAssuranceGraphError(f"{context} must be a non-empty string")
    return value


def _string_list(value: object, *, context: str, nonempty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (nonempty and not value)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        qualifier = "non-empty unique" if nonempty else "unique"
        raise ApplicationAssuranceGraphError(
            f"{context} must be a {qualifier} string list"
        )
    return list(value)


def _dependencies(
    raw: object, dependency_sets: Mapping[str, object], *, context: str
) -> dict[str, list[str]]:
    if not isinstance(raw, dict) or set(raw) != set(DEPENDENCY_CLASSES):
        raise ApplicationAssuranceGraphError(
            f"{context} must declare every dependency class exactly once"
        )
    result: dict[str, list[str]] = {}
    for dependency_class in DEPENDENCY_CLASSES:
        names = _string_list(raw[dependency_class], context=f"{context}.{dependency_class}")
        unknown = sorted(set(names) - set(dependency_sets))
        if unknown:
            raise ApplicationAssuranceGraphError(
                f"{context}.{dependency_class} names unknown dependency sets: "
                + ", ".join(unknown)
            )
        result[dependency_class] = names
    return result


def compile_application_assurance_graph(
    raw: object,
    *,
    pack_gates: Mapping[str, Any],
    pack_gate_catalog: Mapping[str, Any],
) -> dict[str, Any]:
    """Compile graph-owned claims, groups, gates and catalog projections once."""

    if not isinstance(raw, dict) or raw.get("version") != "1.0":
        raise ApplicationAssuranceGraphError(
            "application_assurance requires version 1.0"
        )
    dependency_sets = raw.get("dependency_sets")
    groups = raw.get("groups")
    if not isinstance(dependency_sets, dict) or not dependency_sets:
        raise ApplicationAssuranceGraphError(
            "application_assurance dependency_sets must be non-empty"
        )
    normalized_sets: dict[str, list[str]] = {}
    for name, patterns in dependency_sets.items():
        dependency_id = _string(name, context="application assurance dependency ID")
        normalized_sets[dependency_id] = _string_list(
            patterns,
            context=f"application_assurance.dependency_sets.{dependency_id}",
            nonempty=True,
        )
    non_proof = _string_list(
        raw.get("non_proof_dependencies", []),
        context="application_assurance.non_proof_dependencies",
    )
    unknown_non_proof = sorted(set(non_proof) - set(normalized_sets))
    if unknown_non_proof:
        raise ApplicationAssuranceGraphError(
            "application_assurance non-proof dependencies are unknown: "
            + ", ".join(unknown_non_proof)
        )
    if not isinstance(groups, dict) or not groups:
        raise ApplicationAssuranceGraphError(
            "application_assurance groups must be non-empty"
        )

    flat_groups: dict[str, dict[str, Any]] = {}
    flat_claims: dict[str, dict[str, Any]] = {}
    custom_gates: dict[str, dict[str, Any]] = {}
    custom_catalog: dict[str, dict[str, Any]] = {}
    catalog_targets = {
        str(value.get("target"))
        for value in pack_gate_catalog.values()
        if isinstance(value, dict) and isinstance(value.get("target"), str)
    }
    producers: set[str] = set()
    for group_key, group_raw in groups.items():
        group_id = _string(group_key, context="application assurance group ID")
        if not isinstance(group_raw, dict):
            raise ApplicationAssuranceGraphError(
                f"application_assurance.groups.{group_id} must be a mapping"
            )
        producer = _string(
            group_raw.get("producer"),
            context=f"application_assurance.groups.{group_id}.producer",
        )
        if producer in producers:
            raise ApplicationAssuranceGraphError(
                f"application assurance producer {producer} has multiple owners"
            )
        producers.add(producer)
        captured = group_raw.get("captured_by_preflight", False)
        if not isinstance(captured, bool):
            raise ApplicationAssuranceGraphError(
                f"application_assurance.groups.{group_id}.captured_by_preflight must be boolean"
            )
        depends_on = _string_list(
            group_raw.get("depends_on", []),
            context=f"application_assurance.groups.{group_id}.depends_on",
        )
        nested_claims = group_raw.get("claims")
        if not isinstance(nested_claims, dict) or not nested_claims:
            raise ApplicationAssuranceGraphError(
                f"application_assurance.groups.{group_id}.claims must be non-empty"
            )
        claim_ids: list[str] = []
        for claim_key, claim_raw in nested_claims.items():
            claim_id = _string(claim_key, context="application assurance claim ID")
            if claim_id in flat_claims:
                raise ApplicationAssuranceGraphError(
                    f"application assurance claim {claim_id} has multiple owners"
                )
            if not isinstance(claim_raw, dict):
                raise ApplicationAssuranceGraphError(
                    f"application assurance claim {claim_id} must be a mapping"
                )
            scope = claim_raw.get("qualification_scope")
            if scope not in {"none", "detector", "subject"}:
                raise ApplicationAssuranceGraphError(
                    f"application assurance claim {claim_id} qualification_scope is invalid"
                )
            profiles = _string_list(
                claim_raw.get("profiles"),
                context=f"application assurance claim {claim_id}.profiles",
                nonempty=True,
            )
            if set(profiles) - {"normal", "regulated", "self"}:
                raise ApplicationAssuranceGraphError(
                    f"application assurance claim {claim_id} profiles are invalid"
                )
            legacy_gate = claim_raw.get("legacy_gate", producer)
            legacy_gate_id = _string(
                legacy_gate,
                context=f"application assurance claim {claim_id}.legacy_gate",
            )
            claim: dict[str, Any] = {
                "truth": _string(
                    claim_raw.get("truth"),
                    context=f"application assurance claim {claim_id}.truth",
                ),
                "execution_group": group_id,
                "legacy_gate": legacy_gate_id,
                "dependencies": _dependencies(
                    claim_raw.get("dependencies"),
                    normalized_sets,
                    context=f"application assurance claim {claim_id}.dependencies",
                ),
                "qualification_scope": scope,
                "profiles": profiles,
            }
            for optional in ("whole_tree", "freshness_limit_seconds"):
                if optional in claim_raw:
                    claim[optional] = claim_raw[optional]
            if "whole_tree" in claim and not isinstance(claim["whole_tree"], bool):
                raise ApplicationAssuranceGraphError(
                    f"application assurance claim {claim_id}.whole_tree must be boolean"
                )
            if "freshness_limit_seconds" in claim and (
                isinstance(claim["freshness_limit_seconds"], bool)
                or not isinstance(claim["freshness_limit_seconds"], int)
                or claim["freshness_limit_seconds"] < 1
            ):
                raise ApplicationAssuranceGraphError(
                    f"application assurance claim {claim_id}.freshness_limit_seconds is invalid"
                )
            flat_claims[claim_id] = claim
            claim_ids.append(claim_id)
            if captured and legacy_gate_id not in pack_gates:
                gate = claim_raw.get("gate")
                if not isinstance(gate, dict):
                    raise ApplicationAssuranceGraphError(
                        f"preflight claim {claim_id} requires its legacy gate contract"
                    )
                if legacy_gate_id in custom_gates and custom_gates[legacy_gate_id] != gate:
                    raise ApplicationAssuranceGraphError(
                        f"preflight gate {legacy_gate_id} has multiple definitions"
                    )
                custom_gates[legacy_gate_id] = deepcopy(gate)
                if legacy_gate_id not in catalog_targets:
                    custom_catalog[legacy_gate_id] = {
                        "target": legacy_gate_id,
                        "status": "required",
                        "command_policy": _string(
                            claim_raw.get("command_policy"),
                            context=f"preflight claim {claim_id}.command_policy",
                        ),
                        "rationale": _string(
                            claim_raw.get("rationale"),
                            context=f"preflight claim {claim_id}.rationale",
                        ),
                    }
        flat_group: dict[str, Any] = {
            "producer": producer,
            "claims": sorted(claim_ids),
        }
        if captured:
            if depends_on or any(
                key in group_raw for key in ("gate", "command_policy", "rationale")
            ):
                raise ApplicationAssuranceGraphError(
                    f"preflight group {group_id} cannot own executable gate fields"
                )
            flat_group["captured_by_preflight"] = True
        else:
            flat_group["depends_on"] = depends_on
            if producer in pack_gates:
                if any(key in group_raw for key in ("gate", "command_policy", "rationale")):
                    raise ApplicationAssuranceGraphError(
                        f"pack gate {producer} cannot be overridden by application assurance"
                    )
            else:
                gate = group_raw.get("gate")
                if not isinstance(gate, dict):
                    raise ApplicationAssuranceGraphError(
                        f"application producer {producer} requires one gate contract"
                    )
                custom_gates[producer] = deepcopy(gate)
                if producer in catalog_targets:
                    if any(key in group_raw for key in ("command_policy", "rationale")):
                        raise ApplicationAssuranceGraphError(
                            f"pack catalog metadata for {producer} cannot be overridden"
                        )
                else:
                    custom_catalog[producer] = {
                        "target": producer,
                        "status": "required",
                        "command_policy": _string(
                            group_raw.get("command_policy"),
                            context=f"application producer {producer}.command_policy",
                        ),
                        "rationale": _string(
                            group_raw.get("rationale"),
                            context=f"application producer {producer}.rationale",
                        ),
                    }
        flat_groups[group_id] = flat_group

    for group_id, group in flat_groups.items():
        unknown = sorted(set(group.get("depends_on", [])) - set(flat_groups))
        if unknown:
            raise ApplicationAssuranceGraphError(
                f"application assurance group {group_id} has unknown dependencies: "
                + ", ".join(unknown)
            )
    collisions = sorted(set(custom_gates) & set(pack_gates))
    if collisions:
        raise ApplicationAssuranceGraphError(
            "application assurance cannot replace pack gates: " + ", ".join(collisions)
        )
    model = {
        "version": "1.0",
        "dependency_sets": normalized_sets,
        "non_proof_dependencies": non_proof,
        "execution_groups": flat_groups,
        "claims": flat_claims,
    }
    try:
        parse_claim_model(
            {"claim_model": model, "gates": {**deepcopy(dict(pack_gates)), **custom_gates}}
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ApplicationAssuranceGraphError(str(exc)) from exc
    return {
        "claim_model": model,
        "gates": custom_gates,
        "gate_catalog": custom_catalog,
    }
