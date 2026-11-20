"""Bind protected public policy captures to existing lifecycle source roots.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, NamedTuple

from .ci_graph_errors import CIGraphError
from .semantic_authority_contracts import (
    SemanticAuthorityError, load_application_operations, load_committed_application_operations,
    _required_operation_population, _discover_population,
)


class _PublicOperationCapture(NamedTuple):
    """Local source binding; caller authenticates the protected actor and roots."""
    registry: Any
    metadata: dict[str, Any]
    relationship_roots: dict
    policy_root: Path
    runtime_root: Path
    policy_subject: tuple[str, str]
    runtime_subject: tuple[str, str]
    registry_sha256: str
    bindings: tuple
    roots: tuple
    runtime_policy_sha256: str | None
    runtime_claims_sha256: str | None = None


def _runtime_qualification_policy(registry, policy_root, policy_subject):
    """Bind declarations to canonical protected claims; grant no runtime credit."""
    from .semantic_source_paths import committed_regular_blob_capture
    from .semantic_yaml import load_unique_mapping_text
    from .evidence_planning import parse_claim_model

    declarations = [row for operation in registry.operations
                    for row in operation.get("runtime_qualifications", [])]
    if not declarations:
        return None
    try:
        identity, raw = committed_regular_blob_capture(policy_root,
            path="governance/gate-contracts.yml", **policy_subject)
        model = parse_claim_model(load_unique_mapping_text(raw.decode("utf-8")))
        for declaration in declarations:
            for claim_id in declaration["claims"]:
                claim = model["claims"].get(claim_id)
                if (not isinstance(claim, dict) or claim.get("qualification_scope") != "subject"
                        or not set(declaration["profiles"]) <= set(claim.get("profiles", []))
                        or model["execution_groups"][claim["execution_group"]].get("captured_by_preflight") is True):
                    raise ValueError("runtime qualification requires a subject-qualified executable claim/profile")
    except (OSError, TypeError, KeyError, UnicodeError, ValueError) as exc:
        raise CIGraphError(f"public operation runtime qualification policy is invalid: {exc}") from exc
    return identity["sha256"]


def _reauthenticate_public_operation_capture(capture, *, repo_root=None, inventory=None):
    """Recheck concrete source bindings, never a candidate authority assertion."""
    from .semantic_operation_python import _inventory_source_subject
    from .semantic_source_paths import committed_application_registry_identity, committed_regular_blob_capture

    if type(capture) is not _PublicOperationCapture:
        raise CIGraphError("public operation capture is incompatible")
    policy_subject = dict(zip(("commit_sha", "tree_sha"), capture.policy_subject))
    runtime_subject = dict(zip(("commit_sha", "tree_sha"), capture.runtime_subject))
    try:
        identity, raw = committed_regular_blob_capture(capture.policy_root,
            path="governance/application-operations.yml", **policy_subject)
        identity["registry_sha256"] = identity.pop("sha256")
        registry = load_application_operations(capture.policy_root,
            expected_sha256=capture.registry_sha256, source_bytes=raw)
    except (SemanticAuthorityError, OSError, ValueError) as exc:
        raise CIGraphError(f"public operation protected policy moved after capture: {exc}") from exc
    if identity["registry_sha256"] != capture.registry_sha256 or registry != capture.registry:
        raise CIGraphError("public operation protected policy capture was modified")
    expected = dict(operations_checked=len(registry.operations), policy_subject=identity["subject"],
        policy_blob_oid=identity["blob_oid"], registry_sha256=identity["registry_sha256"],
        bindings=capture.bindings, runtime_subject=runtime_subject)
    if capture.runtime_policy_sha256 is not None:
        try:
            runtime_policy = committed_application_registry_identity(capture.runtime_root, **runtime_subject)
        except (OSError, ValueError) as exc:
            raise CIGraphError(f"public operation runtime policy source is unavailable: {exc}") from exc
        if runtime_policy["registry_sha256"] != capture.runtime_policy_sha256:
            raise CIGraphError("public operation runtime policy source differs from capture")
        expected.update(runtime_policy_sha256=capture.runtime_policy_sha256,
            policy_changed=capture.runtime_policy_sha256 != capture.registry_sha256)
    claims_sha = _runtime_qualification_policy(registry, capture.policy_root, policy_subject)
    if claims_sha != capture.runtime_claims_sha256:
        raise CIGraphError("public operation runtime qualification policy differs from capture")
    if claims_sha is not None:
        expected["runtime_claims_sha256"] = claims_sha
    if capture.metadata != expected:
        raise CIGraphError("public operation capture metadata contradicts source binding")
    roots = {pair: frozenset(values) for pair, values in capture.roots}
    if capture.relationship_roots != roots:
        raise CIGraphError("public operation lifecycle roots differ from capture")
    if inventory is not None:
        try:
            subject = _inventory_source_subject(inventory)
        except ValueError as exc:
            raise CIGraphError("public operation runtime subject differs from capture") from exc
        if repo_root.resolve() != capture.runtime_root or subject != runtime_subject:
            raise CIGraphError("public operation runtime subject differs from capture")
    return registry


def capture_public_operation_bindings(
    repo_root: Path, *, policy_subject, runtime_subject, required_relationships, relationship_roots,
    policy_repo_root: Path | None = None,
):
    """Capture protected policy separately; caller authenticates actor/source custody."""
    if not isinstance(policy_subject, Mapping) or set(policy_subject) != {"commit_sha", "tree_sha"}:
        raise CIGraphError("public operation binding requires exact consumer policy subject")
    if not isinstance(runtime_subject, Mapping) or set(runtime_subject) != {"commit_sha", "tree_sha"}:
        raise CIGraphError("public operation binding requires exact runtime source subject")
    policy_subject = dict(policy_subject)
    runtime_subject = dict(runtime_subject)
    if policy_repo_root is not None and not isinstance(policy_repo_root, Path):
        raise CIGraphError("public operation policy root must be a repository Path")
    policy_root = (repo_root if policy_repo_root is None else policy_repo_root).resolve()
    if not isinstance(required_relationships, Mapping):
        raise CIGraphError("public operation binding requires independent relationships")
    bindings = dict(required_relationships)
    if any(not isinstance(key, str) or not key or not isinstance(pairs, frozenset) or not pairs
           or any(pair not in relationship_roots for pair in pairs)
           for key, pairs in bindings.items()):
        raise CIGraphError("public operation binding relationship population is empty or unknown")
    try:
        registry, identity = load_committed_application_operations(
            policy_root, policy_commit_sha=policy_subject["commit_sha"], policy_tree_sha=policy_subject["tree_sha"],
        )
    except (SemanticAuthorityError, OSError, ValueError) as exc:
        raise CIGraphError(f"public operation policy capture failed: {exc}") from exc
    claims_sha = _runtime_qualification_policy(registry, policy_root, policy_subject)
    if bindings.keys() != {operation["id"] for operation in registry.operations}:
        raise CIGraphError("public operation binding omits or invents required operations")
    try:
        populations = {row["id"]: _discover_population(repo_root, row, source_subject=dict(runtime_subject))
                       for row in registry.populations}
    except (SemanticAuthorityError, OSError, ValueError) as exc:
        raise CIGraphError(f"public operation catalog capture failed: {exc}") from exc
    classified = set()
    for operation in registry.operations:
        slot = (operation["population"], operation["population_key"])
        actual = populations[slot[0]].get(slot[1])
        if slot in classified or actual is None or operation["entrypoints"] != [actual]:
            raise CIGraphError("public operation entrypoint contradicts its exact source catalog")
        classified.add(slot)
    if classified != {(population, key) for population, entries in populations.items() for key in entries}:
        missing = sorted(f"{population}:{key}" for population, entries in populations.items()
                         for key in entries if (population, key) not in classified)
        raise CIGraphError("unclassified public application operations: " + ", ".join(missing))
    roots = {pair: frozenset(values) for pair, values in relationship_roots.items()}
    metadata = dict(
        operations_checked=len(registry.operations), policy_subject=identity["subject"], runtime_subject=runtime_subject,
        policy_blob_oid=identity["blob_oid"], registry_sha256=identity["registry_sha256"],
        bindings=tuple(sorted((key, tuple(sorted(pairs))) for key, pairs in bindings.items())),
    )
    if claims_sha is not None:
        metadata["runtime_claims_sha256"] = claims_sha
    runtime_policy_sha256 = None
    if policy_repo_root is not None:
        from .semantic_source_paths import committed_application_registry_identity
        try:
            runtime_policy = committed_application_registry_identity(repo_root, **runtime_subject)
        except (OSError, ValueError) as exc:
            raise CIGraphError(f"public operation runtime policy observation failed: {exc}") from exc
        runtime_policy_sha256 = runtime_policy["registry_sha256"]
        metadata.update(runtime_policy_sha256=runtime_policy_sha256,
            policy_changed=runtime_policy_sha256 != identity["registry_sha256"])
    return _PublicOperationCapture(registry, metadata, roots, policy_root, repo_root.resolve(),
        tuple(policy_subject[key] for key in ("commit_sha", "tree_sha")),
        tuple(runtime_subject[key] for key in ("commit_sha", "tree_sha")),
        identity["registry_sha256"], metadata["bindings"],
        tuple(sorted((pair, tuple(sorted(values))) for pair, values in roots.items())), runtime_policy_sha256, claims_sha)


def validate_public_operation_capture(repo_root: Path, inventory: dict[str, Any], capture) -> dict[str, Any]:
    """Reuse one local factory capture; no caller-supplied capture ingress."""
    registry = _reauthenticate_public_operation_capture(capture, repo_root=repo_root, inventory=inventory)
    metadata, relationship_roots = capture.metadata, capture.relationship_roots
    try:
        population = _required_operation_population(repo_root, registry.raw, inventory, metadata["registry_sha256"])
    except SemanticAuthorityError as exc:
        raise CIGraphError(f"public operation source conformance failed: {exc}") from exc
    relationships = dict(metadata["bindings"])
    for operation, _, runtime_function in population["entrypoint_bindings"]:
        if any(runtime_function not in relationship_roots[pair] for pair in relationships[operation]):
            raise CIGraphError("public operation runtime function is absent from its lifecycle relationship")
    return dict(metadata, **population)


def validate_effect_binding_contexts(bindings, capture, compiled):
    """Close protected port contexts before source discovery; ports resolve later."""
    if capture is None:
        raise CIGraphError("effect binding requires protected public operations")
    if not isinstance(bindings, Mapping):
        raise CIGraphError("source effect bindings require a protected mapping")
    _reauthenticate_public_operation_capture(capture)
    relationships = dict(capture[1]["bindings"])
    for port, pairs in bindings.items():
        if (not isinstance(port, tuple) or len(port) != 4
                or any(not isinstance(value, str) or not value for value in port)
                or port[1] not in {"read", "mutation", "authority", "observation"}
                or port[2] not in {"function", "call"}
                or port[0] not in relationships or not isinstance(pairs, frozenset)
                or not pairs or any(pair not in relationships[port[0]] for pair in pairs)):
            raise CIGraphError("source effect binding context differs from protected public operation")

    from .ci_graph_composition import _bytes

    declared = {(*pair, _bytes(port).decode()) for port, pairs in bindings.items() for pair in pairs}
    if declared != _compiled_effect_population(compiled):
        raise CIGraphError("reconstructed declared effect population differs from compiled lifecycle")


def _compiled_effect_population(compiled):
    return {
        (row["context"], row["producer"], row["consumer"], effect)
        for row in compiled["relationships"] if row["contract"] is not None
        for effect in row["contract"]["effects"]
    }


def validate_reconstructed_effects(compiled, public_operations, bindings):
    """Project validated source rows through the existing effect population owner."""
    from .ci_graph_composition import lifecycle_effect_population

    effects = set()
    observed_ports = set()
    for operation, _, entrypoint, ports in public_operations["operations"]:
        keys = {(operation, *port) for port in ports}
        observed_ports.update(keys)
        observation = dict(
            operation=operation, entrypoint=entrypoint,
            effect_ports=[dict(classification=role, target_kind=kind, symbol=symbol)
                          for role, kind, symbol in ports],
            write_effect_count=sum(role == "mutation" for role, _, _ in ports),
            authority_effect_count=sum(role == "authority" for role, _, _ in ports),
        )
        effects.update(lifecycle_effect_population(
            [observation], expected_entrypoints={operation: entrypoint},
            effect_bindings={key: bindings[key] for key in keys if key in bindings},
        ))
    if observed_ports != bindings.keys():
        raise CIGraphError("reconstructed source effect bindings omit or invent ports")
    compiled_effects = _compiled_effect_population(compiled)
    if effects != compiled_effects:
        raise CIGraphError("reconstructed source effect population differs from compiled lifecycle")
    return dict(authority=False, execution_qualified=False,
                scope="protected_public_operation_static_effects_only",
                effects_checked=len(effects), bindings=tuple(sorted(effects)))
