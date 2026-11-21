"""Bind protected public policy captures to existing lifecycle source roots.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import hashlib
import json
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


def validate_public_operation_capture(repo_root: Path, inventory: dict[str, Any], capture, *, runtime_contexts=None) -> dict[str, Any]:
    """Reuse one local factory capture; no caller-supplied capture ingress."""
    registry = _reauthenticate_public_operation_capture(capture, repo_root=repo_root, inventory=inventory)
    if runtime_contexts is not None:
        operations = {row["id"] for row in registry.operations}
        if (type(runtime_contexts) is not dict or set(runtime_contexts) - operations
                or any(type(context) is not _OperationRuntimeContext
                       or context.operation_id != operation or context.public_capture != capture
                       for operation, context in runtime_contexts.items())):
            raise CIGraphError("runtime context differs from consuming protected operation capture")
    metadata, relationship_roots = capture.metadata, capture.relationship_roots
    try:
        population = _required_operation_population(repo_root, registry.raw, inventory, metadata["registry_sha256"], runtime_contexts=runtime_contexts)
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


class _OperationRuntimeContext(NamedTuple):
    public_capture: Any
    operation_id: str
    evidence_root: Path
    native_subject: tuple[str, str]
    inventory_sha256: str
    statement: str
    receipts: tuple
    sites: tuple


def _runtime_inventory_digest(inventory):
    """Freeze only native data; caller objects cannot run during qualification."""
    pending, seen = [inventory], set()
    while pending:
        value = pending.pop()
        if type(value) in {list, tuple, dict}:
            if id(value) in seen:
                continue
            seen.add(id(value))
            if type(value) is dict:
                if any(type(key) is not str for key in value):
                    raise CIGraphError("runtime context inventory has nonnative keys")
                pending.extend(value.values())
            else:
                pending.extend(value)
        elif type(value) not in {str, int, float, bool, type(None)}:
            raise CIGraphError("runtime context inventory contains caller objects")
    digest = hashlib.sha256()
    try:
        for chunk in json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False).iterencode(inventory):
            digest.update(chunk.encode())
    except (TypeError, ValueError, RecursionError) as exc:
        raise CIGraphError("runtime context inventory is not closed native data") from exc
    return digest.hexdigest()


def capture_operation_runtime_context(repo_root, inventory, public_capture, *, operation_id, evidence_root, native_subject):
    """Bind approved model evidence to scope; actor authenticates roots/native selection.

    The actor must authenticate evidence collection custody and protected producer
    source provenance, including model-premise evaluation for the selected native
    implementation and namespace. Candidate receipts alone cannot establish this. This
    constructor is not a candidate ingress or a native/runtime security approval.
    """
    from .evidence_claim_resolution import capture_claim_policy, _claim_policy_inputs, eligible_claim_receipts
    from .evidence_gate_contracts import expected_evidence_kinds, expected_invocations
    from .evidence_planning import assurance_scope
    from .truth_receipts import load_receipts, ReceiptError
    from .semantic_operation_effects import _source_function_population
    from .semantic_authority_operations import _validate_python_call_source_coverage
    from .semantic_authority_contracts import _function_for_entrypoint
    from .semantic_source_paths import committed_regular_blob_capture
    from .semantic_ownership_protocols import cli_snapshot_model_sites

    keys = ("implementation_sha256", "namespace_sha256")
    if (type(native_subject) is not dict or set(native_subject) != set(keys)
            or any(type(native_subject[key]) is not str or len(native_subject[key]) != 64
                   or any(character not in "0123456789abcdef" for character in native_subject[key]) for key in keys)):
        raise CIGraphError("runtime context requires an exact selected native scope")
    if not isinstance(evidence_root, Path):
        raise CIGraphError("runtime context requires an authenticated evidence root")
    inventory_sha = _runtime_inventory_digest(inventory)
    registry = _reauthenticate_public_operation_capture(public_capture, repo_root=repo_root, inventory=inventory)
    source_subject = dict(zip(("commit_sha", "tree_sha"), public_capture.runtime_subject))
    policy_subject = dict(zip(("commit_sha", "tree_sha"), public_capture.policy_subject))
    matches = [row for row in registry.operations if row["id"] == operation_id]
    if len(matches) != 1:
        raise CIGraphError("runtime context operation is absent or ambiguous")
    operation = matches[0]
    try:
        policy = _claim_policy_inputs(capture_claim_policy(public_capture.policy_root, policy_subject))
        scope = assurance_scope(public_capture.policy_root, payload=policy["profile"])
        declarations = [row for row in operation.get("runtime_qualifications", []) if scope in row["profiles"]]
        if (registry.raw["schema_version"] != "1.1" or len(declarations) != 1
                or declarations[0]["model"] != "python.cli-string-snapshot" or declarations[0]["version"] != "1.0"):
            raise CIGraphError("runtime context model policy is missing or unsupported")
        functions = _source_function_population(inventory)
        _validate_python_call_source_coverage(repo_root, inventory, functions, source_subject)
        function = _function_for_entrypoint(repo_root, operation["entrypoints"][0], functions, source_subject=source_subject)
        if function is None or function["symbol"].split("::")[-1] != "main":
            raise CIGraphError("runtime context caller is unsupported")
        caller = function["symbol"]
        caller_path = caller.split("::")[0]
        guard_path = str(Path(caller_path).parent / "nested_cli_runtime.py")
        callee = guard_path + "::cli_arguments"
        _, caller_raw = committed_regular_blob_capture(repo_root, path=caller_path, **source_subject)
        _, guard_raw = committed_regular_blob_capture(repo_root, path=guard_path, **source_subject)
        _, approved_guard = committed_regular_blob_capture(public_capture.policy_root, path=guard_path, **policy_subject)
        sites = cli_snapshot_model_sites(caller_raw, guard_raw, approved_guard,
            caller=caller, callee=callee, calls=function.get("calls", []))
        target = dict(source_subject=source_subject, operation=operation_id, entrypoint=operation["entrypoints"][0],
                      profile=scope, native_subject=dict(native_subject))
        statement = dict(schema_version="1.0", model="python.cli-string-snapshot", model_version="1.0", target=target,
            caller_sha256=hashlib.sha256(caller_raw).hexdigest(), guard_sha256=hashlib.sha256(guard_raw).hexdigest(),
            call_sites=[json.loads(identity) for identity, _ in sites])
        settings = policy["evidence_policy"].get("settings", {})
        receipts = load_receipts(public_capture.policy_root, evidence_root, policy_subject,
            policy_subject=policy_subject, require_negative_control=bool(settings.get("require_negative_control_for_required_gates", True)),
            tree_independent_allowlist=set(settings.get("tree_independent_allowlist", [])),
            expected_kinds=expected_evidence_kinds(public_capture.policy_root, source_subject=policy_subject),
            invocations=expected_invocations(public_capture.policy_root, source_subject=policy_subject), require_session=True,
            selected_profile=policy["profile"].get("profile", {}).get("selected", "standard"), contract_version="3.0")
        identities = set()
        for claim_id in declarations[0]["claims"]:
            applicable = []
            for row in eligible_claim_receipts(receipts, policy["model"], claim_id, set(), include_preflight=False):
                receipt = row.get("receipt", {})
                context = receipt.get("observations", {}).get("runtime_context")
                if (row.get("result") == "verified" and row.get("admission_policy") == policy["identity"]
                        and context == statement):
                    applicable.append(row)
            if not applicable:
                raise CIGraphError("runtime context lacks an exact approved model qualification")
            for row in applicable:
                identities.add((row["receipt_path"], row["artifact_sha256"], row["evidence_id"]))
        if _runtime_inventory_digest(inventory) != inventory_sha:
            raise CIGraphError("runtime context source inventory changed during capture")
    except (OSError, TypeError, ValueError, KeyError, ReceiptError) as exc:
        if isinstance(exc, CIGraphError):
            raise
        raise CIGraphError(f"runtime context qualification failed: {exc}") from exc
    return _OperationRuntimeContext(public_capture, operation_id, evidence_root.resolve(),
        tuple(native_subject[key] for key in keys), inventory_sha,
        json.dumps(statement, sort_keys=True, separators=(",", ":")), tuple(sorted(identities)), sites)


def runtime_context_call_summaries(operation, inventory, capture):
    """Reauthenticate the complete model capture; its class identity is not authority."""
    if type(capture) is not _OperationRuntimeContext or capture.operation_id != operation["id"]:
        raise CIGraphError("runtime context capture differs from the operation")
    parent = capture.public_capture
    fresh = capture_operation_runtime_context(parent.runtime_root, inventory, parent,
        operation_id=capture.operation_id, evidence_root=capture.evidence_root,
        native_subject=dict(zip(("implementation_sha256", "namespace_sha256"), capture.native_subject)))
    if fresh != capture:
        raise CIGraphError("runtime context capture changed before consumption")
    expected = next(row for row in parent.registry.operations if row["id"] == operation["id"])
    if operation != expected:
        raise CIGraphError("runtime context operation policy differs from protected source")
    return frozenset((json.loads(identity)["caller"], raw_call) for identity, raw_call in capture.sites)
