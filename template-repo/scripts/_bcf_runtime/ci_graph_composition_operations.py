"""Bind protected public policy captures to existing lifecycle source roots.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .semantic_authority_contracts import (
    SemanticAuthorityError, load_committed_application_operations,
    _required_operation_population,
)


def capture_public_operation_bindings(
    repo_root: Path, *, policy_subject, required_relationships, relationship_roots,
):
    """Reject policy/crosswalk contradictions before expensive source discovery."""
    if not isinstance(policy_subject, Mapping) or set(policy_subject) != {"commit_sha", "tree_sha"}:
        raise CIGraphError("public operation binding requires exact consumer policy subject")
    if not isinstance(required_relationships, Mapping):
        raise CIGraphError("public operation binding requires independent relationships")
    bindings = dict(required_relationships)
    if any(not isinstance(key, str) or not key or not isinstance(pairs, frozenset) or not pairs
           or any(pair not in relationship_roots for pair in pairs)
           for key, pairs in bindings.items()):
        raise CIGraphError("public operation binding relationship population is empty or unknown")
    try:
        registry, identity = load_committed_application_operations(
            repo_root, policy_commit_sha=policy_subject["commit_sha"], policy_tree_sha=policy_subject["tree_sha"],
        )
    except (SemanticAuthorityError, OSError, ValueError) as exc:
        raise CIGraphError(f"public operation policy capture failed: {exc}") from exc
    if bindings.keys() != {operation["id"] for operation in registry.operations}:
        raise CIGraphError("public operation binding omits or invents required operations")
    for operation in registry.operations:
        if any(not set(operation["entrypoints"]) <= relationship_roots[pair]
               for pair in bindings[operation["id"]]):
            raise CIGraphError("public operation entrypoint is absent from its lifecycle relationship")
    metadata = dict(
        operations_checked=len(registry.operations), policy_subject=identity["subject"],
        policy_blob_oid=identity["blob_oid"], registry_sha256=identity["registry_sha256"],
        bindings=tuple(sorted((key, tuple(sorted(pairs))) for key, pairs in bindings.items())),
    )
    return registry, metadata


def validate_public_operation_capture(repo_root: Path, inventory: dict[str, Any], capture) -> dict[str, Any]:
    """Reuse one local factory capture; no caller-supplied capture ingress."""
    registry, metadata = capture
    try:
        population = _required_operation_population(repo_root, registry.raw, inventory, metadata["registry_sha256"])
    except SemanticAuthorityError as exc:
        raise CIGraphError(f"public operation source conformance failed: {exc}") from exc
    return dict(metadata, **population)
