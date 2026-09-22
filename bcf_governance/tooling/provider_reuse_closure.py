"""Recompute main-side claim closure from exact read-only provider Git objects."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable

import yaml  # type: ignore[import-untyped]

from .ci_github_identity import GitHubControllerError, MainIdentity
from .evidence_planning import build_dependency_manifest, parse_claim_model


CONTRACT_PATH = "governance/gate-contracts.yml"


def trusted_main_claim_context(
    api: Any, repository: str, main: MainIdentity, claim_ids: Iterable[str],
    *, repo_root: Path,
) -> tuple[dict[str, Any], tuple[tuple[str, str], ...], dict[str, Any]]:
    """Return canonical declarations and closure bound to the admitted main tree."""
    commit = api.commit(repository, main.checkout_sha)
    committed_tree = commit.get("tree") if isinstance(commit, dict) else None
    if not isinstance(committed_tree, dict) or committed_tree.get("sha") != main.tree_sha:
        raise GitHubControllerError("provider main commit tree differs from admitted subject")
    entries = api.complete_tree(repository, main.tree_sha)
    indexed = dict(entries)
    if len(indexed) != len(entries) or CONTRACT_PATH not in indexed:
        raise GitHubControllerError("provider main tree lacks an exact claim contract")
    content = api.content(repository, CONTRACT_PATH, ref=main.checkout_sha)
    raw = content.content
    if content.path != CONTRACT_PATH or not isinstance(raw, bytes):
        raise GitHubControllerError("provider claim contract content is not exact")
    algorithm = hashlib.sha1 if len(content.blob_oid) == 40 else hashlib.sha256
    blob = algorithm(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if content.blob_oid != indexed[CONTRACT_PATH] or content.blob_oid != blob:
        raise GitHubControllerError("provider claim contract bytes differ from main tree")
    try:
        payload = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GitHubControllerError("provider claim contract is not valid YAML") from exc
    model = parse_claim_model(payload)
    manifest = build_dependency_manifest(
        repo_root, claim_ids, model=model, tree_entries=entries,
    )
    return payload, entries, manifest
