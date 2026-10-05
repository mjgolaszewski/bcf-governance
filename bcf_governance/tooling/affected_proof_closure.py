"""Exact changed-input to required-proof reachability.

This owner classifies assurance reachability only.  Receipt qualification and
reuse remain consumers of the resulting frontier.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable, Mapping

from .evidence_execution import EvidenceError
from .semantic_derivations import legacy_generated_projections
from .semantic_ownership_registry import load_registry


DEPENDENCY_CLASSES = (
    "subject",
    "detector",
    "test_population",
    "toolchain",
    "trust",
)
CLASSIFICATIONS = (
    "required",
    "demonstrably_unaffected",
    "ambiguous_requires_execution",
)


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def matches(path: str, pattern: str) -> bool:
    return pattern == "**" or fnmatch.fnmatchcase(path, pattern)


def patterns_for_claims(
    model: Mapping[str, Any], claim_ids: Iterable[str]
) -> dict[str, list[str]]:
    patterns: dict[str, set[str]] = {name: set() for name in DEPENDENCY_CLASSES}
    sets = model["dependency_sets"]
    for claim_id in claim_ids:
        claim = model["claims"].get(claim_id)
        if not isinstance(claim, dict):
            raise EvidenceError(f"unknown claim {claim_id}")
        for dependency_class in DEPENDENCY_CLASSES:
            for set_name in claim["dependencies"][dependency_class]:
                patterns[dependency_class].update(
                    str(value) for value in sets[set_name]
                )
    return {name: sorted(values) for name, values in patterns.items()}


def changed_paths(
    repo_root: Path, prior_commit: str | None, prior_tree: str | None = None,
) -> list[str] | None:
    """Return an exact tree diff, including transported-tree fallback."""

    if not prior_commit:
        return []
    if prior_tree is not None and re.fullmatch(r"[a-f0-9]{40,64}", prior_tree) is None:
        return None
    source = prior_commit
    commit_tree = subprocess.run(
        ["git", "rev-parse", f"{prior_commit}^{{tree}}"], cwd=repo_root,
        capture_output=True, text=True, check=False,
    )
    if commit_tree.returncode == 0:
        if prior_tree is not None and commit_tree.stdout.strip() != prior_tree:
            return None
    else:
        if prior_tree is None:
            return None
        tree_type = subprocess.run(
            ["git", "cat-file", "-t", prior_tree], cwd=repo_root,
            capture_output=True, text=True, check=False,
        )
        if tree_type.returncode or tree_type.stdout.strip() != "tree":
            return None
        source = prior_tree
    result = subprocess.run(
        ["git", "diff", "--name-only", source, "HEAD"], cwd=repo_root,
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        return None
    return sorted(line for line in result.stdout.splitlines() if line)


def _projection_rows(repo_root: Path) -> list[dict[str, str]]:
    registry = repo_root / "governance/canonical-representations.yml"
    schema = repo_root / "schemas/canonical-representations.schema.json"
    if not registry.is_file() or not schema.is_file():
        return []
    try:
        return legacy_generated_projections(repo_root, load_registry(repo_root))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"canonical generated-projection ownership is invalid: {exc}") from exc


def _expand_projection_paths(
    paths: Iterable[str], rows: Iterable[Mapping[str, str]]
) -> tuple[list[str], list[dict[str, str]]]:
    expanded = set(paths)
    edges: list[dict[str, str]] = []
    changed = True
    materialized = [dict(row) for row in rows]
    while changed:
        changed = False
        for row in materialized:
            source, output = row["canonical_source"], row["path"]
            if source in expanded or output in expanded:
                for value in (source, output):
                    if value not in expanded:
                        expanded.add(value)
                        changed = True
                edge = {"from": source, "to": output, "kind": "generated_projection"}
                if edge not in edges:
                    edges.append(edge)
    return sorted(expanded), sorted(edges, key=lambda row: (row["from"], row["to"]))


def _tracked_contract_digest(repo_root: Path, relative: str) -> str | None:
    path = repo_root / relative
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def derive_affected_proof_set(
    repo_root: Path,
    model: Mapping[str, Any],
    required_claim_ids: Iterable[str],
    *,
    current_subject: Mapping[str, str],
    prior_subjects: Iterable[tuple[str, str | None]],
) -> dict[str, Any]:
    """Classify every required proof exactly once from canonical dependencies."""

    required_claims = sorted(set(str(value) for value in required_claim_ids))
    subjects = sorted(set(prior_subjects), key=lambda value: (value[0], value[1] or ""))
    changes = [changed_paths(repo_root, commit, tree) for commit, tree in subjects]
    ambiguous_subject = (
        len({commit for commit, _ in subjects}) != len(subjects)
        or any(value is None for value in changes)
    )
    raw_changed = sorted({path for values in changes if values for path in values})
    projection_rows = _projection_rows(repo_root)
    expanded, projection_edges = _expand_projection_paths(raw_changed, projection_rows)
    referenced_sets = {
        str(set_name)
        for claim in model["claims"].values()
        for dependency_class in DEPENDENCY_CLASSES
        for set_name in claim["dependencies"][dependency_class]
    }
    non_proof_sets = {
        str(value) for value in model.get("non_proof_dependencies", [])
    }
    all_declared_patterns = sorted({
        str(pattern)
        for set_name in referenced_sets | non_proof_sets
        for pattern in model["dependency_sets"][set_name]
        if str(pattern) != "**"
    })
    unknown_paths = sorted(
        path for path in expanded
        if not any(matches(path, pattern) for pattern in all_declared_patterns)
    )
    global_ambiguity = ambiguous_subject or bool(unknown_paths)
    classifications: list[dict[str, Any]] = []
    for claim_id in required_claims:
        claim = model["claims"][claim_id]
        patterns_by_class = patterns_for_claims(model, [claim_id])
        matched = sorted({
            path for path in expanded
            if any(
                matches(path, pattern)
                for patterns in patterns_by_class.values()
                for pattern in patterns
            )
        })
        if not subjects:
            classification, reasons = "required", ["no_prior_subject"]
        elif global_ambiguity:
            classification, reasons = "ambiguous_requires_execution", [
                "subject_or_ownership_ambiguity"
            ]
        elif claim.get("whole_tree") is True and expanded:
            classification, reasons = "required", ["whole_tree_dependency_changed"]
        elif matched:
            classification, reasons = "required", ["reachable_dependency_changed"]
        else:
            classification, reasons = "demonstrably_unaffected", [
                "no_reachable_dependency_changed"
            ]
        classifications.append({
            "claim_id": claim_id,
            "execution_group": str(claim["execution_group"]),
            "classification": classification,
            "matched_paths": matched,
            "reasons": reasons,
        })
    groups = model["execution_groups"]
    by_claim = {row["claim_id"]: row for row in classifications}
    active_groups = {
        row["execution_group"] for row in classifications
        if row["classification"] != "demonstrably_unaffected"
    }
    pending = sorted(active_groups)
    while pending:
        group_id = pending.pop(0)
        for dependency in groups[group_id].get("depends_on", []):
            if dependency not in active_groups:
                active_groups.add(dependency)
                pending.append(dependency)
                pending.sort()
            for claim_id in groups[dependency]["claims"]:
                row = by_claim.get(str(claim_id))
                if row is not None and row["classification"] == "demonstrably_unaffected":
                    row["classification"] = "required"
                    row["reasons"] = ["current_run_dependency_required"]
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "current_subject": dict(current_subject),
        "prior_subjects": [
            {"commit_sha": commit, **({"tree_sha": tree} if tree else {})}
            for commit, tree in subjects
        ],
        "claim_model_sha256": canonical_sha256(model),
        "semantic_ownership_sha256": _tracked_contract_digest(
            repo_root, "governance/canonical-representations.yml"
        ),
        "lifecycle_sha256": canonical_sha256({
            path: _tracked_contract_digest(repo_root, path)
            for path in (
                "plans/phase-ledger.yml",
                "plans/phase-30-workitems.yml",
                "phases/phase-30-log.yml",
            )
        }),
        "raw_changed_paths": raw_changed,
        "expanded_changed_paths": expanded,
        "unknown_paths": unknown_paths,
        "projection_edges": projection_edges,
        "classifications": sorted(classifications, key=lambda row: row["claim_id"]),
    }
    payload["affected_proof_set_sha256"] = canonical_sha256(payload)
    return payload


def verify_affected_proof_set(
    expected: Mapping[str, Any], actual: Mapping[str, Any]
) -> None:
    """Reject any planner/truth reachability disagreement."""

    if dict(expected) != dict(actual):
        raise EvidenceError("affected proof set differs from canonical reachability")
    rows = actual.get("classifications")
    if not isinstance(rows, list) or any(
        not isinstance(row, dict) or row.get("classification") not in CLASSIFICATIONS
        for row in rows
    ):
        raise EvidenceError("affected proof classifications are incomplete")
    claim_ids = [str(row.get("claim_id", "")) for row in rows]
    if not all(claim_ids) or len(claim_ids) != len(set(claim_ids)):
        raise EvidenceError("affected proof claims are missing or duplicated")
    digest_payload = dict(actual)
    digest = digest_payload.pop("affected_proof_set_sha256", None)
    if digest != canonical_sha256(digest_payload):
        raise EvidenceError("affected proof set digest is invalid")


def verify_session_affected_proof_set(
    repo_root: Path,
    model: Mapping[str, Any],
    session: Mapping[str, Any],
    *,
    current_subject: Mapping[str, str],
    prior_receipts: Iterable[Mapping[str, Any]],
) -> None:
    """Recompute a v3 session frontier from authenticated source receipts."""

    actual = session.get("affected_proof_set")
    required = session.get("required_claims")
    if not isinstance(actual, dict) or not isinstance(required, list):
        raise EvidenceError("evidence session affected proof set is incomplete")
    subjects: set[tuple[str, str]] = set()
    for receipt in prior_receipts:
        subject = receipt.get("subject")
        commit = subject.get("commit_sha") if isinstance(subject, dict) else None
        tree = subject.get("tree_sha") if isinstance(subject, dict) else None
        if not isinstance(commit, str) or not isinstance(tree, str):
            raise EvidenceError("prior receipt subject is invalid for affected proof closure")
        subjects.add((commit, tree))
    expected = derive_affected_proof_set(
        repo_root,
        model,
        [str(value) for value in required],
        current_subject=current_subject,
        prior_subjects=subjects,
    )
    verify_affected_proof_set(expected, actual)
