"""Dependency-scoped claim applicability and minimum verification planning.

The authoritative declarations live in ``governance/gate-contracts.yml``.  This
module only evaluates those declarations; it is not a second claim registry.
"""

from __future__ import annotations

from datetime import UTC, datetime
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable, Mapping

import yaml  # type: ignore[import-untyped]

from .evidence_execution import EvidenceError
from .evidence_scheduling import assign_duration_aware_shards, duration_estimates


DEPENDENCY_CLASSES = (
    "subject",
    "detector",
    "test_population",
    "toolchain",
    "trust",
)

INVALIDATION_BY_CLASS = {
    "subject": ("subject_dependency_changed",),
    "detector": ("detector_dependency_changed",),
    "test_population": ("test_population_changed",),
    # Environment contracts are deliberately part of the toolchain closure:
    # an interpreter, lock, image, or setup-contract change is both facts.
    "toolchain": ("toolchain_changed", "environment_contract_changed"),
    # Artifact identity/custody inputs live inside the trust closure.
    "trust": ("trust_input_changed", "artifact_identity_changed"),
}


def _git(repo_root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True, check=False
    )
    if check and result.returncode:
        raise EvidenceError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_claim_model(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "governance/gate-contracts.yml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return parse_claim_model(payload)


def parse_claim_model(payload: object) -> dict[str, Any]:
    """Validate one canonical claim declaration, including provider-read bytes."""
    model = payload.get("claim_model") if isinstance(payload, dict) else None
    gates = payload.get("gates") if isinstance(payload, dict) else None
    if not isinstance(model, dict) or model.get("version") != "1.0":
        raise EvidenceError("gate contracts require claim_model version 1.0")
    sets = model.get("dependency_sets")
    groups = model.get("execution_groups")
    claims = model.get("claims")
    if not all(isinstance(value, dict) and value for value in (sets, groups, claims)):
        raise EvidenceError("claim model sets, groups, and claims must be nonempty")
    claim_ids = set(claims)
    legacy_owners: dict[str, str] = {}
    grouped: set[str] = set()
    membership: dict[str, int] = {claim_id: 0 for claim_id in claim_ids}
    for group_id, raw in groups.items():
        if not isinstance(raw, dict) or not isinstance(raw.get("producer"), str):
            raise EvidenceError(f"execution group {group_id} is invalid")
        members = raw.get("claims")
        if not isinstance(members, list) or not members:
            raise EvidenceError(f"execution group {group_id} has no claims")
        unknown = set(str(value) for value in members) - claim_ids
        if unknown:
            raise EvidenceError(
                f"execution group {group_id} names unknown claims: "
                + ", ".join(sorted(unknown))
            )
        grouped.update(str(value) for value in members)
        for claim_id in members:
            membership[str(claim_id)] += 1
        if raw.get("captured_by_preflight") is not True and (
            not isinstance(gates, dict) or raw["producer"] not in gates
        ):
            raise EvidenceError(
                f"execution group {group_id} producer is not an executable gate"
            )
    if grouped != claim_ids:
        raise EvidenceError("every claim must belong to exactly one execution group")
    if any(count != 1 for count in membership.values()):
        raise EvidenceError("every claim must belong to exactly one execution group")
    for claim_id, raw in claims.items():
        if not isinstance(raw, dict):
            raise EvidenceError(f"claim {claim_id} is invalid")
        group = raw.get("execution_group")
        if group not in groups or claim_id not in groups[group].get("claims", []):
            raise EvidenceError(f"claim {claim_id} execution group is inconsistent")
        legacy_gate = raw.get("legacy_gate")
        if not isinstance(legacy_gate, str) or not legacy_gate:
            raise EvidenceError(f"claim {claim_id} legacy gate is invalid")
        if (
            groups[group].get("captured_by_preflight") is not True
            and (not isinstance(gates, dict) or legacy_gate not in gates)
        ):
            raise EvidenceError(f"claim {claim_id} legacy gate is not executable")
        if legacy_gate in legacy_owners:
            raise EvidenceError(
                f"claims {legacy_owners[legacy_gate]} and {claim_id} duplicate legacy gate {legacy_gate}"
            )
        legacy_owners[legacy_gate] = str(claim_id)
        dependencies = raw.get("dependencies")
        if not isinstance(dependencies, dict) or set(dependencies) != set(DEPENDENCY_CLASSES):
            raise EvidenceError(f"claim {claim_id} dependency classes are incomplete")
        for dependency_class, names in dependencies.items():
            if not isinstance(names, list) or any(name not in sets for name in names):
                raise EvidenceError(
                    f"claim {claim_id} {dependency_class} dependencies are invalid"
                )
    return model


def assurance_scope(repo_root: Path) -> str:
    payload = yaml.safe_load(
        (repo_root / "governance-profile.yml").read_text(encoding="utf-8")
    )
    if not isinstance(payload, dict):
        raise EvidenceError("governance profile must be an object")
    declared = payload.get("assurance_scope")
    if declared in {"normal", "regulated", "self"}:
        return str(declared)
    profile = payload.get("profile")
    selected = profile.get("selected") if isinstance(profile, dict) else None
    return "regulated" if selected == "regulated" else "normal"


def required_claims(repo_root: Path) -> list[str]:
    model = load_claim_model(repo_root)
    scope = assurance_scope(repo_root)
    return sorted(
        claim_id
        for claim_id, raw in model["claims"].items()
        if isinstance(raw, dict) and scope in raw.get("profiles", [])
    )


def receipt_producing_legacy_gates(model: Mapping[str, Any]) -> set[str]:
    """Return legacy gates whose canonical execution groups emit receipts."""
    groups = model.get("execution_groups", {})
    return {
        str(claim["legacy_gate"])
        for claim in model.get("claims", {}).values()
        if isinstance(claim, dict)
        and isinstance(claim.get("legacy_gate"), str)
        and isinstance(groups.get(claim.get("execution_group")), dict)
        and groups[claim["execution_group"]].get("captured_by_preflight") is not True
    }


def claims_for_legacy_gate(repo_root: Path, gate_id: str) -> list[str]:
    model = load_claim_model(repo_root)
    direct = [
        claim_id
        for claim_id, raw in model["claims"].items()
        if isinstance(raw, dict) and raw.get("legacy_gate") == gate_id
    ]
    groups = {
        str(model["claims"][claim_id]["execution_group"]) for claim_id in direct
    }
    if not groups:
        return []
    # A producer can satisfy every claim in its group only after each claim's
    # exact observation is present.  Receipt validation enforces that detail.
    if len(groups) == 1:
        group = model["execution_groups"][next(iter(groups))]
        if group.get("producer") == gate_id:
            return sorted(str(value) for value in group["claims"])
    return sorted(direct)


def _patterns_for_claims(
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
                patterns[dependency_class].update(str(value) for value in sets[set_name])
    return {name: sorted(values) for name, values in patterns.items()}


def _tree_entries(repo_root: Path, ref: str = "HEAD") -> list[tuple[str, str]]:
    output = _git(repo_root, "ls-tree", "-r", "--full-tree", ref)
    entries: list[tuple[str, str]] = []
    for line in output.splitlines():
        metadata, separator, path = line.partition("\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise EvidenceError("git tree inventory is malformed")
        entries.append((path, fields[2]))
    return entries


def _matches(path: str, pattern: str) -> bool:
    return pattern == "**" or fnmatch.fnmatchcase(path, pattern)


def dependency_fingerprint(
    repo_root: Path, patterns: Iterable[str], *, ref: str = "HEAD",
    tree_entries: Iterable[tuple[str, str]] | None = None,
) -> tuple[str, list[str]]:
    selected = sorted(
        (path, object_id)
        for path, object_id in (
            _tree_entries(repo_root, ref) if tree_entries is None else tree_entries
        )
        if any(_matches(path, pattern) for pattern in patterns)
    )
    return _canonical_sha256(selected), [path for path, _ in selected]


def build_dependency_manifest(
    repo_root: Path, claim_ids: Iterable[str], *,
    model: Mapping[str, Any] | None = None,
    tree_entries: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    selected_claims = sorted(set(str(value) for value in claim_ids))
    if not selected_claims:
        raise EvidenceError("dependency manifest requires at least one claim")
    model = load_claim_model(repo_root) if model is None else model
    patterns = _patterns_for_claims(model, selected_claims)
    claim_dependencies: dict[str, list[dict[str, Any]]] = {}
    for claim_id in selected_claims:
        claim_patterns = _patterns_for_claims(model, [claim_id])
        claim_dependencies[claim_id] = []
        for dependency_class in DEPENDENCY_CLASSES:
            digest, paths = dependency_fingerprint(
                repo_root, claim_patterns[dependency_class], tree_entries=tree_entries
            )
            claim_dependencies[claim_id].append(
                {
                    "class": dependency_class,
                    "patterns": claim_patterns[dependency_class],
                    "paths": paths,
                    "fingerprint": digest,
                }
            )
    classes: list[dict[str, Any]] = []
    for dependency_class in DEPENDENCY_CLASSES:
        digest, paths = dependency_fingerprint(
            repo_root, patterns[dependency_class], tree_entries=tree_entries
        )
        classes.append(
            {
                "class": dependency_class,
                "patterns": patterns[dependency_class],
                "paths": paths,
                "fingerprint": digest,
            }
        )
    return {
        "contract_version": "3.0",
        "claim_model_version": str(model["version"]),
        "claim_model_sha256": _canonical_sha256(model),
        "complete": True,
        "claims": selected_claims,
        "classes": classes,
        "claim_dependencies": claim_dependencies,
    }


def receipt_applicability(
    repo_root: Path, receipt: Mapping[str, Any], claim_id: str, *,
    current_subject: Mapping[str, str] | None = None,
    model: Mapping[str, Any] | None = None,
    tree_entries: Iterable[tuple[str, str]] | None = None,
) -> tuple[bool, list[str]]:
    provider_context = any(value is not None for value in (current_subject, model, tree_entries))
    if provider_context and any(value is None for value in (current_subject, model, tree_entries)):
        raise EvidenceError("provider claim applicability context must be complete")
    current_commit = (
        str(current_subject["commit_sha"]) if current_subject is not None
        else _git(repo_root, "rev-parse", "HEAD")
    )
    current_tree = (
        str(current_subject["tree_sha"]) if current_subject is not None
        else _git(repo_root, "rev-parse", "HEAD^{tree}")
    )
    subject = receipt.get("subject")
    if not isinstance(subject, dict):
        return False, ["dependency_closure_ambiguous"]
    if receipt.get("schema_version") == "2.0":
        if provider_context:
            return False, ["legacy_evidence_exact_subject_only"]
        mapped_claims = claims_for_legacy_gate(repo_root, str(receipt.get("gate_id", "")))
        if (
            receipt.get("result") == "passed"
            and claim_id in mapped_claims
            and subject.get("commit_sha") == current_commit
            and subject.get("tree_sha") == current_tree
        ):
            return True, []
        return False, ["legacy_evidence_exact_subject_only"]
    if receipt.get("schema_version") != "3.0" or receipt.get("result") != "passed":
        return False, ["dependency_closure_ambiguous"]
    claims = receipt.get("claims")
    manifest = receipt.get("dependency_manifest")
    if (
        not isinstance(claims, list)
        or claim_id not in claims
        or not isinstance(manifest, dict)
        or manifest.get("complete") is not True
        or manifest.get("contract_version") != "3.0"
        or sorted(manifest.get("claims", [])) != sorted(claims)
    ):
        return False, ["dependency_closure_ambiguous"]
    model = load_claim_model(repo_root) if model is None else model
    claim = model["claims"].get(claim_id)
    group = (
        model["execution_groups"].get(claim.get("execution_group"))
        if isinstance(claim, dict)
        else None
    )
    if not isinstance(group, dict) or group.get("producer") != receipt.get("gate_id"):
        return False, ["claim_producer_mismatch"]
    if manifest.get("claim_model_sha256") != _canonical_sha256(model):
        return False, ["detector_dependency_changed"]
    claim_dependencies = manifest.get("claim_dependencies")
    classes = (
        claim_dependencies.get(claim_id)
        if isinstance(claim_dependencies, dict)
        else None
    )
    if not isinstance(classes, list):
        return False, ["dependency_closure_ambiguous"]
    indexed = {raw.get("class"): raw for raw in classes if isinstance(raw, dict)}
    if len(classes) != len(DEPENDENCY_CLASSES) or set(indexed) != set(DEPENDENCY_CLASSES):
        return False, ["dependency_closure_ambiguous"]
    declared_patterns = _patterns_for_claims(model, [claim_id])
    reasons: list[str] = []
    for dependency_class in DEPENDENCY_CLASSES:
        raw = indexed.get(dependency_class)
        if not isinstance(raw, dict) or not isinstance(raw.get("patterns"), list):
            reasons.append("dependency_closure_ambiguous")
            continue
        if raw["patterns"] != declared_patterns[dependency_class]:
            reasons.append("dependency_closure_ambiguous")
            continue
        expected, paths = dependency_fingerprint(
            repo_root, raw["patterns"], tree_entries=tree_entries,
        )
        if raw.get("paths") != paths:
            reasons.extend(INVALIDATION_BY_CLASS[dependency_class])
        elif raw.get("fingerprint") != expected:
            reasons.extend(INVALIDATION_BY_CLASS[dependency_class])
    claim = model["claims"].get(claim_id, {})
    if claim.get("whole_tree") is True and subject.get("tree_sha") != current_tree:
        reasons.append("subject_dependency_changed")
    claim_limit = claim.get("freshness_limit_seconds")
    receipt_limit = receipt.get("freshness_limit_seconds")
    limit = claim_limit
    if receipt_limit is not None:
        try:
            limit = min(int(receipt_limit), int(claim_limit)) if claim_limit is not None else int(receipt_limit)
        except (TypeError, ValueError):
            reasons.append("freshness_expired")
            limit = None
    if limit is not None:
        try:
            captured = datetime.fromisoformat(
                str(receipt.get("timestamp", "")).replace("Z", "+00:00")
            )
            age = None if captured.tzinfo is None else (datetime.now(UTC) - captured).total_seconds()
            if age is None or age < 0 or age > int(limit):
                reasons.append("freshness_expired")
        except (TypeError, ValueError):
            reasons.append("freshness_expired")
    qualification_scope = claim.get("qualification_scope")
    if qualification_scope != "none":
        qualifications = receipt.get("qualifications")
        qualification = (
            qualifications.get(claim_id)
            if isinstance(qualifications, dict)
            else receipt.get("qualification")
        )
        qualified = (
            isinstance(qualification, dict)
            and qualification.get("scope") == qualification_scope
            and qualification.get("satisfied") is True
        )
        if not qualified:
            reasons.append("qualification_missing")
    return not reasons, sorted(set(reasons))


def qualification_applicability(
    repo_root: Path, receipt: Mapping[str, Any], claim_id: str
) -> bool:
    """Return whether one detector-scoped qualification remains applicable."""

    if receipt.get("schema_version") != "3.0":
        return False
    model = load_claim_model(repo_root)
    claim = model["claims"].get(claim_id)
    qualifications = receipt.get("qualifications")
    qualification = (
        qualifications.get(claim_id)
        if isinstance(qualifications, dict)
        else receipt.get("qualification")
    )
    manifest = receipt.get("dependency_manifest")
    if (
        receipt.get("result") != "passed"
        or not isinstance(claim, dict)
        or claim.get("qualification_scope") != "detector"
        or not isinstance(receipt.get("claims"), list)
        or claim_id not in receipt["claims"]
        or not isinstance(qualification, dict)
        or qualification.get("scope") != "detector"
        or qualification.get("satisfied") is not True
        or not isinstance(manifest, dict)
        or manifest.get("complete") is not True
        or manifest.get("claim_model_sha256") != _canonical_sha256(model)
    ):
        return False
    claim_dependencies = manifest.get("claim_dependencies")
    classes = (
        claim_dependencies.get(claim_id)
        if isinstance(claim_dependencies, dict)
        else None
    )
    if not isinstance(classes, list):
        return False
    indexed = {raw.get("class"): raw for raw in classes if isinstance(raw, dict)}
    if len(classes) != len(DEPENDENCY_CLASSES) or set(indexed) != set(DEPENDENCY_CLASSES):
        return False
    declared_patterns = _patterns_for_claims(model, [claim_id])
    for dependency_class in ("detector", "test_population", "toolchain", "trust"):
        raw = indexed.get(dependency_class)
        if not isinstance(raw, dict) or not isinstance(raw.get("patterns"), list):
            return False
        if raw["patterns"] != declared_patterns[dependency_class]:
            return False
        fingerprint, paths = dependency_fingerprint(repo_root, raw["patterns"])
        if raw.get("fingerprint") != fingerprint or raw.get("paths") != paths:
            return False
    limit = claim.get("freshness_limit_seconds")
    if limit is not None:
        try:
            captured = datetime.fromisoformat(
                str(receipt.get("timestamp", "")).replace("Z", "+00:00")
            )
            age = None if captured.tzinfo is None else (datetime.now(UTC) - captured).total_seconds()
            if age is None or age < 0 or age > int(limit):
                return False
        except (TypeError, ValueError):
            return False
    return True


def _changed_paths(
    repo_root: Path, prior_commit: str | None, prior_tree: str | None = None,
) -> list[str] | None:
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
        # A transported receipt can name an execution commit absent from this
        # clone.  Git tree identity still permits an exact path diff; this
        # planning fact alone never certifies reuse or provider custody.
        source = prior_tree
    result = subprocess.run(
        ["git", "diff", "--name-only", source, "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return None
    return sorted(line for line in result.stdout.splitlines() if line)


def plan_verification(
    repo_root: Path,
    prior_receipts: Iterable[Mapping[str, Any]] = (),
    *,
    preflight_claims: Iterable[str] = (),
) -> dict[str, Any]:
    model = load_claim_model(repo_root)
    required = required_claims(repo_root)
    current = {
        "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
        "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
    }
    receipts = [dict(value) for value in prior_receipts]
    prior_subjects = {
        (str(subject["commit_sha"]), subject.get("tree_sha") if isinstance(subject.get("tree_sha"), str) else None)
        for receipt in receipts
        if isinstance((subject := receipt.get("subject")), dict)
        and isinstance(subject.get("commit_sha"), str)
    }
    prior_commits = sorted({commit for commit, _ in prior_subjects})
    prior_subject = {"commit_sha": prior_commits[0]} if len(prior_commits) == 1 else None
    change_sets = [
        _changed_paths(repo_root, commit, tree)
        for commit, tree in sorted(prior_subjects, key=lambda value: (value[0], value[1] or ""))
    ]
    changed = sorted({path for values in change_sets if values for path in values})
    change_ambiguity = (
        len(prior_subjects) != len(prior_commits)
        or any(values is None for values in change_sets)
    )
    routable_claims = [
        claim_id for claim_id in required
        if model["execution_groups"][model["claims"][claim_id]["execution_group"]].get(
            "captured_by_preflight"
        ) is not True
    ]
    declared_patterns = _patterns_for_claims(model, routable_claims)
    all_patterns = [pattern for values in declared_patterns.values() for pattern in values]
    known_nonbehavior = lambda path: path.startswith(("docs/", "plans/", "phases/", "audits/")) or path in {
        "README.md", "CHANGELOG.md", "MEMORY.yml"
    }
    unknown_paths = [
        path for path in changed
        if not any(_matches(path, pattern) for pattern in all_patterns)
        and not known_nonbehavior(path)
    ]
    conservative_fallback = change_ambiguity or bool(unknown_paths)
    identity_counts: dict[str, int] = {}
    for receipt in receipts:
        evidence_id = receipt.get("evidence_id")
        if isinstance(evidence_id, str):
            identity_counts[evidence_id] = identity_counts.get(evidence_id, 0) + 1
    colliding_ids = {key for key, count in identity_counts.items() if count > 1}
    preflight = set(preflight_claims)
    reused: list[dict[str, Any]] = []
    invalidated: list[dict[str, Any]] = []
    satisfied = sorted(set(required).intersection(preflight))
    unresolved: list[str] = []
    for claim_id in required:
        if claim_id in preflight:
            continue
        candidates: list[tuple[Mapping[str, Any], list[str]]] = []
        for receipt in receipts:
            legacy_claim = receipt.get("gate_id")
            claims = (
                claims_for_legacy_gate(repo_root, str(legacy_claim))
                if receipt.get("schema_version") == "2.0"
                else receipt.get("claims", [legacy_claim])
            )
            if not isinstance(claims, list) or claim_id not in claims:
                continue
            if receipt.get("evidence_id") in colliding_ids:
                candidates.append((receipt, ["dependency_closure_ambiguous"]))
                continue
            if conservative_fallback:
                candidates.append((receipt, ["dependency_closure_ambiguous"]))
                continue
            applicable, reasons = receipt_applicability(repo_root, receipt, claim_id)
            if applicable:
                reused.append(
                    {
                        "claim_id": claim_id,
                        "evidence_id": receipt.get("evidence_id"),
                        "artifact_sha256": receipt.get("artifact_sha256"),
                        "reason": "dependency fingerprints remain applicable",
                    }
                )
                break
            candidates.append((receipt, reasons))
        else:
            unresolved.append(claim_id)
            reasons = sorted({reason for _, values in candidates for reason in values})
            invalidated.append(
                {
                    "claim_id": claim_id,
                    "evidence_ids": sorted(
                        str(value.get("evidence_id")) for value, _ in candidates
                    ),
                    "reasons": reasons or ["dependency_closure_ambiguous"],
                }
            )
    grouped: dict[str, list[str]] = {}
    for claim_id in unresolved:
        group = str(model["claims"][claim_id]["execution_group"])
        if model["execution_groups"][group].get("captured_by_preflight") is True:
            # A missing current preflight observation is not safely routable.
            invalidated.append(
                {
                    "claim_id": claim_id,
                    "evidence_ids": [],
                    "reasons": ["dependency_closure_ambiguous"],
                }
            )
            continue
        grouped.setdefault(group, []).append(claim_id)
    nodes = []
    for group_id, claim_ids in sorted(grouped.items()):
        qualification_refs: list[dict[str, str]] = []
        for claim_id in claim_ids:
            for receipt in receipts:
                if qualification_applicability(repo_root, receipt, claim_id):
                    digest = receipt.get("artifact_sha256")
                    evidence_id = receipt.get("evidence_id")
                    if isinstance(digest, str) and isinstance(evidence_id, str):
                        qualification_refs.append(
                            {
                                "claim_id": claim_id,
                                "evidence_id": evidence_id,
                                "artifact_sha256": digest,
                            }
                        )
                        break
        nodes.append({
            "id": group_id,
            "producer": model["execution_groups"][group_id]["producer"],
            "claims": sorted(claim_ids),
            "depends_on": [],
            "reason": "required claims lack applicable authenticated evidence",
            "qualification_refs": qualification_refs,
        })
    nodes = assign_duration_aware_shards(
        nodes, duration_estimates(receipts, model)
    )
    return {
        "current_subject": current,
        "prior_subject": prior_subject,
        "changed_paths": changed,
        "changed_domains": sorted(
            {
                "documentation" if path.startswith(("docs/", "README")) else
                "test" if path.startswith("tests/") else
                "governance" if path.startswith(("governance/", "plans/", "phases/")) else
                "workflow" if path.startswith(".github/workflows/") else
                "implementation"
                for path in changed
            }
        ),
        "required_claims": required,
        "preflight_satisfied_claims": satisfied,
        "reused_evidence": sorted(reused, key=lambda value: value["claim_id"]),
        "invalidated_evidence": sorted(
            invalidated, key=lambda value: (value["claim_id"], value["reasons"])
        ),
        "execution_dag": {"nodes": nodes, "edges": []},
        "decision_explanations": [
            *[
                f"reused because {item['claim_id']} dependency fingerprints remain applicable"
                for item in reused
            ],
            *[
                f"executed because {node['id']} has unresolved claims: "
                + ", ".join(node["claims"])
                for node in nodes
            ],
            *(
                ["expanded because dependency closure was ambiguous for: " + ", ".join(unknown_paths)]
                if unknown_paths else []
            ),
            *(
                ["expanded because a prior subject was unavailable from repository history"]
                if change_ambiguity else []
            ),
        ],
    }


def load_prior_receipts(
    repo_root: Path, evidence_dir: Path | None, expected_digest: str | None
) -> list[Mapping[str, Any]]:
    """Decode caller-authenticated prior evidence without owning its format."""
    from .prior_evidence_receipts import load_prior_receipts as decode

    return decode(
        repo_root, evidence_dir, expected_digest,
        current_subject={
            "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
            "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
            "tracked_clean": True,
            "untracked_clean": True,
        } if evidence_dir is not None else None,
    )


def verification_plan(
    repo_root: Path,
    subject: Mapping[str, Any],
    prior_receipts: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Select dependency planning for v3 and strict exact-subject planning otherwise."""
    profile = yaml.safe_load(
        (repo_root / "governance-profile.yml").read_text(encoding="utf-8")
    )
    if isinstance(profile, dict) and profile.get("profile_contract_version") == "3.0":
        return plan_verification(
            repo_root,
            prior_receipts,
            preflight_claims=(
                "governance-contracts-valid",
                "governance-exposure-clean",
                "source-syntax-format",
                "semantic-ownership-valid",
            ),
        )
    release = profile.get("release_gate_profile") if isinstance(profile, dict) else None
    raw_gates = release.get("gates") if isinstance(release, dict) else None
    gate_values = raw_gates.values() if isinstance(raw_gates, dict) else ()
    gates = sorted(
        str(value["target"])
        for value in gate_values
        if isinstance(value, dict)
        and value.get("status") == "required"
        and isinstance(value.get("target"), str)
    )
    nodes = [
        {"id": gate, "producer": gate, "claims": [gate], "depends_on": [],
         "reason": "legacy profile requires exact-subject execution"}
        for gate in gates
    ]
    return {
        "current_subject": {"commit_sha": subject.get("commit_sha"), "tree_sha": subject.get("tree_sha")},
        "prior_subject": None, "changed_paths": [], "changed_domains": [],
        "required_claims": gates, "preflight_satisfied_claims": [], "reused_evidence": [],
        "invalidated_evidence": [
            {"claim_id": gate, "evidence_ids": [], "reasons": ["legacy_evidence_exact_subject_only"]}
            for gate in gates
        ],
        "execution_dag": {"nodes": nodes, "edges": []},
        "decision_explanations": [f"executed because legacy claim {gate} is exact-subject only" for gate in gates],
    }
