"""Evidence-derived lifecycle state for ordinary phase workitems."""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from .ci_graph_yaml import GraphYAMLError, load_yaml_path

from .truth_reporting import eligible_receipts

if TYPE_CHECKING:
    from .ci_github_api import GitHubAPI
    from .ci_github_identity import MainIdentity


DEPENDENCY_PREFIX = "requires-workitem-closure:"
PHASE_DEPENDENCY_PREFIX = "requires-phase-closure:"


class WorkitemContractError(ValueError):
    """Raised when ordinary workitem dependency declarations are ambiguous."""


def _authored_yaml(path: Path) -> dict[str, Any]:
    """Load authored lifecycle YAML through one typed fail-closed boundary."""

    try:
        return load_yaml_path(path)
    except (OSError, UnicodeError, GraphYAMLError) as exc:
        raise WorkitemContractError(
            f"authored lifecycle contract is unreadable: {path.as_posix()}: {exc}"
        ) from exc


def _closure_predecessors(entry: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Decode both closed mandatory namespaces without treating either as prose."""
    values = entry.get("acceptance", [])
    if not isinstance(values, list):
        raise WorkitemContractError("workitem acceptance must be a list")
    predecessors: list[str] = []
    phases: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise WorkitemContractError("workitem acceptance predicates must be strings")
        if value.strip().casefold().startswith("requires-") and (
            value != value.strip() or not value.startswith((DEPENDENCY_PREFIX, PHASE_DEPENDENCY_PREFIX))
        ):
            raise WorkitemContractError(
                f"unsupported or malformed mandatory workitem predicate {value!r}"
            )
        if value.startswith(DEPENDENCY_PREFIX):
            predecessor = value.removeprefix(DEPENDENCY_PREFIX)
            if not predecessor or ":" in predecessor:
                raise WorkitemContractError(
                    f"malformed workitem closure predicate {value!r}"
                )
            predecessors.append(predecessor)
        elif value.startswith(PHASE_DEPENDENCY_PREFIX):
            phase = value.removeprefix(PHASE_DEPENDENCY_PREFIX)
            if re.fullmatch(r"P[0-9]+", phase) is None:
                raise WorkitemContractError(f"malformed phase closure predicate {value!r}")
            phases.append(phase)
    if len(predecessors) != len(set(predecessors)):
        raise WorkitemContractError("duplicate workitem predecessor declaration")
    if len(phases) != len(set(phases)):
        raise WorkitemContractError("duplicate phase predecessor declaration")
    return predecessors, phases


def workitem_predecessors(entry: dict[str, Any]) -> list[str]:
    """Return workitem predecessors while validating all mandatory predicates."""
    return _closure_predecessors(entry)[0]


def workitem_phase_predecessors(entry: dict[str, Any]) -> list[str]:
    """Return phase prerequisites separately from the existing workitem graph."""
    return _closure_predecessors(entry)[1]


def phase_prerequisite_observation(
    repo_root: Path, entries: Iterable[dict[str, Any]], *,
    provider_api: GitHubAPI | None = None, repository: str | None = None,
    policy_subject: MainIdentity | None = None,
) -> dict[str, Any]:
    """Consume provider-authenticated phase facts, with no proof-dictionary ingress."""

    required = sorted({phase for entry in entries for phase in workitem_phase_predecessors(entry)})
    report: dict[str, Any] = {
        "required_phases": required, "protected_required_phases": [],
        "verified_phases": [], "missing_phases": required,
        "evidence_refs": [], "issues": [], "satisfied": not required,
    }
    if provider_api is None and repository is None and policy_subject is None and not required:
        return report
    if (provider_api is None or not isinstance(repository, str) or not repository
            or not callable(getattr(provider_api, "repository", None))):
        report.update(satisfied=False, issues=["phase_closure_authority_missing_or_invalid"])
        return report
    ledger = _authored_yaml(repo_root / "plans/phase-ledger.yml")
    active = ledger.get("active_phase")
    phase_id = active.get("id") if isinstance(active, dict) else None
    if not isinstance(phase_id, str):
        report.update(satisfied=False, issues=["phase_closure_target_missing"])
        return report
    # Import provider owners only at actual consumption, keeping parsing pure.
    from .ci_github_api import GitHubAPIError
    from .trusted_inputs import verify_required_phase_closure_inputs
    try:
        protected, inputs = verify_required_phase_closure_inputs(
            provider_api, repository=repository, phase_id=None if policy_subject is not None else phase_id,
            policy_subject=policy_subject,
        )
    except (ValueError, OSError, GitHubAPIError) as exc:
        report.update(satisfied=False, issues=[f"phase_closure_not_verified:{exc}"])
        return report
    protected_required = sorted(inputs)
    report.update(
        required_phases=sorted(set(required) | set(protected_required)),
        protected_required_phases=protected_required,
        verified_phases=protected_required,
        missing_phases=sorted(set(required) - set(protected_required)),
        policy_subject={
            "repository": repository, "repository_id": protected.repository_id,
            "commit_sha": protected.checkout_sha, "tree_sha": protected.tree_sha,
        },
        evidence_refs=[{
            "phase_id": phase, "artifact": artifact.as_dict(),
            "certification_sha256": verification.certification_sha256,
            "session_manifest_sha256": verification.session_manifest_sha256,
            "proposition": verification.certified_proposition,
        } for phase, (artifact, verification, _raw) in inputs.items()],
    )
    report["satisfied"] = not report["missing_phases"]
    return report


def validate_workitem_dependencies(entries: Iterable[dict[str, Any]]) -> list[str]:
    """Require unique workitems and backward-only, unambiguous dependencies."""
    values = list(entries)
    ids = [str(entry.get("id", "")) for entry in values]
    if any(not item_id for item_id in ids):
        raise WorkitemContractError("workitem id is missing")
    duplicates = sorted({item_id for item_id in ids if ids.count(item_id) > 1})
    if duplicates:
        raise WorkitemContractError(
            "duplicate workitem ids make dependencies ambiguous: " + ", ".join(duplicates)
        )
    positions = {item_id: index for index, item_id in enumerate(ids)}
    statuses = {item_id: values[index].get("status") for index, item_id in enumerate(ids)}
    for index, entry in enumerate(values):
        item_id = ids[index]
        for predecessor in workitem_predecessors(entry):
            if predecessor not in positions:
                raise WorkitemContractError(
                    f"workitem {item_id} has unknown predecessor {predecessor}"
                )
            if positions[predecessor] >= index:
                raise WorkitemContractError(
                    f"workitem {item_id} predecessor {predecessor} is forward or cyclic"
                )
            if entry.get("status") == "DONE" and statuses[predecessor] != "DONE":
                raise WorkitemContractError(
                    f"workitem {item_id} is authored DONE before predecessor {predecessor}"
                )
    return ids


def active_workitem_entries(repo_root: Path) -> tuple[str, list[dict[str, Any]]]:
    """Load the one active workitem ledger through the canonical lifecycle owner."""

    ledger = _authored_yaml(repo_root / "plans/phase-ledger.yml")
    active = ledger.get("active_phase") if isinstance(ledger, dict) else None
    workitems_path = active.get("workitems") if isinstance(active, dict) else None
    if not isinstance(workitems_path, str):
        raise WorkitemContractError("active workitem ledger is missing")
    payload = _authored_yaml(repo_root / workitems_path)
    entries = payload.get("workitems") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise WorkitemContractError("active workitem entries are invalid")
    validate_workitem_dependencies(entries)
    return workitems_path, entries


def validate_bounded_target_successor(
    repo_root: Path, target_id: str
) -> None:
    """Reject a bounded target that would strand later authored workitems."""

    _, entries = active_workitem_entries(repo_root)
    ids = [str(item["id"]) for item in entries]
    if target_id not in ids:
        raise WorkitemContractError(f"bounded workitem target {target_id} is unknown")
    unfinished = [
        str(item["id"])
        for item in entries
        if item.get("id") != target_id and item.get("status") != "DONE"
    ]
    successors = [
        str(item["id"])
        for item in entries
        if target_id in workitem_predecessors(item)
    ]
    if len(successors) > 1:
        raise WorkitemContractError(
            f"bounded workitem target {target_id} has ambiguous successors"
        )
    if unfinished and not successors:
        raise WorkitemContractError(
            f"bounded workitem target {target_id} would strand unfinished workitems"
        )


def bounded_target_acceptance_evidence(repo_root: Path, target_id: str) -> list[str]:
    """Return exact gates for a target and its declared predecessor closure."""

    _, entries = active_workitem_entries(repo_root)
    by_id = {str(item["id"]): item for item in entries}
    target = by_id.get(target_id)
    if target is None:
        raise WorkitemContractError(f"bounded workitem target {target_id} is unknown")
    required: set[str] = set()
    pending = [target_id]
    visited: set[str] = set()
    while pending:
        item_id = pending.pop(0)
        if item_id in visited:
            continue
        visited.add(item_id)
        entry = by_id[item_id]
        raw = entry.get("acceptance_evidence")
        if (
            not isinstance(raw, list)
            or not raw
            or any(not isinstance(value, str) or not value for value in raw)
            or len(raw) != len(set(raw))
        ):
            raise WorkitemContractError(
                f"bounded workitem target {item_id} acceptance evidence is invalid"
            )
        required.update(raw)
        pending.extend(workitem_predecessors(entry))
    return sorted(required)


def validate_bounded_target_authored_ready(
    repo_root: Path, target_id: str, *,
    provider_api: GitHubAPI | None = None, repository: str | None = None,
    policy_subject: MainIdentity | None = None,
) -> None:
    """Reject a prospectively impossible bounded target before evidence allocation."""

    _, entries = active_workitem_entries(repo_root)
    target = next((item for item in entries if item.get("id") == target_id), None)
    if target is None:
        raise WorkitemContractError(f"bounded workitem target {target_id} is unknown")
    if target.get("status") != "DONE":
        raise WorkitemContractError(
            f"bounded workitem target {target_id} is not authored DONE"
        )
    by_id = {str(entry["id"]): entry for entry in entries}
    pending = [target_id]
    closure: dict[str, dict[str, Any]] = {}
    while pending:
        item_id = pending.pop()
        if item_id not in closure:
            closure[item_id] = by_id[item_id]
            pending.extend(workitem_predecessors(by_id[item_id]))
    prerequisites = phase_prerequisite_observation(
        repo_root, closure.values(), provider_api=provider_api, repository=repository, policy_subject=policy_subject,
    )
    if not prerequisites["satisfied"]:
        raise WorkitemContractError(
            f"bounded workitem target {target_id} phase closure prerequisites are unverified: "
            + ", ".join(prerequisites["issues"] + prerequisites["missing_phases"])
        )


def validate_phase_closure_authored_ready(
    repo_root: Path, *, provider_api: GitHubAPI | None = None,
    repository: str | None = None,
    policy_subject: MainIdentity | None = None,
) -> None:
    """Reject structurally impossible phase closure before evidence allocation."""

    ledger = _authored_yaml(repo_root / "plans/phase-ledger.yml")
    active = ledger.get("active_phase") if isinstance(ledger, dict) else None
    phase_id = active.get("id") if isinstance(active, dict) else None
    log_path = active.get("log") if isinstance(active, dict) else None
    if not isinstance(phase_id, str) or not isinstance(log_path, str):
        raise WorkitemContractError("active phase closure identity is missing")
    phase = _authored_yaml(repo_root / log_path)
    document = phase.get("document") if isinstance(phase, dict) else None
    if not isinstance(document, dict) or document.get("status") != "completed":
        raise WorkitemContractError(
            f"phase closure target {phase_id} is not authored completed"
        )
    for path in sorted((repo_root / "phases").glob("phase-[0-9]*-hotfix*.yml")):
        payload = _authored_yaml(path)
        hotfix = payload.get("hotfix") if isinstance(payload, dict) else None
        if not isinstance(hotfix, dict) or hotfix.get("related_phase_id") != phase_id:
            continue
        hotfix_document = payload.get("document")
        hotfix_id = str(hotfix.get("id", path.stem))
        if (
            not isinstance(hotfix_document, dict)
            or hotfix_document.get("status") != "completed"
        ):
            raise WorkitemContractError(
                f"phase closure hotfix {hotfix_id} is not authored completed"
            )
    _, entries = active_workitem_entries(repo_root)
    unfinished = sorted(str(entry["id"]) for entry in entries if entry.get("status") != "DONE")
    if unfinished:
        raise WorkitemContractError(
            "phase closure workitems are not authored DONE: " + ", ".join(unfinished)
        )
    prerequisites = phase_prerequisite_observation(
        repo_root, entries, provider_api=provider_api, repository=repository, policy_subject=policy_subject,
    )
    if not prerequisites["satisfied"]:
        raise WorkitemContractError(
            f"phase closure target {phase_id} prerequisites are unverified: "
            + ", ".join(prerequisites["issues"] + prerequisites["missing_phases"])
        )


def validate_evaluation_authored_ready(
    repo_root: Path, *, intent: str, target: str,
    provider_api: GitHubAPI | None = None, repository: str | None = None,
    policy_subject: MainIdentity | None = None,
) -> None:
    """Validate the authored prerequisite for one exact evaluation intent."""

    try:
        if intent == "workitem":
            validate_bounded_target_authored_ready(
                repo_root, target, provider_api=provider_api, repository=repository, policy_subject=policy_subject,
            )
        elif intent == "closure":
            validate_phase_closure_authored_ready(
                repo_root, provider_api=provider_api, repository=repository, policy_subject=policy_subject,
            )
    except WorkitemContractError as exc:
        boundary = (
            "bounded_certification" if intent == "workitem" else "phase_closure"
        )
        raise WorkitemContractError(f"target_not_ready_for_{boundary}: {exc}") from exc


def _authored_effective_state(authored_state: str) -> str:
    return {
        "DONE": "completed",
        "IN_PROGRESS": "active",
        "BLOCKED": "blocked",
    }.get(authored_state, "planned")


def workitem_observation(
    repo_root: Path,
    receipts: dict[str, list[dict[str, Any]]],
    claim_model: dict[str, Any],
    preflight_claims: set[str],
    subject: dict[str, Any],
    reuse_attestations: Mapping[str, dict[str, Any]] | None = None,
    *, provider_api: GitHubAPI | None = None, repository: str | None = None,
) -> dict[str, Any]:
    """Compute bounded workitem closure without conferring parent authority."""
    ledger = _authored_yaml(repo_root / "plans/phase-ledger.yml")
    active = ledger.get("active_phase") if isinstance(ledger, dict) else None
    workitems_path = active.get("workitems") if isinstance(active, dict) else None
    if not isinstance(workitems_path, str):
        return {"satisfied": False, "issue": "active_workitem_ledger_missing"}
    payload = _authored_yaml(repo_root / workitems_path)
    raw_entries = payload.get("workitems") if isinstance(payload, dict) else None
    if not isinstance(raw_entries, list) or not raw_entries:
        return {"satisfied": False, "issue": "workitems_missing"}
    entries = [entry for entry in raw_entries if isinstance(entry, dict)]
    structural_issues = (
        [] if len(entries) == len(raw_entries) else ["workitem entry is not a mapping"]
    )
    try:
        validate_workitem_dependencies(entries)
    except WorkitemContractError as exc:
        structural_issues.append(str(exc))
    prerequisites = (
        phase_prerequisite_observation(
            repo_root, entries, provider_api=provider_api, repository=repository,
        )
        if not structural_issues else {
            "required_phases": [], "protected_required_phases": [],
            "verified_phases": [], "missing_phases": [], "evidence_refs": [],
            "issues": ["workitem_contract_invalid"], "satisfied": False,
        }
    )

    closed_ids: set[str] = set()
    reports: list[dict[str, Any]] = []
    acceptance_evidence: set[str] = set()
    missing_acceptance_evidence: set[str] = set()
    for entry in entries:
        item_id = str(entry.get("id", "unknown"))
        authored_state = str(entry.get("status", "TODO"))
        gate_ids = sorted(
            {
                str(value)
                for value in entry.get("acceptance_evidence", [])
                if isinstance(value, str)
            }
        )
        acceptance_evidence.update(gate_ids)
        evidence_refs: list[dict[str, Any]] = []
        missing: list[str] = []
        for gate_id in gate_ids:
            candidate = next(
                eligible_receipts(
                    receipts,
                    claim_model,
                    gate_id,
                    preflight_claims,
                    include_preflight=False,
                    reuse_attestations=reuse_attestations,
                ),
                None,
            )
            if candidate is None:
                missing.append(gate_id)
                missing_acceptance_evidence.add(gate_id)
            else:
                evidence_refs.append(
                    {key: value for key, value in candidate.items() if key != "receipt"}
                )
        try:
            predecessors = workitem_predecessors(entry)
            phase_predecessors = workitem_phase_predecessors(entry)
        except WorkitemContractError:
            predecessors = []
            phase_predecessors = []
        missing_phases = sorted(
            (set(phase_predecessors) | set(prerequisites["protected_required_phases"]))
            - set(prerequisites["verified_phases"])
        )
        dependencies_closed = not structural_issues and all(
            predecessor in closed_ids for predecessor in predecessors
        ) and not prerequisites["issues"] and not missing_phases
        verified = (
            authored_state == "DONE"
            and bool(gate_ids)
            and not missing
            and dependencies_closed
            and not structural_issues
        )
        if verified:
            closed_ids.add(item_id)
        reports.append(
            {
                "id": item_id,
                "authored_state": authored_state,
                "effective_state": (
                    "closed" if verified else _authored_effective_state(authored_state)
                ),
                "verification_state": "verified" if verified else "unverified",
                "eligible": dependencies_closed,
                "predecessors": predecessors,
                "phase_predecessors": phase_predecessors,
                "missing_phase_closure": missing_phases,
                "acceptance": entry.get("acceptance", []),
                "required_evidence": gate_ids,
                "missing_or_invalid": missing,
                "evidence_refs": evidence_refs,
                "subject": subject,
                "authority_scope": "workitem_only",
            }
        )
    unclosed_ids = sorted(report["id"] for report in reports if report["effective_state"] != "closed")
    open_ids = sorted(
        report["id"] for report in reports if report["authored_state"] != "DONE"
    )
    return {
        "satisfied": not structural_issues and not unclosed_ids,
        "workitems_path": workitems_path,
        "total": len(raw_entries),
        "open_ids": open_ids,
        "unclosed_ids": unclosed_ids,
        "closed_ids": sorted(closed_ids),
        "acceptance_evidence": sorted(acceptance_evidence),
        "missing_acceptance_evidence": sorted(missing_acceptance_evidence),
        "structural_issues": structural_issues,
        "phase_prerequisites": prerequisites,
        "items": reports,
    }
