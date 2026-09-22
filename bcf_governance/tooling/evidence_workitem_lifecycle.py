"""Evidence-derived lifecycle state for ordinary phase workitems."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml  # type: ignore[import-untyped]

from .truth_reporting import eligible_receipts


DEPENDENCY_PREFIX = "requires-workitem-closure:"


class WorkitemContractError(ValueError):
    """Raised when ordinary workitem dependency declarations are ambiguous."""


def workitem_predecessors(entry: dict[str, Any]) -> list[str]:
    """Decode exact predecessor predicates from the existing acceptance contract."""
    values = entry.get("acceptance", [])
    if not isinstance(values, list):
        raise WorkitemContractError("workitem acceptance must be a list")
    predecessors: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise WorkitemContractError("workitem acceptance predicates must be strings")
        if value.startswith(DEPENDENCY_PREFIX):
            predecessor = value.removeprefix(DEPENDENCY_PREFIX)
            if not predecessor or ":" in predecessor:
                raise WorkitemContractError(
                    f"malformed workitem closure predicate {value!r}"
                )
            predecessors.append(predecessor)
    if len(predecessors) != len(set(predecessors)):
        raise WorkitemContractError("duplicate workitem predecessor declaration")
    return predecessors


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
    return ids


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
) -> dict[str, Any]:
    """Compute bounded workitem closure without conferring parent authority."""
    ledger = yaml.safe_load(
        (repo_root / "plans/phase-ledger.yml").read_text(encoding="utf-8")
    )
    active = ledger.get("active_phase") if isinstance(ledger, dict) else None
    workitems_path = active.get("workitems") if isinstance(active, dict) else None
    if not isinstance(workitems_path, str):
        return {"satisfied": False, "issue": "active_workitem_ledger_missing"}
    payload = yaml.safe_load((repo_root / workitems_path).read_text(encoding="utf-8"))
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
        except WorkitemContractError:
            predecessors = []
        dependencies_closed = not structural_issues and all(
            predecessor in closed_ids for predecessor in predecessors
        )
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
        "items": reports,
    }
