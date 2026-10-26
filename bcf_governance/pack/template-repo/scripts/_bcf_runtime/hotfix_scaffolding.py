"""Construct and register one governed hotfix without a second manual step."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .check_governance_exposure import PATTERNS as GOVERNANCE_EXPOSURE_PATTERNS

HOTFIX_MODES = {"lite", "full"}


def _portable_governed_commands(commands: list[str]) -> list[str]:
    for command in commands:
        matched = sorted(
            name
            for name, pattern in GOVERNANCE_EXPOSURE_PATTERNS.items()
            if pattern.search(command)
        )
        if matched:
            raise ValueError(
                "governed validation command exposes nonportable infrastructure: "
                + ", ".join(matched)
            )
    return commands


def _phase_number(phase_id: str) -> int:
    if not phase_id.startswith("P") or not phase_id[1:].isdigit():
        raise ValueError(f"invalid phase id {phase_id!r}; expected values like 'P01'")
    return int(phase_id[1:])


def _hotfix_number(hotfix_number: int | str) -> int:
    try:
        number = int(hotfix_number)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"invalid hotfix number {hotfix_number!r}; expected a positive integer"
        ) from exc
    if number <= 0:
        raise ValueError(
            f"invalid hotfix number {hotfix_number!r}; expected a positive integer"
        )
    return number


def _hotfix_mode(mode: str) -> str:
    if mode not in HOTFIX_MODES:
        raise ValueError(
            f"invalid hotfix mode {mode!r}; expected one of {sorted(HOTFIX_MODES)}"
        )
    return mode


def _repo_relative_path(repo_root: Path, path: Path) -> str:
    return path.relative_to(repo_root).as_posix()


def _write_yaml_idempotent(
    path: Path, payload: dict[str, Any], *, force: bool
) -> None:
    if path.exists() and not force:
        try:
            current = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise FileExistsError(f"{path} already exists and is unreadable") from exc
        if current == payload:
            return
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def scaffold_hotfix_log(
    *,
    repo_root: Path,
    project_id: str,
    hotfix_id: str,
    mode: str,
    hotfix_number: int,
    summary: str,
    related_phase_id: str,
    date: str,
    validation_commands: list[str],
    force: bool,
) -> Path:
    validation_commands = _portable_governed_commands(validation_commands)
    stem = f"phase-{_phase_number(related_phase_id):02d}-hotfix{_hotfix_number(hotfix_number):02d}"
    log_path = repo_root / "phases" / f"{stem}.yml"
    payload = {
        "document": {
            "kind": "hotfix_execution_log",
            "name": f"{hotfix_id} Hotfix Log",
            "id": f"{project_id}-{stem}",
            "version": "1.0.0",
            "generated_at_utc": f"{date}T00:00:00Z",
            "status": "planned",
            "path": _repo_relative_path(repo_root, log_path),
        },
        "hotfix": {
            "id": hotfix_id,
            "mode": _hotfix_mode(mode),
            "related_phase_id": related_phase_id,
            "hotfix_number": hotfix_number,
            "summary": summary,
        },
        "execution_evidence": {
            "planned_commands": validation_commands,
            "executed_commands": [],
            "notes": [
                "record failing workflows, diagnosed root cause, remediation scope, and merge-back status"
            ],
        },
        "closeout_requirements": {
            "claims": {
                "required_suites_green": {
                    "required_evidence": ["test", "contract-test"]
                },
                "security_review_complete": {
                    "required_evidence": ["governance-validate"]
                },
                "health_checks_green": {"required_evidence": ["runtime-smoke"]},
            },
            "reconciliation": {
                "required_evidence": ["governance-validate", "governance-exposure-scan"]
            },
            "finding_registry": "governance/findings.yml",
        },
    }
    _write_yaml_idempotent(log_path, payload, force=force)
    return log_path


def register_hotfix_log(
    *,
    repo_root: Path,
    hotfix_log: Path,
    hotfix_id: str,
    mode: str,
    related_phase_id: str,
    triggered_by_commits: list[str],
    failing_workflows: list[str],
    root_cause: str,
    canonical_artifacts: list[str],
) -> None:
    """Project one scaffolded hotfix into its canonical ledger record."""

    ledger_path = repo_root / "plans/phase-ledger.yml"
    if ledger_path.is_symlink() or not ledger_path.is_file():
        raise ValueError("hotfix phase ledger is missing or unsafe")
    try:
        ledger = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
        lane = ledger["hotfix_lane"]
        open_records = lane["open_records"]
    except (OSError, UnicodeError, yaml.YAMLError, TypeError, KeyError) as exc:
        raise ValueError("hotfix phase ledger is invalid") from exc
    if (
        not isinstance(ledger, dict)
        or not isinstance(lane, dict)
        or not isinstance(open_records, list)
    ):
        raise ValueError("hotfix phase ledger is invalid")
    if not triggered_by_commits or any(
        not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{40}", value) is None
        for value in triggered_by_commits
    ):
        raise ValueError("hotfix trigger commits must be exact Git identities")
    if not root_cause.strip():
        raise ValueError("hotfix root cause is required")
    for name, values in (
        ("failing workflows", failing_workflows),
        ("canonical artifacts", canonical_artifacts),
    ):
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError(f"hotfix {name} are invalid")
    record = {
        "id": hotfix_id,
        "mode": _hotfix_mode(mode),
        "status": "active",
        "triggered_by_commits": triggered_by_commits,
        "failing_workflows": failing_workflows,
        "root_cause": root_cause,
        "remediated_in_phase": related_phase_id,
        "canonical_artifacts": canonical_artifacts,
        "hotfix_log": _repo_relative_path(repo_root, hotfix_log),
    }
    matches = [
        item
        for item in open_records
        if isinstance(item, dict) and item.get("id") == hotfix_id
    ]
    if matches:
        current = matches[0]
        stable_fields = set(record) - {"canonical_artifacts"}
        if any(current.get(field) != record[field] for field in stable_fields):
            raise ValueError("hotfix phase ledger record conflicts with scaffold inputs")
        merged = sorted(
            set(current.get("canonical_artifacts", []))
            | set(record["canonical_artifacts"])
        )
        if current.get("canonical_artifacts") == merged:
            return
        current["canonical_artifacts"] = merged
    else:
        open_records.append(record)
    ledger_path.write_text(
        json.dumps(ledger, sort_keys=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
