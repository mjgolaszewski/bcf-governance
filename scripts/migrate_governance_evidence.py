"""Migrate authored terminal governance state to computed lifecycle requirements."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


LEGACY_CLOSEOUT_FIELDS = (
    "all_tickets_closed",
    "required_suites_green",
    "ast_architecture_gates_green",
    "health_checks_green",
    "security_review_complete",
    "release_ready",
    "zero_findings",
)
TERMINAL_STATES = {"verified", "closed", "released", "release_ready"}
HEX_DIGEST = re.compile(r"^[a-f0-9]+$")


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_hex_digest(value: object, lengths: set[int]) -> bool:
    return (
        isinstance(value, str)
        and len(value) in lengths
        and HEX_DIGEST.fullmatch(value) is not None
    )


def _write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False, default_flow_style=False, width=120),
        encoding="utf-8",
    )


def _required_gates(repo_root: Path) -> tuple[list[str], list[str], list[str], list[str]]:
    profile = _load_yaml(repo_root / "governance-profile.yml")
    release_profile = profile.get("release_gate_profile")
    gates = release_profile.get("gates") if isinstance(release_profile, dict) else {}
    tests: list[str] = []
    architecture: list[str] = []
    security: list[str] = []
    health: list[str] = []
    if isinstance(gates, dict):
        for value in gates.values():
            if not isinstance(value, dict) or value.get("status") not in {"required", "deferred"}:
                continue
            target = value.get("target")
            policy = str(value.get("command_policy", ""))
            if not isinstance(target, str):
                continue
            if policy.startswith("architecture_") or policy == "architecture_tests":
                architecture.append(target)
            elif policy.startswith("security_"):
                security.append(target)
            elif policy == "runtime_smoke":
                health.append(target)
            elif policy in {"automated_tests", "contract_tests", "lint", "typecheck"}:
                tests.append(target)
    return sorted(tests), sorted(architecture), sorted(security), sorted(health)


def _closeout_requirements(repo_root: Path) -> dict[str, Any]:
    tests, architecture, security, health = _required_gates(repo_root)
    return {
        "claims": {
            "workitems_closed": {"required_evidence": ["governance-validate"]},
            "required_suites_green": {"required_evidence": tests},
            "architecture_gates_green": {"required_evidence": architecture},
            "health_checks_green": {"required_evidence": health},
            "security_review_complete": {"required_evidence": security},
            "findings_resolved": {"required_evidence": security},
        },
        "reconciliation": {
            "required_evidence": ["governance-validate", "governance-exposure-scan"]
        },
        "finding_registry": "governance/findings.yml",
    }


def _migrate_phase_log(
    repo_root: Path, path: Path, report_entries: list[dict[str, Any]], *, apply: bool
) -> bool:
    original = path.read_bytes()
    payload = _load_yaml(path)
    document = payload.get("document")
    if not isinstance(document, dict):
        return False
    legacy: dict[str, Any] = {}
    old_status = document.get("status")
    if old_status in TERMINAL_STATES:
        legacy["document.status"] = old_status
        document["status"] = "completed"
    for field in LEGACY_CLOSEOUT_FIELDS:
        if field in payload:
            legacy[field] = payload.pop(field)
    is_hotfix = document.get("kind") == "hotfix_execution_log"
    if is_hotfix and "reconciliation" in payload:
        legacy["reconciliation"] = payload.pop("reconciliation")
    if "closeout_requirements" not in payload:
        if is_hotfix:
            requirements = _closeout_requirements(repo_root)
            payload["closeout_requirements"] = {
                "claims": requirements["claims"],
                "reconciliation": requirements["reconciliation"],
                "finding_registry": "governance/findings.yml",
            }
        else:
            payload["closeout_requirements"] = _closeout_requirements(repo_root)
    elif is_hotfix and isinstance(payload["closeout_requirements"], dict):
        payload["closeout_requirements"].setdefault(
            "reconciliation", _closeout_requirements(repo_root)["reconciliation"]
        )
    if not legacy and payload == _load_yaml(path):
        return False
    updated = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False, width=120).encode("utf-8")
    if updated == original:
        return False
    report_entries.append(
        {
            "path": path.relative_to(repo_root).as_posix(),
            "source_sha256": _sha256_bytes(original),
            "legacy_attestations": legacy,
            "authoritative": False,
        }
    )
    if apply:
        _write_yaml(path, payload)
    return True


def _migrate_ledger(
    repo_root: Path, path: Path, report_entries: list[dict[str, Any]], *, apply: bool
) -> bool:
    original = path.read_bytes()
    payload = _load_yaml(path)
    before = copy.deepcopy(payload)
    legacy: dict[str, Any] = {}
    active = payload.get("active_phase")
    if isinstance(active, dict) and active.get("lifecycle_status") in TERMINAL_STATES:
        legacy["active_phase.lifecycle_status"] = active["lifecycle_status"]
        active["lifecycle_status"] = "completed"
    release_trains = payload.get("release_trains")
    if isinstance(release_trains, dict):
        for release_id, raw in release_trains.items():
            if isinstance(raw, dict) and raw.get("status") in TERMINAL_STATES:
                legacy[f"release_trains.{release_id}.status"] = raw["status"]
                raw["status"] = "completed"
    readiness = payload.get("release_readiness")
    if isinstance(readiness, dict):
        if "status" in readiness:
            legacy["release_readiness.status"] = readiness.pop("status")
        readiness["computed_by"] = "bcf truth"
        readiness["requirements_source"] = "governance/evidence-policy.yml"
    if payload == before:
        return False
    updated = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False, width=120).encode("utf-8")
    if updated == original:
        return False
    report_entries.append(
        {
            "path": path.relative_to(repo_root).as_posix(),
            "source_sha256": _sha256_bytes(original),
            "legacy_attestations": legacy,
            "authoritative": False,
        }
    )
    if apply:
        _write_yaml(path, payload)
    return True


def _migrate_history(
    repo_root: Path, path: Path, report_entries: list[dict[str, Any]], *, apply: bool
) -> bool:
    if not path.exists():
        return False
    original = path.read_bytes()
    payload = _load_yaml(path)
    changed = False
    legacy: dict[str, Any] = {}
    entries = payload.get("entries")
    if isinstance(entries, list):
        for index, raw in enumerate(entries):
            if not isinstance(raw, dict) or raw.get("status") not in {"verified", "closed"}:
                continue
            terminal_state = str(raw["status"])
            legacy[f"entries.{index}.status"] = terminal_state
            snapshot = raw.get("verification_snapshot")
            snapshot_valid = isinstance(snapshot, dict) and all(
                _is_hex_digest(snapshot.get(field), lengths)
                for field, lengths in (
                    ("commit_sha", {40, 64}),
                    ("tree_sha", {40, 64}),
                    ("truth_report_sha256", {64}),
                    ("evidence_bundle_sha256", {64}),
                )
            ) and isinstance(snapshot.get("durable_ref"), str) and bool(
                snapshot["durable_ref"]
            ) and isinstance(snapshot.get("verifier"), dict) and (
                snapshot["verifier"].get("kind") in {"human", "model", "service", "workflow"}
            ) and isinstance(snapshot["verifier"].get("id"), str) and bool(
                snapshot["verifier"]["id"]
            )
            raw["status"] = "completed"
            if snapshot_valid:
                raw["derived_state_at_capture"] = terminal_state
                raw.pop("legacy_terminal_status", None)
            else:
                raw["legacy_terminal_status"] = terminal_state
                if "verification_snapshot" in raw:
                    legacy[f"entries.{index}.verification_snapshot"] = raw.pop(
                        "verification_snapshot"
                    )
                if "derived_state_at_capture" in raw:
                    legacy[f"entries.{index}.derived_state_at_capture"] = raw.pop(
                        "derived_state_at_capture"
                    )
            changed = True
    if not changed:
        return False
    report_entries.append(
        {
            "path": path.relative_to(repo_root).as_posix(),
            "source_sha256": _sha256_bytes(original),
            "legacy_attestations": legacy,
            "authoritative": False,
        }
    )
    if apply:
        _write_yaml(path, payload)
    return True


def _migrate_workitems(
    repo_root: Path, path: Path, report_entries: list[dict[str, Any]], *, apply: bool
) -> bool:
    original = path.read_bytes()
    payload = _load_yaml(path)
    changed = False
    entries = payload.get("workitems")
    if isinstance(entries, list):
        for raw in entries:
            if isinstance(raw, dict) and "acceptance_evidence" not in raw:
                raw["acceptance_evidence"] = ["test", "contract-test"]
                changed = True
    if not changed:
        return False
    report_entries.append(
        {
            "path": path.relative_to(repo_root).as_posix(),
            "source_sha256": _sha256_bytes(original),
            "legacy_attestations": {},
            "authoritative": False,
        }
    )
    if apply:
        _write_yaml(path, payload)
    return True


def migration_plan(repo_root: Path, *, apply: bool = False) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    entries: list[dict[str, Any]] = []
    changed_paths: list[str] = []
    for path in sorted((repo_root / "phases").glob("*.yml")):
        if _migrate_phase_log(repo_root, path, entries, apply=apply):
            changed_paths.append(path.relative_to(repo_root).as_posix())
    for path in sorted((repo_root / "plans").glob("phase-*-workitems.yml")):
        if _migrate_workitems(repo_root, path, entries, apply=apply):
            changed_paths.append(path.relative_to(repo_root).as_posix())
    ledger_path = repo_root / "plans/phase-ledger.yml"
    if ledger_path.exists() and _migrate_ledger(repo_root, ledger_path, entries, apply=apply):
        changed_paths.append("plans/phase-ledger.yml")
    history_path = repo_root / "plans/phase-history.yml"
    if _migrate_history(repo_root, history_path, entries, apply=apply):
        changed_paths.append("plans/phase-history.yml")
    report = {
        "document": {
            "kind": "evidence_integrity_migration",
            "version": "1.0",
            "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "authoritative": False,
        },
        "changed_paths": changed_paths,
        "legacy_records": entries,
    }
    if apply and changed_paths:
        report_path = repo_root / "governance/migrations/evidence-integrity-v1.yml"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        _write_yaml(report_path, report)
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Migrate governance lifecycle to computed evidence state.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    report = migration_plan(args.repo_root, apply=args.apply)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        status = "required" if report["changed_paths"] else "not-required"
        print(f"evidence-migration-{status}")
        for path in report["changed_paths"]:
            print(f"- {path}")
    if args.check and report["changed_paths"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
