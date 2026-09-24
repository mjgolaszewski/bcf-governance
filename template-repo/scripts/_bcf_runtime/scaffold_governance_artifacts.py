"""Scaffold governed phase and hotfix artifacts for the template governance pack."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Iterable

import yaml  # type: ignore[import-untyped]

try:
    from bcf_governance import __version__
except ModuleNotFoundError:  # Standalone template runtime owns a relative projection.
    from ._version import __version__

from .test_manifests import declared_test_gates

HOTFIX_MODES = {"lite", "full"}


def _phase_number(phase_id: str) -> int:
    if not phase_id.startswith("P") or not phase_id[1:].isdigit():
        raise ValueError(f"invalid phase id {phase_id!r}; expected values like 'P01'")
    return int(phase_id[1:])


def _phase_stem(phase_id: str) -> str:
    return f"phase-{_phase_number(phase_id):02d}"


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


def _hotfix_stem(related_phase_id: str, hotfix_number: int | str) -> str:
    return f"{_phase_stem(related_phase_id)}-hotfix{_hotfix_number(hotfix_number):02d}"


def _hotfix_mode(mode: str) -> str:
    if mode not in HOTFIX_MODES:
        raise ValueError(f"invalid hotfix mode {mode!r}; expected one of {sorted(HOTFIX_MODES)}")
    return mode


def _write_yaml(path: Path, payload: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _repo_relative_path(repo_root: Path, path: Path) -> str:
    return path.relative_to(repo_root).as_posix()


def scaffold_phase_artifacts(
    *,
    repo_root: Path,
    project_id: str,
    phase_id: str,
    build_block: str,
    objective: str,
    planner: str,
    date: str,
    hard_dependencies: list[str],
    deliverables: list[str],
    workstreams: list[str],
    verification_commands: list[str],
    force: bool,
) -> dict[str, Path]:
    stem = _phase_stem(phase_id)
    phase_number = _phase_number(phase_id)
    plan_path = repo_root / "plans" / f"{stem}-plan.yml"
    workitems_path = repo_root / "plans" / f"{stem}-workitems.yml"
    log_path = repo_root / "phases" / f"{stem}-log.yml"

    plan_payload = {
        "document": {
            "kind": "execution_phase_plan",
            "name": f"Phase {phase_number:02d} Plan",
            "id": f"{project_id}-{stem}-plan",
            "version": "1.0.0",
            "generated_at_utc": f"{date}T00:00:00Z",
            "status": "planned",
            "path": _repo_relative_path(repo_root, plan_path),
        },
        "phase": {
            "id": phase_id,
            "build_block": build_block,
            "planner": planner,
            "date": date,
            "scope_source": [
                "AGENTS.yml",
                "plans/product-spec.yml",
                "plans/build-plan.yml",
                "plans/phase-ledger.yml",
                "MEMORY.yml",
            ],
        },
        "delivery_contract": {
            "tightly_scoped_deliverables": deliverables,
            "parallelizable_workstreams": [
                {"id": f"{phase_id}-WS{index + 1}", "name": workstream}
                for index, workstream in enumerate(workstreams)
            ],
            "hard_dependencies": hard_dependencies,
            "docker_first_local_runtime": "repo_native_validation_and_governance_commands",
            "completeness_standard": "full_completeness_for_declared_scope",
        },
        "scope_lock": [
            {
                "order": 1,
                "statement": (
                    "keep the phase narrowly scoped to declared deliverables and update "
                    "canonical governed artifacts in the same change"
                ),
            }
        ],
        "verification_plan": verification_commands,
    }

    workitem_entries = [
        {
            "id": f"{phase_id}-P0-{index + 1:02d}",
            "priority": "P0",
            "status": "TODO",
            "summary": f"deliver {deliverable}",
            "acceptance": [f"{deliverable}_is_complete"],
            "acceptance_evidence": ["test", "contract-test"],
        }
        for index, deliverable in enumerate(deliverables)
    ]

    workitems_payload = {
        "document": {
            "kind": "execution_phase_workitem_ledger",
            "name": f"Phase {phase_number:02d} Workitems",
            "id": f"{project_id}-{stem}-workitems",
            "version": "1.0.0",
            "generated_at_utc": f"{date}T00:00:00Z",
            "status": "planned",
            "path": _repo_relative_path(repo_root, workitems_path),
            "phase_id": phase_id,
        },
        "workitems": workitem_entries,
    }

    log_payload = {
        "document": {
            "kind": "execution_phase_log",
            "name": f"Phase {phase_number:02d} Log",
            "id": f"{project_id}-{stem}-log",
            "version": "1.0.0",
            "generated_at_utc": f"{date}T00:00:00Z",
            "status": "planned",
            "path": _repo_relative_path(repo_root, log_path),
        },
        "phase": {"id": phase_id, "build_block": build_block},
        "summary": {
            "outcome": "planned",
            "highlights": [
                f"{phase_id} is opened for {objective}",
                "phase artifacts were scaffolded from the governance template",
            ],
        },
        "workitems": [
            {"id": workitem["id"], "status": workitem["status"], "summary": workitem["summary"]}
            for workitem in workitem_entries
        ],
        "execution_evidence": {
            "planned_commands": verification_commands,
            "executed_commands": [],
            "notes": ["phase scaffolding was generated by scaffold_governance_artifacts.py"],
        },
        "closeout_requirements": {
            "claims": {
                "workitems_closed": {"required_evidence": ["governance-validate"]},
                "required_suites_green": {
                    "required_evidence": ["lint", "typecheck", "test", "contract-test"]
                },
                "architecture_gates_green": {"required_evidence": ["architecture-test"]},
                "health_checks_green": {"required_evidence": ["runtime-smoke"]},
                "security_review_complete": {"required_evidence": ["governance-validate"]},
                "findings_resolved": {
                    "required_evidence": ["security-vulnerability-scan"]
                },
            },
            "reconciliation": {
                "required_evidence": ["governance-validate", "governance-exposure-scan"]
            },
            "finding_registry": "governance/findings.yml",
        },
        "known_constraints": [
            "update canonical governed artifacts together when behavior or environment contracts change"
        ],
        "next_work": ["implement scoped workitems and record execution evidence in this log"],
    }

    _write_yaml(plan_path, plan_payload, force=force)
    _write_yaml(workitems_path, workitems_payload, force=force)
    _write_yaml(log_path, log_payload, force=force)
    return {"plan": plan_path, "workitems": workitems_path, "log": log_path}


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
    hotfix_stem = _hotfix_stem(related_phase_id, hotfix_number)
    log_path = repo_root / "phases" / f"{hotfix_stem}.yml"
    payload = {
        "document": {
            "kind": "hotfix_execution_log",
            "name": f"{hotfix_id} Hotfix Log",
            "id": f"{project_id}-{hotfix_stem}",
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
                "required_suites_green": {"required_evidence": ["test", "contract-test"]},
                "security_review_complete": {"required_evidence": ["governance-validate"]},
                "health_checks_green": {"required_evidence": ["runtime-smoke"]},
            },
            "reconciliation": {
                "required_evidence": ["governance-validate", "governance-exposure-scan"]
            },
            "finding_registry": "governance/findings.yml",
        },
    }
    _write_yaml(log_path, payload, force=force)
    return log_path


class ReconcileError(ValueError):
    """Governed projections cannot be checked or converged safely."""


Action = Callable[[], None]


@dataclass(frozen=True)
class ReconcileStep:
    """One canonical projection owner with distinct check and apply actions."""

    step_id: str
    check: Action
    apply: Action


def _run_reconcile_command(command: list[str], *, repo_root: Path, step_id: str) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        command,
        cwd=repo_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ReconcileError(f"{step_id} failed: {detail}")


def _reconcile_action(repo_root: Path, step_id: str, command: list[str]) -> Action:
    return lambda: _run_reconcile_command(command, repo_root=repo_root, step_id=step_id)


def _editorial_base(audit: Path) -> str:
    try:
        payload = yaml.safe_load(audit.read_text(encoding="utf-8"))
        base = payload["base_commit"]
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        raise ReconcileError("editorial audit does not expose an immutable base") from exc
    if not isinstance(base, str) or len(base) != 40 or any(c not in "0123456789abcdef" for c in base):
        raise ReconcileError("editorial audit base is not an exact commit")
    return base


def reconcile_steps(repo_root: Path, python: Path) -> tuple[ReconcileStep, ...]:
    """Return the closed canonical projection order for this repository."""

    cli = [str(python), "-m", "bcf_governance.cli"]
    steps: list[ReconcileStep] = [
        ReconcileStep(
            "semantic-lock",
            _reconcile_action(repo_root, "semantic-lock", [*cli, "semantic-ownership", "lock", "--repo-root", str(repo_root), "--check"]),
            _reconcile_action(repo_root, "semantic-lock", [*cli, "semantic-ownership", "lock", "--repo-root", str(repo_root), "--apply"]),
        )
    ]
    for gate_id in declared_test_gates(repo_root):
        common = [*cli, "test-manifest"]
        suffix = ["--gate", gate_id, "--repo-root", str(repo_root), "--python", str(python)]
        steps.append(
            ReconcileStep(
                f"test-manifest:{gate_id}",
                _reconcile_action(repo_root, f"test-manifest:{gate_id}", [*common, "check", *suffix]),
                _reconcile_action(repo_root, f"test-manifest:{gate_id}", [*common, "update", *suffix]),
            )
        )
    for operation in ("lock", "render"):
        steps.append(
            ReconcileStep(
                f"ci-graph-{operation}",
                _reconcile_action(repo_root, f"ci-graph-{operation}", [*cli, "ci", "graph", operation, "--repo-root", str(repo_root), "--check"]),
                _reconcile_action(repo_root, f"ci-graph-{operation}", [*cli, "ci", "graph", operation, "--repo-root", str(repo_root), "--apply"]),
            )
        )
    pack = repo_root / ".github/scripts/build_pack_manifest.py"
    if pack.is_file() and not pack.is_symlink():
        steps.append(
            ReconcileStep(
                "pack-projection",
                _reconcile_action(repo_root, "pack-projection", [str(python), str(pack), "--check"]),
                _reconcile_action(repo_root, "pack-projection", [str(python), str(pack)]),
            )
        )
    checker = repo_root / ".github/scripts/check_editorial_contract.py"
    builder = repo_root / ".github/scripts/build_editorial_audit.py"
    if checker.is_file() and builder.is_file() and not checker.is_symlink() and not builder.is_symlink():
        audit = repo_root / f"audits/v{__version__}-editorial-review.yml"
        base = _editorial_base(audit)
        steps.append(
            ReconcileStep(
                "editorial-audit",
                _reconcile_action(repo_root, "editorial-audit", [str(python), str(checker)]),
                _reconcile_action(repo_root, "editorial-audit", [str(python), str(builder), "--repo-root", str(repo_root), "--audit", str(audit), "--base-sha", base, "--apply"]),
            )
        )
    return tuple(steps)


def _reconcile_snapshot(repo_root: Path) -> str:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ReconcileError("cannot inventory governed repository files")
    digest = hashlib.sha256()
    for raw in sorted(value for value in result.stdout.split(b"\0") if value):
        relative = raw.decode("utf-8")
        path = repo_root / relative
        digest.update(raw + b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0" + os.readlink(path).encode())
        elif path.is_file():
            digest.update(b"file\0" + path.read_bytes())
        else:
            digest.update(b"absent\0")
    return digest.hexdigest()


def converge(
    steps: Iterable[ReconcileStep],
    snapshot: Callable[[], str],
    *,
    max_rounds: int = 4,
) -> int:
    """Apply the ordered owners until one entire round is byte-stable."""

    ordered = tuple(steps)
    for round_number in range(1, max_rounds + 1):
        before = snapshot()
        for step in ordered:
            step.apply()
        if snapshot() == before:
            for step in ordered:
                step.check()
            return round_number
    raise ReconcileError(f"governance projections did not converge after {max_rounds} rounds")


def reconcile_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Converge all mechanically derived governance surfaces.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    try:
        steps = reconcile_steps(root, args.python.resolve())
        if args.check:
            for step in steps:
                step.check()
            rounds = 0
        else:
            rounds = converge(steps, lambda: _reconcile_snapshot(root))
    except (OSError, UnicodeError, ReconcileError, ValueError) as exc:
        raise SystemExit(f"governance-reconcile-failed: {exc}") from exc
    print(json.dumps({"status": "clean" if args.check else "converged", "rounds": rounds, "steps": [step.step_id for step in steps]}, sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scaffold governed phase or hotfix artifacts.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--project-id", default="project")
    parser.add_argument("--force", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    phase = subparsers.add_parser("phase")
    phase.add_argument("--phase-id", required=True)
    phase.add_argument("--build-block", required=True)
    phase.add_argument("--objective", required=True)
    phase.add_argument("--planner", default="codex")
    phase.add_argument("--date", required=True)
    phase.add_argument("--hard-dependency", action="append", default=[])
    phase.add_argument("--deliverable", action="append", required=True)
    phase.add_argument("--workstream", action="append", required=True)
    phase.add_argument("--verification-command", action="append", required=True)

    hotfix = subparsers.add_parser("hotfix")
    hotfix.add_argument("--hotfix-id", required=True)
    hotfix.add_argument("--mode", choices=sorted(HOTFIX_MODES), default="full")
    hotfix.add_argument("--hotfix-number", type=int, required=True)
    hotfix.add_argument("--summary", required=True)
    hotfix.add_argument("--related-phase-id", required=True)
    hotfix.add_argument("--date", required=True)
    hotfix.add_argument("--validation-command", action="append", required=True)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    repo_root = args.repo_root.resolve()
    if args.command == "phase":
        created = scaffold_phase_artifacts(
            repo_root=repo_root,
            project_id=args.project_id,
            phase_id=args.phase_id,
            build_block=args.build_block,
            objective=args.objective,
            planner=args.planner,
            date=args.date,
            hard_dependencies=args.hard_dependency,
            deliverables=args.deliverable,
            workstreams=args.workstream,
            verification_commands=args.verification_command,
            force=args.force,
        )
        for artifact_type, path in created.items():
            print(f"{artifact_type}: {path.relative_to(repo_root)}")
        return
    if args.command == "hotfix":
        created_path = scaffold_hotfix_log(
            repo_root=repo_root,
            project_id=args.project_id,
            hotfix_id=args.hotfix_id,
            mode=args.mode,
            hotfix_number=args.hotfix_number,
            summary=args.summary,
            related_phase_id=args.related_phase_id,
            date=args.date,
            validation_commands=args.validation_command,
            force=args.force,
        )
        print(f"hotfix_log: {created_path.relative_to(repo_root)}")


if __name__ == "__main__":
    main()
