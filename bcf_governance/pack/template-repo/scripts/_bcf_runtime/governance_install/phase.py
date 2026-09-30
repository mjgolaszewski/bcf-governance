"""Install-time phase artifact construction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import scaffold_governance_artifacts
from ..governance_validation.release_gates import canonical_release_check_command


def _validation_commands(profile: str, repo_root: Path) -> list[str]:
    if profile == "lite":
        return ["make governance-validate"]
    return [
        "make governance-validate",
        "make architecture-test",
        canonical_release_check_command(repo_root),
    ]


def generate_phase_artifacts(args: Any, target_root: Path) -> dict[str, Path]:
    return scaffold_governance_artifacts.scaffold_phase_artifacts(
        repo_root=target_root,
        project_id=args.project_id,
        phase_id=args.phase_id,
        build_block=args.build_block,
        objective=args.phase_objective,
        planner=args.planner,
        date=args.date,
        hard_dependencies=args.hard_dependency,
        deliverables=args.deliverable,
        workstreams=args.workstream,
        verification_commands=_validation_commands(args.profile, target_root),
        force=True,
    )
