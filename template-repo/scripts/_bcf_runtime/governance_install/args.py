"""Install command argument parser."""

from __future__ import annotations

import argparse
from pathlib import Path


def build_parser(
    *,
    profile_choices: tuple[str, ...],
    adoption_mode_choices: tuple[str, ...],
    default_target_user: str,
    default_runner_labels: str,
    default_date: str,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install the governance pack into a target repository.")
    parser.add_argument("--target", type=Path, required=True, help="Target repository root.")
    parser.add_argument(
        "--profile",
        choices=profile_choices,
        help="Fresh installs default to standard; upgrades preserve the installed profile.",
    )
    parser.add_argument(
        "--profile-contract-version",
        choices=("1.0", "2.0"),
        help="Fresh Standard/Regulated default to 2.0; upgrades preserve the installed version.",
    )
    parser.add_argument(
        "--adoption-mode",
        choices=adoption_mode_choices,
        default="fresh",
        help="Use fresh for new repositories or existing to label conversion/inventory phase artifacts.",
    )
    parser.add_argument("--project-id", help="Machine-readable project id. Defaults from --target name.")
    parser.add_argument("--project-name", help="Human-readable project name. Defaults from --project-id.")
    parser.add_argument("--product-name", help="Product name. Defaults from --project-name.")
    parser.add_argument(
        "--product-positioning",
        default="governed agent-led software delivery",
        help="Short product positioning used in product-spec.yml.",
    )
    parser.add_argument("--target-user", default=default_target_user)
    parser.add_argument("--runner-labels", default=default_runner_labels)
    parser.add_argument("--phase-id", default="P01")
    parser.add_argument("--build-block", default="foundation")
    parser.add_argument("--phase-objective", default="establish governed foundation")
    parser.add_argument("--planner", default="codex")
    parser.add_argument("--date", default=default_date)
    parser.add_argument("--hard-dependency", action="append", default=[])
    parser.add_argument("--deliverable", action="append", default=["initial governed foundation"])
    parser.add_argument("--workstream", action="append", default=["bootstrap governance pack"])
    parser.add_argument("--backend-architecture", default="cqrs_lite_with_strict_ports")
    parser.add_argument("--frontend-architecture", default="route_modules_thin_components")
    parser.add_argument("--data-architecture", default="repo_defined")
    parser.add_argument("--operating-constraint", default="repo_native_runtime")
    parser.add_argument(
        "--profile-config",
        type=Path,
        help="Typed gate-contract configuration required by standard and regulated profiles.",
    )
    parser.add_argument(
        "--force-rescaffold",
        action="store_true",
        help="Delete known BCF governance artifacts, then install a fresh governance pack.",
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Refresh latest pack-owned support files while preserving product and phase state.",
    )
    parser.add_argument(
        "--reset-options",
        action="store_true",
        help="With --upgrade, reset profile, Makefile, and architecture option surfaces from current flags.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm destructive --force-rescaffold without an interactive prompt.",
    )
    parser.add_argument("--skip-validation", action="store_true")
    parser.add_argument(
        "--require-strict-validation",
        action="store_true",
        help="Fail installation if strict validation does not pass after install.",
    )
    return parser
