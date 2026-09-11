"""Command-line adapter for the governance-pack installer."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime

from ..install_governance_pack import (
    ADOPTION_MODE_CHOICES,
    DEFAULT_RUNNER_LABELS,
    DEFAULT_TARGET_USER,
    PROFILE_CHOICES,
    REQUIRED_STANDARD_GATES,
    _apply_adoption_mode_defaults,
    _project_id_from_name,
    _title_from_id,
    install,
)
from .args import build_parser
from .reporting import print_summary


def _parser() -> argparse.ArgumentParser:
    return build_parser(
        profile_choices=PROFILE_CHOICES,
        adoption_mode_choices=ADOPTION_MODE_CHOICES,
        default_target_user=DEFAULT_TARGET_USER,
        default_runner_labels=DEFAULT_RUNNER_LABELS,
        default_date=datetime.now(UTC).date().isoformat(),
    )


def _finalize_args(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> argparse.Namespace:
    if args.project_id is None:
        args.project_id = _project_id_from_name(args.target.resolve().name)
    if args.project_name is None:
        args.project_name = _title_from_id(args.project_id)
    if args.product_name is None:
        args.product_name = args.project_name
    _apply_adoption_mode_defaults(args, parser)
    return args


def main(argv: list[str] | None = None) -> None:
    parser = _parser()
    args = _finalize_args(parser.parse_args(argv), parser)
    try:
        result = install(args)
    except Exception as exc:
        print(f"install-governance-pack failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print_summary(args, result, required_standard_gates=REQUIRED_STANDARD_GATES)
