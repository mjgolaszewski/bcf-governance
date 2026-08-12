"""Command line entry point for BCF governance tooling."""

from __future__ import annotations

import argparse
import sys

from bcf_governance import __version__
from scripts import cleanup_governance_pack
from scripts import check_governance_exposure
from scripts import doctor_governance_pack
from scripts import install_governance_pack
from scripts import governance_evidence
from scripts import governance_truth
from scripts import migrate_governance_evidence
from scripts import scaffold_governance_artifacts
from scripts import validate_governance_yaml


COMMANDS = {
    "cleanup": cleanup_governance_pack.main,
    "exposure-scan": check_governance_exposure.main,
    "install": install_governance_pack.main,
    "evidence": governance_evidence.main,
    "truth": governance_truth.main,
    "migrate-evidence": migrate_governance_evidence.main,
    "validate": validate_governance_yaml.main,
    "scaffold": scaffold_governance_artifacts.main,
    "doctor": doctor_governance_pack.main,
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bcf",
        description="BCF governance pack CLI.",
    )
    parser.add_argument("--version", action="version", version=f"bcf {__version__}")
    parser.add_argument(
        "command",
        choices=sorted(COMMANDS),
        help="Command to run.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    if not args:
        parser.print_help()
        raise SystemExit(2)
    if args[0] in COMMANDS:
        COMMANDS[args[0]](args[1:])
        return
    namespace, remainder = parser.parse_known_args(args)
    COMMANDS[namespace.command](remainder)


if __name__ == "__main__":
    main()
