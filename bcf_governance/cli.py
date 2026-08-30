"""Command line entry point for BCF governance tooling."""

from __future__ import annotations

import argparse
import sys

from bcf_governance import __version__
from bcf_governance.tooling import (
    check_governance_exposure,
    ci_commands,
    cleanup_ci_resources,
    cleanup_governance_pack,
    doctor_governance_pack,
    governance_evidence,
    governance_truth,
    install_governance_pack,
    migrate_governance_evidence,
    preflight,
    profile_governance,
    publish_audit,
    scaffold_governance_artifacts,
    semantic_ownership_scan,
    test_manifests,
    validate_governance_yaml,
)

COMMANDS = {
    "ci": ci_commands.main,
    "cleanup": cleanup_governance_pack.main,
    "ci-cleanup": cleanup_ci_resources.main,
    "exposure-scan": check_governance_exposure.main,
    "install": install_governance_pack.main,
    "evidence": governance_evidence.main,
    "truth": governance_truth.main,
    "migrate-evidence": migrate_governance_evidence.main,
    "profile": profile_governance.main,
    "preflight": preflight.main,
    "publish-audit": publish_audit.main,
    "validate": validate_governance_yaml.main,
    "scaffold": scaffold_governance_artifacts.main,
    "semantic-ownership": semantic_ownership_scan.main,
    "test-manifest": test_manifests.main,
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
