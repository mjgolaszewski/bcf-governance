"""Command line entry point for BCF governance tooling."""

from __future__ import annotations

import argparse
from collections.abc import Callable as _Callable
import sys

from bcf_governance import __version__
from bcf_governance.tooling import (
    check_governance_exposure as check_governance_exposure,
)
from bcf_governance.tooling import (
    ci_commands as ci_commands,
)
from bcf_governance.tooling import (
    ci_github_commands as ci_github_commands,
)
from bcf_governance.tooling import (
    cleanup_ci_resources as cleanup_ci_resources,
)
from bcf_governance.tooling import (
    cleanup_governance_pack as cleanup_governance_pack,
)
from bcf_governance.tooling import (
    doctor_governance_pack as doctor_governance_pack,
)
from bcf_governance.tooling import (
    evidence_storage_commands as evidence_storage_commands,
)
from bcf_governance.tooling import (
    governance_evidence as governance_evidence,
)
from bcf_governance.tooling import (
    governance_truth_cli as governance_truth_cli,
)
from bcf_governance.tooling import (
    interpreter_environment as interpreter_environment,
)
from bcf_governance.tooling import (
    migrate_contracts as migrate_contracts,
)
from bcf_governance.tooling import (
    migrate_governance_evidence as migrate_governance_evidence,
)
from bcf_governance.tooling import (
    preflight as preflight,
)
from bcf_governance.tooling import (
    profile_governance as profile_governance,
)
from bcf_governance.tooling import (
    publish_audit as publish_audit,
)
from bcf_governance.tooling import (
    scaffold_governance_artifacts as scaffold_governance_artifacts,
)
from bcf_governance.tooling import (
    semantic_ownership_scan as semantic_ownership_scan,
)
from bcf_governance.tooling import (
    test_manifests as test_manifests,
)
from bcf_governance.tooling import (
    validate_governance_yaml as validate_governance_yaml,
)
from bcf_governance.tooling.check_governance_exposure import (
    main as _command_check_governance_exposure,
)
from bcf_governance.tooling.ci_commands import main as _command_ci_commands
from bcf_governance.tooling.ci_github_commands import main as _command_ci_github_commands
from bcf_governance.tooling.cleanup_ci_resources import main as _command_cleanup_ci_resources
from bcf_governance.tooling.cleanup_governance_pack import main as _command_cleanup_governance_pack
from bcf_governance.tooling.doctor_governance_pack import main as _command_doctor_governance_pack
from bcf_governance.tooling.evidence_storage_commands import (
    main as _command_evidence_storage_commands,
)
from bcf_governance.tooling.governance_evidence import main as _command_governance_evidence
from bcf_governance.tooling.governance_install import cli as _governance_install_cli
from bcf_governance.tooling.governance_install.cli import main as _command_governance_install_cli
from bcf_governance.tooling.governance_truth_cli import main as _command_governance_truth_cli
from bcf_governance.tooling.interpreter_environment import main as _command_interpreter_environment
from bcf_governance.tooling.migrate_contracts import main as _command_migrate_contracts
from bcf_governance.tooling.migrate_governance_evidence import (
    main as _command_migrate_governance_evidence,
)
from bcf_governance.tooling.preflight import main as _command_preflight
from bcf_governance.tooling.profile_governance import main as _command_profile_governance
from bcf_governance.tooling.publish_audit import main as _command_publish_audit
from bcf_governance.tooling.scaffold_governance_artifacts import (
    main as _command_scaffold_governance_artifacts,
)
from bcf_governance.tooling.scaffold_governance_artifacts import (
    reconcile_main as _command_reconcile,
)
from bcf_governance.tooling.semantic_ownership_scan import main as _command_semantic_ownership_scan
from bcf_governance.tooling.test_manifests import main as _command_test_manifests
from bcf_governance.tooling.validate_governance_yaml import (
    main as _command_validate_governance_yaml,
)

governance_install_cli = _governance_install_cli

COMMANDS: dict[str, _Callable[[list[str]], object]] = {
    "ci": _command_ci_commands,
    "ci-github": _command_ci_github_commands,
    "cleanup": _command_cleanup_governance_pack,
    "ci-cleanup": _command_cleanup_ci_resources,
    "exposure-scan": _command_check_governance_exposure,
    "install": _command_governance_install_cli,
    "migrate-contract": _command_migrate_contracts,
    "environment": _command_interpreter_environment,
    "evidence": _command_governance_evidence,
    "evidence-store": _command_evidence_storage_commands,
    "truth": _command_governance_truth_cli,
    "migrate-evidence": _command_migrate_governance_evidence,
    "profile": _command_profile_governance,
    "preflight": _command_preflight,
    "publish-audit": _command_publish_audit,
    "reconcile": _command_reconcile,
    "validate": _command_validate_governance_yaml,
    "scaffold": _command_scaffold_governance_artifacts,
    "semantic-ownership": _command_semantic_ownership_scan,
    "test-manifest": _command_test_manifests,
    "doctor": _command_doctor_governance_pack,
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
