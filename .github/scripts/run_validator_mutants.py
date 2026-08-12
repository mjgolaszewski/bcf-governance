from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = REPO_ROOT / "scripts" / "validate_governance_yaml.py"
VALIDATION_PACKAGE_PATH = REPO_ROOT / "scripts" / "governance_validation"
TRUTH_PATH = REPO_ROOT / "scripts" / "governance_truth.py"
TRUTH_SUPPORT_PATH = REPO_ROOT / "scripts" / "governance_truth_support.py"


@dataclass(frozen=True)
class Mutant:
    mutant_id: str
    description: str
    search: str
    replace: str
    profiles: tuple[str, ...]
    target_path: str = "scripts/validate_governance_yaml.py"


MUTANTS = (
    Mutant(
        mutant_id="schema-classifier",
        description="schema failures must stay classified as schema failures",
        search='    if "failed structural schema" in message:\n',
        replace='    if "failed structural schema NEVER" in message:\n',
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/common.py",
    ),
    Mutant(
        mutant_id="placeholder-classifier",
        description="placeholder failures must stay classified separately",
        search='    if "unresolved template placeholders remain" in message:\n',
        replace='    if "unresolved template placeholders remain NEVER" in message:\n',
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/common.py",
    ),
    Mutant(
        mutant_id="allow-placeholders-report",
        description="allow-placeholders success output must stay marked as skipped",
        search='            "placeholders": "skipped" if allow_placeholders else "pass",\n',
        replace='            "placeholders": "pass",\n',
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/common.py",
    ),
    Mutant(
        mutant_id="active-phase-report",
        description="success and failure output must continue reporting the active phase",
        search="    return phase_id if isinstance(phase_id, str) and phase_id else None\n",
        replace="    return None\n",
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/common.py",
    ),
    Mutant(
        mutant_id="semantic-failure-report",
        description="semantic failures must not be reported as passing",
        search='    checks["semantic"] = "fail"\n',
        replace='    checks["semantic"] = "pass"\n',
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/common.py",
    ),
    Mutant(
        mutant_id="failure-exit-code",
        description="CLI failures must preserve a non-zero exit code",
        search="        raise SystemExit(1)\n",
        replace="        raise SystemExit(0)\n",
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/runner.py",
    ),
    Mutant(
        mutant_id="document-path-equality",
        description="document.path must stay exact and repo-relative",
        search="    if document_path != expected_path:\n",
        replace="    if False and document_path != expected_path:\n",
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/phase_artifacts.py",
    ),
    Mutant(
        mutant_id="release-gate-placeholder-marker",
        description="placeholder release gate commands must remain rejected",
        search="        if marker in lowered_makefile:\n",
        replace="        if False and marker in lowered_makefile:\n",
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/release_gates.py",
    ),
    Mutant(
        mutant_id="phase-catalog-set-match",
        description="product spec and build plan phase catalogs must stay aligned",
        search="    if set(product_phase_map) != set(build_phase_map):\n",
        replace="    if False and set(product_phase_map) != set(build_phase_map):\n",
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/phase_catalog.py",
    ),
    Mutant(
        mutant_id="planned-log-in-completed-release",
        description="completed release trains must not reference planned phase logs",
        search='            if status == "planned":\n',
        replace='            if False and status == "planned":\n',
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/phase_catalog.py",
    ),
    Mutant(
        mutant_id="memory-active-artifact-sync",
        description="MEMORY active artifacts must stay aligned with the active phase ledger",
        search="        if active_artifacts.get(key) != expected:\n",
        replace="        if False and active_artifacts.get(key) != expected:\n",
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/phase_catalog.py",
    ),
    Mutant(
        mutant_id="workitems-cover-deliverables",
        description="phase workitems must keep covering declared phase deliverables",
        search="    if missing_deliverables:\n",
        replace="    if False and missing_deliverables:\n",
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/phase_artifacts.py",
    ),
    Mutant(
        mutant_id="phase-log-workitem-status-sync",
        description="phase log workitem statuses must stay aligned with the workitem ledger",
        search="    if mismatched_statuses:\n",
        replace="    if False and mismatched_statuses:\n",
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/phase_artifacts.py",
    ),
    Mutant(
        mutant_id="success-status",
        description="successful compact output must report pass status",
        search='        "status": "pass",\n',
        replace='        "status": "fail",\n',
        profiles=("full",),
        target_path="scripts/governance_validation/common.py",
    ),
    Mutant(
        mutant_id="failure-status",
        description="failed compact output must report fail status",
        search='        "status": "fail",\n',
        replace='        "status": "pass",\n',
        profiles=("full",),
        target_path="scripts/governance_validation/common.py",
    ),
)

TRUTH_MUTANTS = (
    Mutant(
        mutant_id="truth-all-skipped-suite",
        description="required suites must execute tests and reject all-skipped evidence",
        search='    if counts["executed"] < int(thresholds.get("min_executed", 1)):\n',
        replace='    if False and counts["executed"] < int(thresholds.get("min_executed", 1)):\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_truth.py",
    ),
    Mutant(
        mutant_id="truth-negative-control",
        description="a semantically inert gate must never verify",
        search='        if not isinstance(exit_code, int) or exit_code == 0:\n',
        replace='        if False and (not isinstance(exit_code, int) or exit_code == 0):\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_truth.py",
    ),
    Mutant(
        mutant_id="truth-current-head",
        description="old-commit evidence must stale after HEAD changes",
        search='        if subject.get("commit_sha") != current["commit_sha"]:\n',
        replace='        if False and subject.get("commit_sha") != current["commit_sha"]:\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_truth.py",
    ),
    Mutant(
        mutant_id="truth-current-tree",
        description="internally consistent old-tree hashes must not verify current HEAD",
        search='        if subject.get("tree_sha") != current["tree_sha"]:\n',
        replace='        if False and subject.get("tree_sha") != current["tree_sha"]:\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_truth.py",
    ),
    Mutant(
        mutant_id="truth-node-binding",
        description="finding proof must bind to an executed test node",
        search='                        (proof_kind == "test_node" and node_id in nodes and control_id in control_ids)\n',
        replace='                        (proof_kind == "test_node" and control_id in control_ids)\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_truth_support.py",
    ),
    Mutant(
        mutant_id="truth-finding-accounting",
        description="review summaries cannot erase discovered corrections",
        search='                if summary.get("findings_total") != findings_by_review[review_id]:\n',
        replace='                if False and summary.get("findings_total") != findings_by_review[review_id]:\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_truth_support.py",
    ),
    Mutant(
        mutant_id="truth-production-environment",
        description="development preflight cannot satisfy production assertions",
        search='        if not isinstance(raw, dict) or raw.get("satisfied") is not True\n',
        replace='        if False and (not isinstance(raw, dict) or raw.get("satisfied") is not True)\n',
        profiles=("semantic-full",),
        target_path="scripts/governance_truth.py",
    ),
    Mutant(
        mutant_id="truth-authored-verified",
        description="verified remains computed and absent from authored state taxonomy",
        search='AUTHORED_STATES = {"planned", "completed"}\n',
        replace='AUTHORED_STATES = {"planned", "completed", "verified"}\n',
        profiles=("semantic-full",),
        target_path="scripts/governance_truth.py",
    ),
)


def _selected_mutants(profile: str) -> tuple[Mutant, ...]:
    return tuple(mutant for mutant in (*MUTANTS, *TRUTH_MUTANTS) if profile in mutant.profiles)


def _copy_validator_sources(temp_dir: Path) -> Path:
    temp_scripts = temp_dir / "scripts"
    temp_scripts.mkdir()
    shutil.copy2(VALIDATOR_PATH, temp_scripts / VALIDATOR_PATH.name)
    shutil.copytree(
        VALIDATION_PACKAGE_PATH,
        temp_scripts / VALIDATION_PACKAGE_PATH.name,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    return temp_scripts / VALIDATOR_PATH.name


def _copy_truth_sources(temp_dir: Path) -> Path:
    temp_scripts = temp_dir / "scripts"
    temp_scripts.mkdir()
    shutil.copy2(TRUTH_PATH, temp_scripts / TRUTH_PATH.name)
    shutil.copy2(REPO_ROOT / "scripts/governance_evidence.py", temp_scripts / "governance_evidence.py")
    shutil.copy2(TRUTH_SUPPORT_PATH, temp_scripts / TRUTH_SUPPORT_PATH.name)
    (temp_scripts / "__init__.py").write_text("\n", encoding="utf-8")
    return temp_scripts / TRUTH_PATH.name


def _target_path(mutant: Mutant, temp_dir: Path) -> Path:
    relative_path = Path(mutant.target_path)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise RuntimeError(
            f"mutant {mutant.mutant_id} has unsafe target path {mutant.target_path!r}"
        )
    target_path = temp_dir / relative_path
    if not target_path.exists():
        raise RuntimeError(
            f"mutant {mutant.mutant_id} target does not exist: {mutant.target_path}"
        )
    return target_path


def _mutate_source(mutant: Mutant, temp_dir: Path) -> Path:
    validator_entrypoint = (
        _copy_truth_sources(temp_dir)
        if mutant.target_path in {
            "scripts/governance_truth.py",
            "scripts/governance_truth_support.py",
        }
        else _copy_validator_sources(temp_dir)
    )
    target_path = _target_path(mutant, temp_dir)
    source = target_path.read_text(encoding="utf-8")
    if mutant.search not in source:
        raise RuntimeError(
            f"mutant {mutant.mutant_id} could not find its target in {mutant.target_path}"
        )
    mutated = source.replace(mutant.search, mutant.replace, 1)
    if mutated == source:
        raise RuntimeError(f"mutant {mutant.mutant_id} did not change the validator source")
    target_path.write_text(mutated, encoding="utf-8")
    return validator_entrypoint


def _run_tests(mutant: Mutant, mutated_path: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if mutant.target_path in {
        "scripts/governance_truth.py",
        "scripts/governance_truth_support.py",
    }:
        env["BCF_TRUTH_MODULE_PATH"] = str(mutated_path)
        test_path = "tests/test_governance_truth.py"
    else:
        env["BCF_VALIDATOR_MODULE_PATH"] = str(mutated_path)
        test_path = "tests/test_validate_governance_yaml.py"
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", test_path],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deterministic validator mutation checks.")
    parser.add_argument(
        "--profile",
        choices=("high-value", "full", "semantic-high-value", "semantic-full"),
        default="high-value",
        help="Mutation profile to execute.",
    )
    parser.add_argument(
        "--mutant",
        choices=tuple(mutant.mutant_id for mutant in (*MUTANTS, *TRUTH_MUTANTS)),
        help="Run one mutant from the selected profile (useful for deterministic sharding).",
    )
    args = parser.parse_args()

    survivors: list[str] = []
    selected = _selected_mutants(args.profile)
    if args.mutant:
        selected = tuple(mutant for mutant in selected if mutant.mutant_id == args.mutant)
        if not selected:
            parser.error(f"mutant {args.mutant!r} is not part of profile {args.profile!r}")
    for mutant in selected:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            mutated_path = _mutate_source(mutant, Path(temp_dir_name))
            result = _run_tests(mutant, mutated_path)
        print(f"[{mutant.mutant_id}] {mutant.description}")
        if result.returncode == 0:
            survivors.append(mutant.mutant_id)
            print("  survived")
            continue
        print("  killed")

    if survivors:
        print("surviving mutants:", ", ".join(sorted(survivors)), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
