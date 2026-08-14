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
VALIDATOR_PATH = REPO_ROOT / "bcf_governance/tooling/validate_governance_yaml.py"
VALIDATION_PACKAGE_PATH = REPO_ROOT / "bcf_governance/tooling/governance_validation"
TRUTH_PATH = REPO_ROOT / "bcf_governance/tooling/governance_truth.py"
TRUTH_SUPPORT_PATH = REPO_ROOT / "bcf_governance/tooling/governance_truth_support.py"
TRUTH_RECEIPTS_PATH = REPO_ROOT / "bcf_governance/tooling/truth_receipts.py"
PYTEST = shutil.which("pytest") or f"{sys.executable} -m pytest"
TRUTH_TARGETS = {
    "scripts/governance_truth.py",
    "scripts/governance_truth_support.py",
    "scripts/truth_receipts.py",
}
EVIDENCE_TARGETS = {"scripts/governance_evidence.py"}


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
        description="no-op executable gate contracts must remain rejected",
        search='        if executable in {"true", "false", "echo", "printf", ":"}:\n',
        replace='        if False and executable in {"true", "false", "echo", "printf", ":"}:\n',
        profiles=("high-value", "full"),
        target_path="scripts/governance_validation/evidence_contracts.py",
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
        mutant_id="evidence-untracked-preflight",
        description="non-ignored untracked helpers must block evidence capture",
        search="    if status:\n        raise EvidenceError(\n",
        replace="    if False and status:\n        raise EvidenceError(\n",
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_evidence.py",
    ),
    Mutant(
        mutant_id="evidence-isolated-positive",
        description="positive gates must execute in a pristine detached tree",
        search="            result = _run(command, cwd=_execution_cwd(worktree, contract), env=env)\n",
        replace="            result = _run(command, cwd=_execution_cwd(repo_root, contract), env=env)\n",
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_evidence.py",
    ),
    Mutant(
        mutant_id="evidence-typed-oracle",
        description="an arbitrary nonzero exit must not satisfy a diagnostic control",
        search="            and isinstance(pattern, str)\n            and re.search(pattern, value) is not None\n",
        replace="            and isinstance(pattern, str)\n",
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_evidence.py",
    ),
    Mutant(
        mutant_id="evidence-tracked-mutation",
        description="a positive gate that mutates tracked files cannot produce evidence",
        search='            observations["execution_tree_clean"] = not bool(post_status)\n',
        replace='            observations["execution_tree_clean"] = True\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/governance_evidence.py",
    ),
    Mutant(
        mutant_id="truth-all-skipped-suite",
        description="required suites must execute tests and reject all-skipped evidence",
        search='    if counts["executed"] < int(thresholds.get("min_executed", 1)):\n',
        replace='    if False and counts["executed"] < int(thresholds.get("min_executed", 1)):\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/truth_receipts.py",
    ),
    Mutant(
        mutant_id="truth-negative-control",
        description="a semantically inert gate must never verify",
        search='        if not satisfied:\n',
        replace='        if False and not satisfied:\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/truth_receipts.py",
    ),
    Mutant(
        mutant_id="truth-current-head",
        description="old-commit evidence must stale after HEAD changes",
        search='        if subject.get("commit_sha") != current["commit_sha"]:\n',
        replace='        if False and subject.get("commit_sha") != current["commit_sha"]:\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/truth_receipts.py",
    ),
    Mutant(
        mutant_id="truth-current-tree",
        description="internally consistent old-tree hashes must not verify current HEAD",
        search='        if subject.get("tree_sha") != current["tree_sha"]:\n',
        replace='        if False and subject.get("tree_sha") != current["tree_sha"]:\n',
        profiles=("semantic-high-value", "semantic-full"),
        target_path="scripts/truth_receipts.py",
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
        target_path="scripts/truth_receipts.py",
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

KILLER_NODES = {
    "evidence-untracked-preflight": ("tests/test_governance_evidence.py::test_capture_rejects_nonignored_untracked_helper_before_execution",),
    "evidence-isolated-positive": ("tests/test_governance_evidence.py::test_ignored_helper_cannot_influence_isolated_positive_execution",),
    "evidence-typed-oracle": ("tests/test_governance_evidence.py::test_arbitrary_crash_does_not_satisfy_typed_diagnostic_oracle",),
    "evidence-tracked-mutation": ("tests/test_governance_evidence.py::test_positive_gate_that_mutates_tracked_file_is_not_evidence",),
    "schema-classifier": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_emits_compact_json_output_for_schema_failure",),
    "placeholder-classifier": ("tests/test_validate_governance_yaml.py::test_validate_template_repo_emits_compact_json_output_for_placeholder_failure",),
    "allow-placeholders-report": ("tests/test_validate_governance_yaml.py::test_validate_template_repo_emits_compact_json_output_with_allowed_placeholders",),
    "active-phase-report": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_emits_compact_json_output",),
    "semantic-failure-report": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_emits_compact_json_output_for_semantic_failure",),
    "failure-exit-code": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_emits_compact_json_output_for_schema_failure",),
    "document-path-equality": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_rejects_document_path_mismatch",),
    "release-gate-placeholder-marker": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_rejects_placeholder_release_gates",),
    "phase-catalog-set-match": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_rejects_product_build_phase_mismatch",),
    "planned-log-in-completed-release": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_rejects_completed_release_train_with_planned_log",),
    "memory-active-artifact-sync": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_rejects_stale_memory_active_artifacts",),
    "workitems-cover-deliverables": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_rejects_workitems_missing_plan_deliverable",),
    "phase-log-workitem-status-sync": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_rejects_log_workitem_status_drift",),
    "success-status": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_emits_compact_json_output",),
    "failure-status": ("tests/test_validate_governance_yaml.py::test_validate_repo_root_emits_compact_json_output_for_schema_failure",),
    "truth-all-skipped-suite": ("tests/test_governance_truth.py::test_semantic_receipt_mutants_die",),
    "truth-negative-control": ("tests/test_governance_truth.py::test_semantic_receipt_mutants_die",),
    "truth-current-head": ("tests/test_governance_truth.py::test_commit_identity_mismatch_alone_invalidates_receipt",),
    "truth-current-tree": ("tests/test_governance_truth.py::test_tree_identity_mismatch_alone_invalidates_receipt",),
    "truth-node-binding": ("tests/test_governance_truth.py::test_finding_proof_rejects_unexecuted_node_id",),
    "truth-finding-accounting": ("tests/test_governance_truth.py::test_correction_with_zero_finding_summary_fails_accounting",),
    "truth-production-environment": ("tests/test_governance_truth.py::test_semantic_receipt_mutants_die",),
    "truth-authored-verified": ("tests/test_governance_truth.py::test_authored_verified_cannot_be_promoted_by_consistent_yaml",),
}


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
    entrypoint = temp_scripts / VALIDATOR_PATH.name
    entrypoint.write_text(
        entrypoint.read_text(encoding="utf-8").replace("from .governance_validation", "from governance_validation"),
        encoding="utf-8",
    )
    return entrypoint


def _copy_truth_sources(temp_dir: Path) -> Path:
    temp_scripts = temp_dir / "scripts"
    temp_scripts.mkdir()
    shutil.copy2(TRUTH_PATH, temp_scripts / TRUTH_PATH.name)
    shutil.copy2(REPO_ROOT / "bcf_governance/tooling/governance_evidence.py", temp_scripts / "governance_evidence.py")
    shutil.copy2(TRUTH_SUPPORT_PATH, temp_scripts / TRUTH_SUPPORT_PATH.name)
    shutil.copy2(TRUTH_RECEIPTS_PATH, temp_scripts / TRUTH_RECEIPTS_PATH.name)
    for name in ("evidence_attestation.py", "evidence_test_adapters.py"):
        shutil.copy2(REPO_ROOT / "bcf_governance/tooling" / name, temp_scripts / name)
    (temp_scripts / "__init__.py").write_text("\n", encoding="utf-8")
    for path in (
        temp_scripts / TRUTH_PATH.name,
        temp_scripts / TRUTH_SUPPORT_PATH.name,
        temp_scripts / TRUTH_RECEIPTS_PATH.name,
        temp_scripts / "governance_evidence.py",
    ):
        path.write_text(
            path.read_text(encoding="utf-8")
            .replace("from .governance_evidence", "from governance_evidence")
            .replace("from .governance_truth_support", "from governance_truth_support"),
            encoding="utf-8",
        )
    evidence = temp_scripts / "governance_evidence.py"
    evidence.write_text(
        evidence.read_text(encoding="utf-8")
        .replace("from .evidence_attestation", "from evidence_attestation")
        .replace("from .evidence_test_adapters", "from evidence_test_adapters"),
        encoding="utf-8",
    )
    receipts = temp_scripts / TRUTH_RECEIPTS_PATH.name
    receipts.write_text(
        receipts.read_text(encoding="utf-8")
        .replace("from .evidence_test_adapters", "from evidence_test_adapters")
        .replace("from .governance_truth_support", "from governance_truth_support"),
        encoding="utf-8",
    )
    truth = temp_scripts / TRUTH_PATH.name
    truth.write_text(
        truth.read_text(encoding="utf-8").replace(
            "from .truth_receipts", "from truth_receipts"
        ),
        encoding="utf-8",
    )
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
    if mutant.target_path in TRUTH_TARGETS | EVIDENCE_TARGETS:
        validator_entrypoint = _copy_truth_sources(temp_dir)
        if mutant.target_path in EVIDENCE_TARGETS:
            validator_entrypoint = temp_dir / "scripts/governance_evidence.py"
    else:
        validator_entrypoint = _copy_validator_sources(temp_dir)
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
    if mutant.target_path in TRUTH_TARGETS:
        env["BCF_TRUTH_MODULE_PATH"] = str(mutated_path)
        test_paths = KILLER_NODES[mutant.mutant_id]
    elif mutant.target_path in EVIDENCE_TARGETS:
        env["BCF_EVIDENCE_MODULE_PATH"] = str(mutated_path)
        test_paths = KILLER_NODES[mutant.mutant_id]
    else:
        env["BCF_VALIDATOR_MODULE_PATH"] = str(mutated_path)
        test_paths = KILLER_NODES[mutant.mutant_id]
    return subprocess.run(
        [*PYTEST.split(), "-q", *test_paths],
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
    baseline_nodes = sorted({node for mutant in selected for node in KILLER_NODES[mutant.mutant_id]})
    baseline = subprocess.run(
        [*PYTEST.split(), "-q", *baseline_nodes],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if baseline.returncode != 0:
        print("mutation baseline failed; no mutant results are valid", file=sys.stderr)
        print(baseline.stdout, file=sys.stderr)
        print(baseline.stderr, file=sys.stderr)
        raise SystemExit(2)

    infrastructure_failures: list[str] = []
    for mutant in selected:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            mutated_path = _mutate_source(mutant, Path(temp_dir_name))
            result = _run_tests(mutant, mutated_path)
        print(f"[{mutant.mutant_id}] {mutant.description}")
        if result.returncode == 0:
            survivors.append(mutant.mutant_id)
            print("  survived")
            continue
        if result.returncode != 1:
            infrastructure_failures.append(mutant.mutant_id)
            print(f"  invalid result (pytest exit {result.returncode})")
            continue
        print("  killed by declared test node")

    if survivors:
        print("surviving mutants:", ", ".join(sorted(survivors)), file=sys.stderr)
        raise SystemExit(1)
    if infrastructure_failures:
        print(
            "mutants did not produce expected test failures: "
            + ", ".join(sorted(infrastructure_failures)),
            file=sys.stderr,
        )
        raise SystemExit(2)


if __name__ == "__main__":
    main()
