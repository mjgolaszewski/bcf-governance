from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = REPO_ROOT / "scripts" / "validate_governance_yaml.py"


@dataclass(frozen=True)
class Mutant:
    mutant_id: str
    description: str
    search: str
    replace: str
    profiles: tuple[str, ...]


MUTANTS = (
    Mutant(
        mutant_id="schema-classifier",
        description="schema failures must stay classified as schema failures",
        search='    if "failed structural schema" in message:\n',
        replace='    if "failed structural schema NEVER" in message:\n',
        profiles=("high-value", "full"),
    ),
    Mutant(
        mutant_id="placeholder-classifier",
        description="placeholder failures must stay classified separately",
        search='    if "unresolved template placeholders remain" in message:\n',
        replace='    if "unresolved template placeholders remain NEVER" in message:\n',
        profiles=("high-value", "full"),
    ),
    Mutant(
        mutant_id="allow-placeholders-report",
        description="allow-placeholders success output must stay marked as skipped",
        search='            "placeholders": "skipped" if allow_placeholders else "pass",\n',
        replace='            "placeholders": "pass",\n',
        profiles=("high-value", "full"),
    ),
    Mutant(
        mutant_id="active-phase-report",
        description="success and failure output must continue reporting the active phase",
        search="    return phase_id if isinstance(phase_id, str) and phase_id else None\n",
        replace="    return None\n",
        profiles=("high-value", "full"),
    ),
    Mutant(
        mutant_id="semantic-failure-report",
        description="semantic failures must not be reported as passing",
        search='    checks["semantic"] = "fail"\n',
        replace='    checks["semantic"] = "pass"\n',
        profiles=("high-value", "full"),
    ),
    Mutant(
        mutant_id="failure-exit-code",
        description="CLI failures must preserve a non-zero exit code",
        search="        raise SystemExit(1)\n",
        replace="        raise SystemExit(0)\n",
        profiles=("high-value", "full"),
    ),
    Mutant(
        mutant_id="success-status",
        description="successful compact output must report pass status",
        search='        "status": "pass",\n',
        replace='        "status": "fail",\n',
        profiles=("full",),
    ),
    Mutant(
        mutant_id="failure-status",
        description="failed compact output must report fail status",
        search='        "status": "fail",\n',
        replace='        "status": "pass",\n',
        profiles=("full",),
    ),
)


def _selected_mutants(profile: str) -> tuple[Mutant, ...]:
    return tuple(mutant for mutant in MUTANTS if profile in mutant.profiles)


def _mutate_source(mutant: Mutant, temp_dir: Path) -> Path:
    source = VALIDATOR_PATH.read_text(encoding="utf-8")
    if mutant.search not in source:
        raise RuntimeError(
            f"mutant {mutant.mutant_id} could not find its target in {VALIDATOR_PATH}"
        )
    mutated = source.replace(mutant.search, mutant.replace, 1)
    if mutated == source:
        raise RuntimeError(f"mutant {mutant.mutant_id} did not change the validator source")
    mutated_path = temp_dir / VALIDATOR_PATH.name
    mutated_path.write_text(mutated, encoding="utf-8")
    return mutated_path


def _run_tests(mutated_path: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["BCF_VALIDATOR_MODULE_PATH"] = str(mutated_path)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_validate_governance_yaml.py"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deterministic validator mutation checks.")
    parser.add_argument(
        "--profile",
        choices=("high-value", "full"),
        default="high-value",
        help="Mutation profile to execute.",
    )
    args = parser.parse_args()

    survivors: list[str] = []
    for mutant in _selected_mutants(args.profile):
        with tempfile.TemporaryDirectory() as temp_dir_name:
            mutated_path = _mutate_source(mutant, Path(temp_dir_name))
            result = _run_tests(mutated_path)
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
