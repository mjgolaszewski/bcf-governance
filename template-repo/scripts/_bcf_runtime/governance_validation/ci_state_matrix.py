"""Executable coverage guard for changed CI state-transition contracts."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Any


class CIStateMatrixError(ValueError):
    """Raised when changed CI semantics lack prospective state coverage."""


MATRIX_PATH = "spec/RELEASE_TRAIN_STATE_DAG.md"
REQUIRED_MARKERS = (
    "### P30/P31 state matrix",
    "### P30 workitem DAG",
    "### P31 workitem DAG",
    "### P30/P31 outward construction tree",
    "### Changed-contract downstream permutation rule",
    "controller pending rotation",
    "scheduled control run",
    "adopter qualification",
)


def _git(repo_root: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _comparison_base(repo_root: Path) -> str | None:
    declared = os.environ.get("BCF_COMPARISON_BASE_SHA", "")
    if declared:
        return declared
    return _git(repo_root, "merge-base", "HEAD", "origin/main")


def _transition_contract(path: str) -> bool:
    name = Path(path).name
    return (
        path == "governance/ci-graph.yml"
        or path.startswith(".github/workflows/")
        or path.startswith("schemas/ci-")
        or path.startswith("spec/RELEASE_TRAIN_STATE_DAG")
        or (
            path.startswith("bcf_governance/tooling/")
            and any(
                token in name
                for token in (
                    "ci_", "controller", "evidence", "evaluation", "preflight", "release"
                )
            )
        )
    )


def validate_ci_state_matrix(repo_root: Path) -> dict[str, Any]:
    """Require state/DAG coverage in every candidate changing CI semantics."""

    path = repo_root / MATRIX_PATH
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CIStateMatrixError(f"CI state matrix is unavailable: {exc}") from exc
    missing = [marker for marker in REQUIRED_MARKERS if marker not in text]
    if missing:
        raise CIStateMatrixError("CI state matrix lacks required coverage: " + ", ".join(missing))
    base = _comparison_base(repo_root)
    if base is None:
        return {"status": "covered", "comparison_base": None, "changed_contracts": []}
    changed_text = _git(repo_root, "diff", "--name-only", base, "--")
    if changed_text is None:
        raise CIStateMatrixError("cannot derive changed CI contracts from comparison base")
    changed = sorted(line for line in changed_text.splitlines() if line)
    contracts = [relative for relative in changed if _transition_contract(relative)]
    if contracts and MATRIX_PATH not in changed:
        raise CIStateMatrixError(
            "changed CI contracts require a same-candidate state matrix update: "
            + ", ".join(contracts)
        )
    return {"status": "covered", "comparison_base": base, "changed_contracts": contracts}
