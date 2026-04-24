from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_text(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_duplicated_governance_scripts_and_requirements_stay_in_sync() -> None:
    pairs = [
        (
            "scripts/validate_governance_yaml.py",
            "template-repo/scripts/validate_governance_yaml.py",
        ),
        (
            "scripts/scaffold_governance_artifacts.py",
            "template-repo/scripts/scaffold_governance_artifacts.py",
        ),
        (
            "requirements-governance.txt",
            "template-repo/requirements-governance.txt",
        ),
    ]

    mismatches = [
        f"{left} != {right}"
        for left, right in pairs
        if _read_text(left) != _read_text(right)
    ]
    assert not mismatches, "duplicated governance files drifted:\n" + "\n".join(mismatches)
