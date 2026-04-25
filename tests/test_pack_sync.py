from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _is_pack_artifact(path: Path) -> bool:
    return "__pycache__" not in path.parts and path.suffix != ".pyc"


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


def test_packaged_template_resource_stays_in_sync() -> None:
    template_files = sorted(
        path.relative_to(REPO_ROOT / "template-repo")
        for path in (REPO_ROOT / "template-repo").rglob("*")
        if path.is_file() and _is_pack_artifact(path)
    )
    packaged_files = sorted(
        path.relative_to(REPO_ROOT / "bcf_governance/pack/template-repo")
        for path in (REPO_ROOT / "bcf_governance/pack/template-repo").rglob("*")
        if path.is_file() and _is_pack_artifact(path)
    )
    assert packaged_files == template_files

    mismatches = [
        relative_path.as_posix()
        for relative_path in template_files
        if (REPO_ROOT / "template-repo" / relative_path).read_bytes()
        != (REPO_ROOT / "bcf_governance/pack/template-repo" / relative_path).read_bytes()
    ]
    assert not mismatches, "packaged template resources drifted:\n" + "\n".join(mismatches)
