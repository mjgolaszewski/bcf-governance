"""Regenerate the explicit content-addressed template pack manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATED_PATHS = {
    ".github/workflows/governance.yml",
    "Makefile.fragment",
    "governance-profile.yml",
    "governance/evidence-policy.yml",
    "governance/gate-contracts.yml",
}
PRESERVED_REQUIRED_ARTIFACTS = {"README.md", "LICENSE", "CHANGELOG.md"}


def _sync_tree(source: Path, destination: Path, *, suffixes: set[str]) -> None:
    source_files = {
        path.relative_to(source)
        for path in source.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix in suffixes
    }
    destination_files = {
        path.relative_to(destination)
        for path in destination.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix in suffixes
        and path.name != "_version.py"
    }
    for relative in sorted(destination_files - source_files):
        (destination / relative).unlink()
    for relative in sorted(source_files):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)


def _sync_packaged_template(source: Path, destination: Path) -> None:
    excluded = {Path(".bcf-pack-manifest.json")}
    source_files = {
        path.relative_to(source)
        for path in source.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(source) not in excluded
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    destination_files = {
        path.relative_to(destination)
        for path in destination.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(destination) not in excluded
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    for relative in sorted(destination_files - source_files):
        (destination / relative).unlink()
    for relative in sorted(source_files):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)


def build(template_root: Path) -> dict[str, object]:
    files = {
        path.relative_to(template_root).as_posix(): {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "operation": (
                "merge"
                if path.relative_to(template_root).as_posix() == ".gitignore"
                else "preserve"
                if path.relative_to(template_root).as_posix() in PRESERVED_REQUIRED_ARTIFACTS
                else "generate"
                if path.relative_to(template_root).as_posix() in GENERATED_PATHS
                else "copy"
            ),
            **(
                {"profiles": ["regulated"]}
                if path.relative_to(template_root).as_posix()
                in {
                    "governance/MODEL_RISK_AND_PROVENANCE.md",
                    "governance/HOTFIX_LANE.md",
                }
                else {}
            ),
        }
        for path in sorted(template_root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.name != ".bcf-pack-manifest.json"
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    return {
        "schema_version": "1.0",
        "files": files,
        "generated": [
            {"path_template": "plans/phase-{NN}-plan.yml", "operation": "generate"},
            {"path_template": "plans/phase-{NN}-workitems.yml", "operation": "generate"},
            {"path_template": "phases/phase-{NN}-log.yml", "operation": "generate"},
        ],
    }


def _tree_bytes(root: Path, *, suffixes: set[str]) -> dict[Path, bytes]:
    return {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix in suffixes
        and path.name != "_version.py"
    }


def check() -> list[str]:
    """Return every mechanically derivable pack surface that is stale."""

    issues: list[str] = []
    template_root = REPO_ROOT / "template-repo"
    packaged_root = REPO_ROOT / "bcf_governance/pack/template-repo"
    if _tree_bytes(
        REPO_ROOT / "bcf_governance/tooling", suffixes={".py", ".mjs"}
    ) != _tree_bytes(template_root / "scripts/_bcf_runtime", suffixes={".py", ".mjs"}):
        issues.append("template private runtime differs from canonical tooling")
    if _tree_bytes(REPO_ROOT / "schemas", suffixes={".json"}) != _tree_bytes(
        template_root / "schemas", suffixes={".json"}
    ):
        issues.append("template schemas differ from canonical schemas")
    expected_version = (REPO_ROOT / "bcf_governance/_version.py").read_bytes()
    for root in (template_root, packaged_root):
        if (root / "scripts/_bcf_runtime/_version.py").read_bytes() != expected_version:
            issues.append(f"{root.relative_to(REPO_ROOT)} version projection is stale")
        manifest = root / ".bcf-pack-manifest.json"
        expected_manifest = json.dumps(build(root), indent=2, sort_keys=True) + "\n"
        if manifest.read_text(encoding="utf-8") != expected_manifest:
            issues.append(f"{manifest.relative_to(REPO_ROOT)} is stale")
    template_files = {
        path.relative_to(template_root): path.read_bytes()
        for path in template_root.rglob("*")
        if path.is_file()
        and path.name != ".bcf-pack-manifest.json"
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    packaged_files = {
        path.relative_to(packaged_root): path.read_bytes()
        for path in packaged_root.rglob("*")
        if path.is_file()
        and path.name != ".bcf-pack-manifest.json"
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    if template_files != packaged_files:
        issues.append("packaged template differs from canonical template")
    return issues


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        issues = check()
        if issues:
            raise SystemExit("; ".join(issues))
        return
    version_source = REPO_ROOT / "bcf_governance/_version.py"
    template_root = REPO_ROOT / "template-repo"
    _sync_tree(
        REPO_ROOT / "bcf_governance/tooling",
        template_root / "scripts/_bcf_runtime",
        suffixes={".py", ".mjs"},
    )
    _sync_tree(REPO_ROOT / "schemas", template_root / "schemas", suffixes={".json"})
    packaged_root = REPO_ROOT / "bcf_governance/pack/template-repo"
    _sync_packaged_template(template_root, packaged_root)
    for root in (template_root, packaged_root):
        (root / "scripts/_bcf_runtime/_version.py").write_bytes(
            version_source.read_bytes()
        )
        manifest = root / ".bcf-pack-manifest.json"
        manifest.write_text(
            json.dumps(build(root), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
