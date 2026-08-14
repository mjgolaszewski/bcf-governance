"""Regenerate the explicit content-addressed template pack manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATED_PATHS = {
    ".github/workflows/governance.yml",
    "Makefile.fragment",
    "governance-profile.yml",
    "governance/evidence-policy.yml",
    "governance/gate-contracts.yml",
}


def build(template_root: Path) -> dict[str, object]:
    files = {
        path.relative_to(template_root).as_posix(): {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "operation": (
                "merge"
                if path.relative_to(template_root).as_posix() == ".gitignore"
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


def main() -> None:
    version_source = REPO_ROOT / "bcf_governance/_version.py"
    for relative in ("template-repo", "bcf_governance/pack/template-repo"):
        root = REPO_ROOT / relative
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
