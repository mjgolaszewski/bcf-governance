"""Existing governance-pack admission query; no evidence or provider authority."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from ..install_governance_pack import _pack_manifest_entries
from ..local_execution_admission import project_python_environment
from ..profile_yaml import render_profile_surface
from .common import _load_yaml
from .context_budgets import _validate_context_budgets
from ..interpreter_environment import derive_interpreter_environment, verify_interpreter_environment_projection


def validate_source_distribution(repo_root: Path, *, python_executable: Path) -> dict[str, Any]:
    """Reject authored source omissions without judging generated pack bytes."""
    repo_root = repo_root.resolve()
    if not (repo_root / "bcf_governance/pack/template-repo").is_dir() or not (repo_root / "pyproject.toml").is_file():
        return {"applicable": False, "authority": False}
    source = repo_root / ".github/scripts/release_source_inventory.py"
    if not source.is_file() or source.is_symlink():
        raise ValueError("framework source distribution declaration owner is missing")
    result = subprocess.run(
        [str(python_executable), str(source), "--repo-root", str(repo_root)],
        cwd=repo_root,
        env=project_python_environment(repo_root, python_executable, os.environ),
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise ValueError("source distribution admission failed: " + (result.stderr.strip() or result.stdout.strip()))
    declaration = json.loads(result.stdout)
    if (not isinstance(declaration, dict)
            or set(declaration) != {"authority", "built_bytes_verified", "scope", "file_count"}
            or type(declaration.get("file_count")) is not int or declaration["file_count"] < 1
            or declaration.get("authority") is not False
            or declaration.get("built_bytes_verified") is not False
            or declaration.get("scope") != "static_source_declaration_coverage"):
        raise ValueError("source distribution declaration has an unsupported observation scope")
    return {**declaration, "applicable": True}


def validate_distribution_pack(repo_root: Path, *, python_executable: Path | None = None) -> dict[str, Any]:
    """Verify BCF's generated pack bytes before package or evidence work."""

    repo_root = repo_root.resolve()
    template_root = repo_root / "bcf_governance/pack/template-repo"
    if not template_root.is_dir():
        return {"applicable": False}
    entries = _pack_manifest_entries(template_root)
    interpreter = derive_interpreter_environment(template_root)
    if interpreter is not None:
        verify_interpreter_environment_projection(interpreter)
    if python_executable is not None and validate_source_distribution(repo_root, python_executable=python_executable)["applicable"]:
        manifest = _load_yaml(repo_root / "governance/artifact-manifest.yml")
        contract = _load_yaml(repo_root / "governance/gate-contracts.yml")
        rendered = render_profile_surface(contract, width=4096).encode("utf-8")
        _validate_context_budgets(repo_root, manifest, projected_contents={"governance/gate-contracts.yml": rendered})
    return {
        "applicable": True,
        "file_count": len(entries),
        "template_interpreter": (
            "not_declared"
            if interpreter is None
            else "dependencies_and_python"
            if interpreter.requires_python is not None
            else "dependencies_only"
        ),
    }
