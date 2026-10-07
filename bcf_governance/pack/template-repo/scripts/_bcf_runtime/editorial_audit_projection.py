"""Derive immutable release editorial-audit comparison identity."""

from __future__ import annotations

from pathlib import Path
import subprocess

import yaml  # type: ignore[import-untyped]

from .reconcile_stage_ledger import ReconcileError


def editorial_base(repo_root: Path, audit: Path) -> str:
    """Read an existing base or derive a new release base from tracked upstream."""

    if not audit.exists():
        result = subprocess.run(
            ["git", "-C", str(repo_root), "merge-base", "HEAD", "@{upstream}"],
            capture_output=True,
            text=True,
            check=False,
        )
        base = result.stdout.strip()
        if result.returncode or len(base) != 40 or any(
            character not in "0123456789abcdef" for character in base
        ):
            raise ReconcileError(
                "new release editorial audit requires an exact tracked upstream base"
            )
        return base
    try:
        payload = yaml.safe_load(audit.read_text(encoding="utf-8"))
        base = payload["base_commit"]
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        raise ReconcileError("editorial audit does not expose an immutable base") from exc
    if not isinstance(base, str) or len(base) != 40 or any(
        character not in "0123456789abcdef" for character in base
    ):
        raise ReconcileError("editorial audit base is not an exact commit")
    return base
