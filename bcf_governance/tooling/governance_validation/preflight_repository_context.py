"""Cheap provider-independent repository context checks for preflight."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
from typing import Any


def pr_context(repo_root: Path, mode: str) -> dict[str, Any]:
    if mode != "pr":
        return {"applicable": False}
    base = os.environ.get("BCF_PR_BASE_SHA", "")
    if not re.fullmatch(r"[a-f0-9]{40,64}", base):
        raise ValueError("PR preflight requires exact BCF_PR_BASE_SHA")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, "HEAD"],
        cwd=repo_root,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("PR base SHA is not an ancestor of HEAD")
    return {"applicable": True, "base_sha": base}
