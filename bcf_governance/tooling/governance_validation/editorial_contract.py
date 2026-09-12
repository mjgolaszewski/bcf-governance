"""Run an optional repository editorial checker during cheap preflight."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Any


def check_editorial(repo_root: Path, python: Path) -> dict[str, Any]:
    """Reject stale declared editorial custody before test collection or evidence."""

    checker = repo_root / ".github/scripts/check_editorial_contract.py"
    if not checker.exists():
        return {"applicable": False}
    if checker.is_symlink() or not checker.is_file():
        raise ValueError("editorial contract checker must be one regular nonsymlink file")
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [str(python), str(checker)],
        cwd=repo_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    editorial_failed = result.returncode != 0
    if editorial_failed:
        detail = result.stderr.strip() or result.stdout.strip() or "checker failed"
        raise ValueError(f"editorial contract preflight failed: {detail}")
    return {"applicable": True, "status": "current"}
