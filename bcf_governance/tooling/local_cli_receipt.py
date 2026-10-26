"""Project the non-authoritative local BCF executable used by generated gates."""

from __future__ import annotations

import os
import re
from pathlib import Path


class LocalCLIReceiptError(ValueError):
    """Raised when local executable custody cannot be projected safely."""


RECEIPT_PATH = Path(".artifacts/bcf/local-cli.mk")


def resolve_local_cli(executable: str) -> Path:
    """Validate one exact executable path before repository mutation."""

    if not executable or re.search(r"[\s#$]", executable):
        raise LocalCLIReceiptError("local BCF executable path is unsafe")
    candidate = Path(executable)
    if not candidate.is_absolute():
        raise LocalCLIReceiptError("local BCF executable path is not absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise LocalCLIReceiptError("local BCF executable is unavailable") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise LocalCLIReceiptError("local BCF executable is unavailable")
    return candidate.absolute()


def project_local_cli_receipt(repo_root: Path, executable: Path) -> Path:
    """Write the local-only Make projection after a successful installation."""

    resolved = resolve_local_cli(str(executable))
    path = repo_root.resolve() / RECEIPT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"BCF := {resolved} -m bcf_governance.cli\n", encoding="utf-8")
    return path
