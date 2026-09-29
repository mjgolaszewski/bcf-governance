"""Authenticated preservation boundary for adopter-owned upgrade bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


def preserved_consumer_inventory(target_root: Path) -> dict[str, str]:
    """Authenticate exact adopter-owned bytes excluded from ordinary upgrade."""
    lock = target_root / "governance/bcf-runtime-lock.json"
    if not lock.exists():
        return {}
    if not lock.is_file() or lock.is_symlink():
        raise RuntimeError("BCF runtime lock must be one nonsymlink file")
    try:
        payload = json.loads(lock.read_text(encoding="utf-8"))
        preserved = payload["preserved_consumer_files"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError) as exc:
        raise RuntimeError("BCF runtime lock preserved-consumer inventory is unreadable") from exc
    if not isinstance(preserved, dict):
        raise RuntimeError("BCF runtime lock preserved-consumer inventory must be an object")
    result: dict[str, str] = {}
    for relative, expected in preserved.items():
        path = Path(str(relative))
        if path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
            raise RuntimeError("BCF runtime lock contains an unsafe preserved-consumer path")
        target = target_root / path
        if (
            not isinstance(expected, str)
            or re.fullmatch(r"[a-f0-9]{64}", expected) is None
            or not target.is_file()
            or target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != expected
        ):
            raise RuntimeError(
                f"preserved consumer file does not match its runtime lock: {relative}"
            )
        result[relative] = expected
    return dict(sorted(result.items()))


def preserved_consumer_files(target_root: Path) -> frozenset[str]:
    """Return exact paths from the authenticated adopter-owned inventory."""

    return frozenset(preserved_consumer_inventory(target_root))
