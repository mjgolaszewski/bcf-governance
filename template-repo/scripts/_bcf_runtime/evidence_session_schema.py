"""Closed evidence-session schema dispatch for N/N+1 expansion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


class EvidenceSessionSchemaError(ValueError):
    """Raised when a session version has no exact governed schema."""


def evidence_session_schema_path(root: Path, version: object) -> Path:
    names = {
        "1.0": "evidence-session.schema.json",
        "2.0": "evidence-session.schema.json",
        "3.0": "evidence-session-v3.schema.json",
    }
    name = names.get(version)
    if name is None:
        raise EvidenceSessionSchemaError(
            "evidence session schema_version must be 1.0, 2.0, or 3.0"
        )
    path = root / "schemas" / name
    if path.is_symlink() or not path.is_file():
        raise EvidenceSessionSchemaError(
            f"evidence session schema {name} is unavailable"
        )
    return path


def load_evidence_session_schema(
    root: Path, payload: Mapping[str, Any]
) -> dict[str, Any]:
    path = evidence_session_schema_path(root, payload.get("schema_version"))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceSessionSchemaError(
            f"cannot load evidence session schema {path.name}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise EvidenceSessionSchemaError("evidence session schema must be an object")
    return value
