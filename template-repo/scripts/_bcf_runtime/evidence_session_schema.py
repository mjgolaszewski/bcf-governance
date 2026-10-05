"""Closed evidence-session schema dispatch for N/N+1 expansion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import yaml  # type: ignore[import-untyped]


class EvidenceSessionSchemaError(ValueError):
    """Raised when a session version has no exact governed schema."""


PLANNED_SESSION_VERSIONS = frozenset({"2.0", "3.0"})


def is_planned_session(payload: Mapping[str, Any]) -> bool:
    """Return whether *payload* carries the canonical verification plan."""

    return payload.get("schema_version") in PLANNED_SESSION_VERSIONS


def active_planned_session_version(root: Path) -> str:
    """Resolve self or adopter activation from canonical claim-model state."""

    claim_path = root / "governance/gate-contracts.yml"
    try:
        claim_payload = yaml.safe_load(claim_path.read_text(encoding="utf-8"))
        claim_model = claim_payload["claim_model"]
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        raise EvidenceSessionSchemaError(
            "canonical evidence claim model is unavailable"
        ) from exc
    if not isinstance(claim_model, dict):
        raise EvidenceSessionSchemaError(
            "canonical evidence claim model is invalid"
        )
    derived = "3.0" if "non_proof_dependencies" in claim_model else "2.0"
    path = root / "governance/public-contracts.yml"
    if not path.exists():
        return derived
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        declared = payload["contracts"]["evidence_session"]["active_version"]
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        raise EvidenceSessionSchemaError(
            "active evidence session contract is unavailable"
        ) from exc
    if declared not in PLANNED_SESSION_VERSIONS or declared != derived:
        raise EvidenceSessionSchemaError(
            "active evidence session differs from canonical claim-model capability"
        )
    return str(declared)


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
