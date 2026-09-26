"""Canonical CI telemetry validation for one prospective proof train."""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

from jsonschema import Draft202012Validator


class ProspectiveTelemetryError(ValueError):
    """The prospective train emitted incomplete or ambiguous telemetry."""


def elapsed_ms(started_ns: int) -> int:
    return max(0, (time.monotonic_ns() - started_ns) // 1_000_000)


def validate_train_telemetry(repo_root: Path, telemetry: dict[str, Any]) -> None:
    expected = {
        "fixed_point", "planning", "reuse", "setup", "producers",
        "positive_tests", "controls", "normalization", "truth",
        "finalization", "publication",
    }
    stages = [
        str(item.get("stage")) for item in telemetry.get("measurements", ())
        if isinstance(item, dict)
    ]
    if len(stages) != len(set(stages)) or set(stages) != expected:
        raise ProspectiveTelemetryError("prospective train telemetry stage inventory is not exact")
    producers = [
        str(item.get("producer")) for item in telemetry.get("producer_observations", ())
        if isinstance(item, dict)
    ]
    if len(producers) != len(set(producers)):
        raise ProspectiveTelemetryError("prospective train telemetry producer inventory is not unique")
    schema = json.loads(
        (repo_root / "schemas/prospective-train-telemetry.schema.json").read_text(encoding="utf-8")
    )
    errors = sorted(Draft202012Validator(schema).iter_errors(telemetry), key=lambda item: list(item.path))
    if errors:
        raise ProspectiveTelemetryError(
            "prospective train telemetry is invalid: " + errors[0].message
        )
