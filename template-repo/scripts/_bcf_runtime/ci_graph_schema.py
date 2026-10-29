"""CI graph schema validation; error ordering and messages remain canonical."""
from __future__ import annotations
from typing import Any
from jsonschema import Draft202012Validator
from .ci_graph_errors import CIGraphError
from .schema_diagnostics import schema_error_relative_path, schema_error_location


def validate_schema(payload: dict[str, Any], schema: dict[str, Any], source: str) -> None:
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=schema_error_relative_path)
    if errors:
        error = errors[0]
        location = schema_error_location(error) or "<root>"
        raise CIGraphError(f"{source} schema violation at {location}: {error.message}")
