"""Stable schema error keys and locations shared by governance queries."""
from __future__ import annotations
from typing import Any
from jsonschema.exceptions import ValidationError


def schema_error_relative_path(error: ValidationError) -> list[Any]:
    return list(error.path)


def schema_error_absolute_path(error: ValidationError) -> list[Any]:
    return list(error.absolute_path)


def schema_error_location(error: ValidationError) -> str:
    tokens: list[str] = []
    for token in error.absolute_path:
        tokens.append(str(token))
    return ".".join(tokens) or "<root>"


def schema_error_string_path(error: ValidationError) -> tuple[str, ...]:
    tokens: list[str] = []
    for token in error.absolute_path:
        tokens.append(str(token))
    return tuple(tokens)
