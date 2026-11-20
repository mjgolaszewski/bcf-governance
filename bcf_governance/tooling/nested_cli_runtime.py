"""Derive nested BCF CLI commands from the exact executing implementation."""

from __future__ import annotations

from pathlib import Path
import sys


_BOOTSTRAP = (
    "from pathlib import Path;import sys;"
    "root=Path(sys.argv[1]).resolve();"
    "sys.path.insert(0,str(root));"
    "from bcf_governance import cli;"
    "origin=Path(cli.__file__).resolve();"
    "expected=(root/'bcf_governance').resolve();"
    "origin.is_relative_to(expected) or sys.exit("
    "f'nested BCF CLI origin mismatch: {origin} is not under {expected}');"
    "cli.main(sys.argv[2:])"
)


def cli_arguments(argv: object = None) -> list[str]:
    """Snapshot ordinary CLI strings before argument consumption or parser setup."""
    raw = sys.argv if argv is None else argv
    kind = type(raw)
    if kind is not list and kind is not tuple:
        raise TypeError("CLI arguments must be an ordinary string list or tuple")
    values = raw[:]
    if any(type(value) is not str for value in values):
        raise TypeError("CLI arguments must contain only ordinary strings")
    if argv is None:
        values = values[1:]
    return values if kind is list else [value for value in values]


def exact_nested_cli_command(*arguments: str) -> list[str]:
    """Bind a child CLI to this module's implementation and interpreter."""

    values = cli_arguments(arguments)
    module_root = Path(__file__).resolve().parents[2]
    return [
        str(Path(sys.executable).absolute()),
        "-I",
        "-c",
        _BOOTSTRAP,
        str(module_root),
        *values,
    ]
