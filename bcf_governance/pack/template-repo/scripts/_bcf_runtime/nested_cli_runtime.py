"""Derive nested BCF CLI commands from the exact executing implementation."""

from __future__ import annotations

import sys
from pathlib import Path

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


def exact_nested_cli_command(*arguments: str) -> list[str]:
    """Bind a child CLI to this module's implementation and interpreter."""

    module_root = Path(__file__).resolve().parents[2]
    return [
        str(Path(sys.executable).absolute()),
        "-I",
        "-c",
        _BOOTSTRAP,
        str(module_root),
        *arguments,
    ]
