"""Single mechanical owner for trusted GitHub CLI environment and outputs."""

from __future__ import annotations

import os
from pathlib import Path

from .ci_github_identity import GitHubControllerError


def required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise GitHubControllerError(f"trusted workflow environment is missing {name}")
    return value


def github_output_path() -> Path:
    path = Path(required_environment("GITHUB_OUTPUT"))
    if path.is_symlink() or not path.is_file():
        raise GitHubControllerError("GITHUB_OUTPUT must be an existing regular file")
    return path


def github_output(payload: dict[str, object], *, path: Path) -> None:
    lines: list[str] = []
    for key, value in sorted(payload.items()):
        if not key.replace("_", "").isalnum() or not key[0].isalpha():
            raise GitHubControllerError("controller output name is unsafe")
        if value is None:
            rendered = ""
        elif isinstance(value, bool):
            rendered = str(value).lower()
        elif isinstance(value, (str, int)):
            rendered = str(value)
        else:
            continue
        if "\n" in rendered or "\r" in rendered:
            raise GitHubControllerError("controller output value is multiline")
        lines.append(f"{key}={rendered}\n")
    with path.open("a", encoding="utf-8") as stream:
        stream.writelines(lines)
