"""Evidence output serialization and content hashes."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()



def _write_output_artifacts(
    output_dir: Path, gate_id: str, result: subprocess.CompletedProcess[str]
) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    for suffix, value in (("stdout", result.stdout), ("stderr", result.stderr)):
        path = output_dir / f"{gate_id}.{suffix}.txt"
        path.write_text(value, encoding="utf-8")
        artifacts.append(
            {
                "path": path.name,
                "media_type": "text/plain",
                "sha256": _sha256(path),
            }
        )
    return artifacts

