from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from bcf_governance import __version__
from bcf_governance.tooling.runtime_capacity import executing_runtime_version


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_source_runtime_version_comes_from_local_canonical_owner() -> None:
    assert executing_runtime_version() == __version__


def test_projected_runtime_version_ignores_ambient_package(tmp_path: Path) -> None:
    runtime = tmp_path / "_bcf_runtime"
    runtime.mkdir()
    (runtime / "runtime_capacity.py").write_bytes(
        (REPO_ROOT / "bcf_governance/tooling/runtime_capacity.py").read_bytes()
    )
    (runtime / "_version.py").write_text('__version__ = "9.8.7"\n', encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                f"sys.path.insert(0, {str(tmp_path)!r}); "
                "from _bcf_runtime.runtime_capacity import executing_runtime_version; "
                "print(executing_runtime_version())"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "9.8.7"
