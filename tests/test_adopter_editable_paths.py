"""Only the admitted adopter's own editable source path is rebound."""
from __future__ import annotations

import sys
import venv
from pathlib import Path

import pytest

from bcf_governance.tooling.release_adopter_qualification import (
    ReleaseQualificationError,
    _isolated_project_python,
)


def environment(tmp_path: Path, line: str) -> tuple[Path, Path, Path]:
    source = tmp_path / "source"
    destination = tmp_path / "candidate"
    source.mkdir()
    destination.mkdir()
    root = source / ".venv"
    venv.EnvBuilder(with_pip=False).create(root)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    hook = root / "lib" / version / "site-packages" / "project.pth"
    hook.write_text(line.replace("SOURCE", str(source)) + "\n")
    return source, destination, root / "bin/python"


def test_admitted_path_rebases_inside_workspace_staging(tmp_path: Path) -> None:
    source, destination, python = environment(tmp_path, "SOURCE/src")
    projected = tmp_path / "projected"
    _isolated_project_python(source, python, destination, projected)
    hooks = list(projected.glob("lib/python*/site-packages/project.pth"))
    assert len(hooks) == 1
    assert hooks[0].read_text() == str(destination / "src") + "\n"


@pytest.mark.parametrize("line", [
    "/docker/unrelated-owner/source",
    "SOURCE/../foreign",
    "SOURCE-other/src",
    "import sys; sys.path.insert(0, 'SOURCE/src')",
], ids=["foreign-root", "parent-escape", "prefix-collision", "executable-hook"])
def test_foreign_or_executable_workspace_hook_refuses(tmp_path: Path, line: str) -> None:
    source, destination, python = environment(tmp_path, line)
    with pytest.raises(ReleaseQualificationError, match="unrelated workspace"):
        _isolated_project_python(source, python, destination, tmp_path / "projected")


def test_source_symlink_cannot_smuggle_an_unrelated_workspace(tmp_path: Path) -> None:
    source, destination, python = environment(tmp_path, "SOURCE/src")
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (source / "src").symlink_to(foreign, target_is_directory=True)
    with pytest.raises(ReleaseQualificationError, match="unrelated workspace"):
        _isolated_project_python(source, python, destination, tmp_path / "projected")
