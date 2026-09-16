from __future__ import annotations

from pathlib import Path
import zipfile

import pytest

from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.release_runtime_verification import (
    _validate_wheel_source_mapping,
)


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    package = source / "bcf_governance"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    return source


def test_exact_wheel_source_bytes_permit_release_composition(tmp_path: Path) -> None:
    source = _source(tmp_path)
    wheel = tmp_path / "package.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.write(source / "bcf_governance/__init__.py", "bcf_governance/__init__.py")
    assert _validate_wheel_source_mapping(wheel, source) == {
        "status": "exact",
        "mapped_files": 1,
    }


def test_modified_generated_wheel_code_fails_closed(tmp_path: Path) -> None:
    source = _source(tmp_path)
    wheel = tmp_path / "package.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("bcf_governance/__init__.py", "VALUE = 'modified'\n")
    with pytest.raises(GitHubControllerError, match="source mapping differs"):
        _validate_wheel_source_mapping(wheel, source)


def test_wheel_code_without_source_owner_fails_closed(tmp_path: Path) -> None:
    source = _source(tmp_path)
    wheel = tmp_path / "package.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("bcf_governance/generated.py", "UNOWNED = True\n")
    with pytest.raises(GitHubControllerError, match="source mapping differs"):
        _validate_wheel_source_mapping(wheel, source)
