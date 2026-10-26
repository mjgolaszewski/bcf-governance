from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.governance_install.existing_adoption import _python_roots
from tests.test_install_governance_pack import _run_installer


def _repository(root: Path, *, discovery: str = 'where = ["src"]', backend: str = "setuptools.build_meta") -> None:
    (root / "src/example").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src/example/__init__.py").write_text("VALUE = 1\n")
    (root / "tests/test_example.py").write_text("def test_example():\n    assert True\n")
    (root / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools>=69", "wheel"]\n'
        + 'build-backend = "' + backend + '"\n'
        + '[project]\nname = "example"\nversion = "1.0.0"\n'
        + '[tool.setuptools.packages.find]\n' + discovery + '\n'
        + '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
    )
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "add", "pyproject.toml", "src", "tests"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Adoption Test", "-c", "user.email=adoption@example.invalid", "commit", "--quiet", "-m", "Native setuptools baseline"],
        cwd=root, check=True,
    )


def test_setuptools_package_roots_come_from_tracked_declared_metadata(tmp_path: Path) -> None:
    _repository(tmp_path)
    before = (tmp_path / "pyproject.toml").read_bytes()
    assert _python_roots(tmp_path) == (("src",), ("tests",))
    assert (tmp_path / "pyproject.toml").read_bytes() == before


def test_existing_hatch_root_contract_is_preserved(tmp_path: Path) -> None:
    _repository(tmp_path)
    metadata = tmp_path / "pyproject.toml"
    metadata.write_text(
        '[tool.hatch.build.targets.wheel]\npackages = ["src/example"]\n'
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
    )
    assert _python_roots(tmp_path) == (("src/example",), ("tests",))


@pytest.mark.parametrize(
    "declaration,backend,reason",
    [
        ('where = ["../outside"]', "setuptools.build_meta", "unsafe"),
        ('where = ["/tmp"]', "setuptools.build_meta", "unsafe"),
        ('where = ["missing"]', "setuptools.build_meta", "not a repository directory"),
        ('where = []', "setuptools.build_meta", "non-empty"),
        ('include = ["example*"]', "setuptools.build_meta", "explicit setuptools"),
        ('where = ["src"]', "hatchling.build", "declared setuptools backend"),
    ],
)
def test_unsupported_or_escaping_setuptools_roots_fail_closed(
    tmp_path: Path, declaration: str, backend: str, reason: str,
) -> None:
    _repository(tmp_path, discovery=declaration, backend=backend)
    before = (tmp_path / "pyproject.toml").read_bytes()
    with pytest.raises(ValueError, match=reason):
        _python_roots(tmp_path)
    assert (tmp_path / "pyproject.toml").read_bytes() == before


@pytest.mark.parametrize("condition", ["ambiguous", "untracked", "symlink", "symlink_parent", "additional_modules"])
def test_setuptools_inventory_rejects_incomplete_or_ambiguous_coverage(tmp_path: Path, condition: str) -> None:
    _repository(tmp_path)
    metadata = tmp_path / "pyproject.toml"
    if condition == "ambiguous":
        metadata.write_text(metadata.read_text() + '[tool.hatch.build.targets.wheel]\npackages = ["src/example"]\n')
        reason = "ambiguous"
    elif condition == "untracked":
        (tmp_path / "untracked").mkdir()
        (tmp_path / "untracked/file.py").write_text("VALUE = 1\n")
        metadata.write_text(metadata.read_text().replace('where = ["src"]', 'where = ["untracked"]'))
        reason = "no tracked files"
    elif condition == "symlink_parent":
        (tmp_path / "src").rename(tmp_path / "original-src")
        (tmp_path / "src").symlink_to("original-src", target_is_directory=True)
        metadata.write_text(metadata.read_text().replace('where = ["src"]', 'where = ["src/example"]'))
        reason = "not a repository directory"
    elif condition == "symlink":
        (tmp_path / "src").rename(tmp_path / "original-src")
        (tmp_path / "src").symlink_to("original-src", target_is_directory=True)
        reason = "not a repository directory"
    else:
        metadata.write_text(metadata.read_text() + '[tool.setuptools]\npy-modules = ["outside_module"]\n')
        reason = "additional setuptools"
    with pytest.raises(ValueError, match=reason):
        _python_roots(tmp_path)


def test_native_existing_install_projects_setuptools_roots_without_changing_application(tmp_path: Path) -> None:
    _repository(tmp_path)
    protected = {name: (tmp_path / name).read_bytes() for name in (
        "pyproject.toml", "src/example/__init__.py", "tests/test_example.py",
    )}
    _run_installer(tmp_path, "--profile", "lite", "--adoption-mode", "existing", "--require-strict-validation")
    architecture = yaml.safe_load((tmp_path / "architecture-boundaries.yml").read_text())
    adoption = yaml.safe_load((tmp_path / "governance/existing-repo-adoption.yml").read_text())
    assert architecture["architecture"]["source_roots"] == ["src"]
    assert adoption["required_inventory"]["source_roots"] == ["src"]
    assert adoption["required_inventory"]["test_roots"] == ["tests"]
    assert {name: (tmp_path / name).read_bytes() for name in protected} == protected
