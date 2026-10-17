from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tomllib
from xml.etree import ElementTree
import zipfile

import pytest

from bcf_governance.tooling.release_runtime_verification import (
    is_release_sdist_test_context,
)
from bcf_governance.tooling.interpreter_environment import (
    validate_runtime_import_dependencies,
)
from bcf_governance.tooling import ci_controller_builder as controller_builder


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / ".github/scripts/test_release_artifacts.py"
spec = importlib.util.spec_from_file_location("release_artifacts", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load release artifact verifier")
release_artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_artifacts)
validate_sdist_source_inventory = release_artifacts.validate_sdist_source_inventory

def test_runtime_third_party_imports_are_declared_as_package_dependencies() -> None:
    validate_runtime_import_dependencies(REPO_ROOT)


def test_controller_builder_derives_every_runtime_requirement_from_pyproject() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert controller_builder._source_requirements(REPO_ROOT) == tuple(
        project["project"]["dependencies"]
    )
    assert any(
        requirement.startswith("packaging")
        for requirement in controller_builder._source_requirements(REPO_ROOT)
    )


def test_controller_builder_rejects_dirty_tree_before_expense(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        controller_builder, "_git", lambda _root, *args: " M source.py"
    )

    with pytest.raises(ValueError, match="clean committed HEAD"):
        controller_builder.build(
            REPO_ROOT,
            Path(".artifacts/unused-controller"),
            run_id="1",
            run_attempt="1",
        )


def test_exact_head_build_source_excludes_ignored_stale_payload(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.invalid"],
        cwd=repo,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Fixture"], cwd=repo, check=True
    )
    (repo / ".gitignore").write_text("build/\n", encoding="utf-8")
    (repo / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=repo, check=True)
    stale = repo / "build/lib/deleted.py"
    stale.parent.mkdir(parents=True)
    stale.write_text("STALE = True\n", encoding="utf-8")

    with controller_builder.exact_head_source(repo) as source:
        assert (source / "source.py").read_text(encoding="utf-8") == "VALUE = 1\n"
        assert not (source / "build").exists()

    assert stale.is_file()


def test_release_artifact_entrypoint_bootstraps_clean_source_checkout() -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME"}
    }
    result = subprocess.run(
        [sys.executable, "-I", str(MODULE_PATH), "--help"],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_current_source_contains_complete_sdist_test_payload() -> None:
    release_artifacts.validate_sdist_payload(REPO_ROOT)
    release_artifacts.validate_sdist_root_selection(REPO_ROOT)


def test_new_tracked_source_root_requires_sdist_selection(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
    (repo / "existing").mkdir()
    (repo / "existing/source.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "new-spec").mkdir()
    (repo / "new-spec/contract.md").write_text("# Contract\n", encoding="utf-8")
    (repo / "MANIFEST.in").write_text(
        "recursive-include existing *.py\n", encoding="utf-8"
    )
    (repo / "pyproject.toml").write_text(
        '[tool.setuptools.packages.find]\ninclude = ["existing*"]\n', encoding="utf-8"
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True)

    with pytest.raises(RuntimeError, match="omits tracked source root: new-spec"):
        release_artifacts.validate_sdist_root_selection(repo)


def test_built_sdist_contains_every_governed_source_file(tmp_path: Path) -> None:
    if is_release_sdist_test_context(REPO_ROOT):
        pytest.skip("requires the canonical source repository's Git custody")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--sdist",
            "--outdir",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    archives = tuple(tmp_path.glob("bcf_governance-*.tar.gz"))
    assert len(archives) == 1
    validate_sdist_source_inventory(REPO_ROOT, archives[0])


def test_missing_tracked_source_is_rejected_from_built_sdist(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
    (repo / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (repo / "included.txt").write_text("included\n", encoding="utf-8")
    (repo / "omitted.yml").write_text("omitted: true\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    archive = tmp_path / "fixture.tar.gz"
    payload = tmp_path / "payload"
    payload.mkdir()
    included = payload / "included.txt"
    included.write_text("included\n", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as output:
        output.add(repo / ".gitignore", arcname="fixture/.gitignore")
        output.add(included, arcname="fixture/included.txt")

    with pytest.raises(ValueError, match="source archive omits tracked source: omitted.yml"):
        validate_sdist_source_inventory(repo, archive)


def test_pyproject_packages_every_discovered_runtime_asset() -> None:
    admitted = release_artifacts.validate_package_data_contract(REPO_ROOT)
    assert "bcf_governance/tooling/semantic_ownership_typescript.mjs" in admitted


def test_missing_runtime_asset_is_rejected_before_wheel_execution(tmp_path: Path) -> None:
    source = tmp_path / "source"
    asset = source / "bcf_governance/tooling/analyzer.mjs"
    asset.parent.mkdir(parents=True)
    asset.write_text("export {};\n", encoding="utf-8")
    (source / "pyproject.toml").write_text(
        '[tool.setuptools.package-data]\nbcf_governance = ["tooling/*.mjs"]\n',
        encoding="utf-8",
    )
    wheel = tmp_path / "bcf_governance-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("bcf_governance/__init__.py", "")

    with pytest.raises(RuntimeError, match="wheel missing runtime assets"):
        release_artifacts.validate_wheel_runtime_assets(wheel, source)

    with zipfile.ZipFile(wheel, "a") as archive:
        archive.write(asset, "bcf_governance/tooling/analyzer.mjs")
    release_artifacts.validate_wheel_runtime_assets(wheel, source)


def test_package_metadata_cannot_omit_discovered_runtime_assets(tmp_path: Path) -> None:
    asset = tmp_path / "bcf_governance/tooling/analyzer.mjs"
    asset.parent.mkdir(parents=True)
    asset.touch()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.setuptools.package-data]\nbcf_governance = []\n', encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="package data excludes runtime assets"):
        release_artifacts.validate_package_data_contract(tmp_path)


def test_missing_sdist_payload_mutant_is_rejected(tmp_path: Path) -> None:
    for relative in release_artifacts.REQUIRED_SDIST_PATHS:
        (tmp_path / relative).mkdir(parents=True, exist_ok=True)
    for relative in release_artifacts.REQUIRED_SDIST_FILES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    missing = tmp_path / "audits"
    missing.rmdir()

    with pytest.raises(RuntimeError, match="sdist payload missing: audits"):
        release_artifacts.validate_sdist_payload(tmp_path)


def test_sdist_source_custody_tracks_the_complete_extracted_tree(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "source.txt").write_text("source\n", encoding="utf-8")
    (tmp_path / "nested/evidence.txt").write_text("evidence\n", encoding="utf-8")

    release_artifacts.initialize_source_custody(tmp_path)

    assert release_artifacts.subprocess.run(
        ["git", "ls-files"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.splitlines() == ["nested/evidence.txt", "source.txt"]
    assert release_artifacts.subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""

    suite = ElementTree.Element("testsuite")
    for classname, name in sorted(release_artifacts.ALLOWED_SDIST_CUSTODY_SKIPS):
        case = ElementTree.SubElement(
            suite, "testcase", {"classname": classname, "name": name}
        )
        ElementTree.SubElement(case, "skipped")
    junit = tmp_path / "sdist-tests.xml"
    ElementTree.ElementTree(suite).write(junit, encoding="utf-8")
    release_artifacts.validate_sdist_test_skips(junit)
    suite.remove(next(iter(suite)))
    ElementTree.ElementTree(suite).write(junit, encoding="utf-8")
    with pytest.raises(RuntimeError, match="sdist test skip contract mismatch"):
        release_artifacts.validate_sdist_test_skips(junit)


@pytest.fixture
def manifest_declaration_fixture(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "pyproject.toml").write_text('[build-system]\nrequires=["setuptools>=69","wheel"]\nbuild-backend="setuptools.build_meta"\n[project]\nname="source-fixture"\nversion="1.0"\n[tool.setuptools.packages.find]\ninclude=["example_pkg*"]\n')
    (root / "example_pkg").mkdir(); (root / "example_pkg/__init__.py").write_text('VALUE=1\n')
    (root / "audits").mkdir(); (root / "audits/collector.py").write_text('VALUE=2\n')
    (root / "README.md").write_text('Source fixture\n')
    (root / "MANIFEST.in").write_text('include README.md pyproject.toml MANIFEST.in\nrecursive-include audits *.py\n')
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    return root


def _manifest_declaration_query(root):
    environment = dict(os.environ); environment.pop("PYTHONPATH", None)
    return subprocess.run([sys.executable, str(REPO_ROOT / '.github/scripts/release_source_inventory.py'), '--repo-root', str(root)],
                          cwd=root, env=environment, capture_output=True, text=True, check=False)


def test_source_manifest_query_uses_backend_defaults_without_build_or_mutation(manifest_declaration_fixture):
    root = manifest_declaration_fixture
    before = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file() and '.git' not in p.parts}
    result = _manifest_declaration_query(root)
    assert result.returncode == 0, result.stderr
    import json
    observed = json.loads(result.stdout)
    assert observed == {'authority': False, 'built_bytes_verified': False, 'file_count': 5, 'scope': 'static_source_declaration_coverage'}
    assert {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file() and '.git' not in p.parts} == before


@pytest.mark.parametrize('cause', ['missing-suffix', 'explicit-exclusion', 'malformed', 'dynamic-code', 'setup-code', 'nonliteral-version', 'symlink-source'])
def test_source_manifest_query_rejects_before_build(manifest_declaration_fixture, cause):
    root = manifest_declaration_fixture
    manifest = root / 'MANIFEST.in'
    if cause == 'missing-suffix': manifest.write_text(manifest.read_text().replace('audits *.py', 'audits *.json'))
    elif cause == 'explicit-exclusion': manifest.write_text(manifest.read_text() + 'exclude audits/collector.py\n')
    elif cause == 'malformed': manifest.write_text(manifest.read_text() + 'unknown-directive audits/collector.py\n')
    elif cause == 'dynamic-code':
        project = root / 'pyproject.toml'
        project.write_text(project.read_text().replace('version="1.0"', 'dynamic=["version"]') + '\n[tool.setuptools.dynamic]\nversion={attr="untrusted.version"}\n')
        (root / 'untrusted.py').write_text('from pathlib import Path\nPath("executed").touch()\nversion="1.0"\n')
    elif cause == 'nonliteral-version':
        project = root / 'pyproject.toml'
        project.write_text(project.read_text().replace('version="1.0"', 'dynamic=["version"]') + '\n[tool.setuptools.dynamic]\nversion={attr="bcf_governance._version.__version__"}\n')
        (root / 'bcf_governance').mkdir()
        (root / 'bcf_governance/_version.py').write_text('from pathlib import Path\ndef compute():\n    Path("executed").touch()\n    return "1.0"\n__version__=compute()\n')
        subprocess.run(['git', 'add', '.'], cwd=root, check=True, capture_output=True)
    elif cause == 'symlink-source':
        source = root / 'audits/collector.py'; source.unlink()
        source.symlink_to(root / 'example_pkg/__init__.py')
    else: (root / 'setup.py').write_text('from pathlib import Path\nPath("executed").touch()\n')
    result = _manifest_declaration_query(root)
    assert result.returncode != 0
    assert 'source' in result.stderr
    assert not (root / 'executed').exists()
    assert not tuple(root.glob('*.egg-info')) and not (root / 'dist').exists()


def test_source_manifest_query_rejects_wrong_working_subject(manifest_declaration_fixture):
    root = manifest_declaration_fixture
    result = subprocess.run([sys.executable, str(REPO_ROOT / '.github/scripts/release_source_inventory.py'),
        '--repo-root', str(root / 'other')], cwd=root, capture_output=True, text=True, check=False)
    assert result.returncode != 0 and 'exact working directory' in result.stderr
