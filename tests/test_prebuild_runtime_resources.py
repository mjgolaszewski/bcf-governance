"""The loaded runtime rejects missing resource declarations before allocation."""

from pathlib import Path
import subprocess
import sys

import pytest

from bcf_governance.tooling.governance_validation import preflight_distribution as admission
from bcf_governance.tooling.governance_validation import source_inventory
from tests.test_source_admission_authority import _fixture


@pytest.fixture
def framework_source(tmp_path):
    program = "from pathlib import Path\nPath('candidate-executed').touch()\nraise RuntimeError('candidate evaluator executed')\n"
    _fixture(tmp_path, coverage=True, program=program)
    # Independently remove declarations even after legacy fixtures are enriched.
    project = tmp_path / 'pyproject.toml'
    project.write_text(project.read_text().split('[tool.setuptools.package-data]')[0])
    fake = tmp_path / '.github/scripts/test_release_artifacts.py'
    fake.write_text(program + '\ndef validate_package_data_contract(root): return []\n')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True)
    return tmp_path


def _declare(root):
    project = root / 'pyproject.toml'
    project.write_text(project.read_text() + '\n[tool.setuptools.package-data]\n'
                       'bcf_governance = ["pack/template-repo/**/*"]\n')


def test_real_missing_metadata_cannot_be_admitted_as_source_complete(framework_source):
    with pytest.raises(ValueError, match='package data excludes runtime assets'):
        admission.validate_source_distribution(framework_source, python_executable=Path(sys.executable))
    assert not (framework_source / 'candidate-executed').exists()


def test_missing_resource_declaration_rejects_before_project_subprocess(framework_source, monkeypatch):
    calls = []
    def allocate(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError('project interpreter allocated before resource rejection')
    monkeypatch.setattr(admission.subprocess, 'run', allocate)
    with pytest.raises(ValueError, match='package data excludes runtime assets'):
        admission.validate_source_distribution(framework_source, python_executable=Path('/unused/python'))
    assert calls == []


def test_excluded_resource_rejects_before_source_query(framework_source):
    _declare(framework_source)
    with (framework_source / 'pyproject.toml').open('a') as output:
        output.write('[tool.setuptools.exclude-package-data]\n'
                     'bcf_governance = ["pack/template-repo/**/*"]\n')
    with pytest.raises(ValueError, match='package data excludes runtime assets'):
        admission.validate_source_distribution(framework_source, python_executable=Path(sys.executable))


def test_standalone_resource_check_precedes_backend_allocation(framework_source, monkeypatch):
    import setuptools
    original = setuptools.Distribution
    class ForbiddenDistribution(original):
        def __init__(self, *args, **kwargs):
            raise AssertionError('backend allocated before resource rejection')
    monkeypatch.setattr(setuptools, 'Distribution', ForbiddenDistribution)
    monkeypatch.chdir(framework_source)
    with pytest.raises(RuntimeError, match='package data excludes runtime assets'):
        source_inventory.validate_sdist_manifest_coverage(framework_source)


def test_complete_metadata_does_not_execute_candidate_evaluator(framework_source):
    _declare(framework_source)
    result = admission.validate_source_distribution(framework_source, python_executable=Path(sys.executable))
    assert result['applicable'] and result['authority'] is False
    assert result['file_count'] == 6
    assert not (framework_source / 'candidate-executed').exists()


def test_standalone_cli_rejects_metadata_without_a_traceback(framework_source):
    result = subprocess.run(
        [sys.executable, '-I', str(Path(source_inventory.__file__)),
         '--repo-root', str(framework_source)],
        cwd=framework_source, capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert 'package data excludes runtime assets' in result.stderr
    assert 'Traceback' not in result.stderr and not result.stdout


def test_nonframework_source_retains_unbound_behavior(tmp_path, monkeypatch):
    def allocate(*args, **kwargs):
        raise AssertionError('nonframework source allocated an interpreter')
    monkeypatch.setattr(admission.subprocess, 'run', allocate)
    assert admission.validate_source_distribution(tmp_path, python_executable=Path('/unused/python')) == {
        'applicable': False, 'authority': False,
    }
