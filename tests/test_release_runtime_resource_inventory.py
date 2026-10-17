"""Release resource population derives from source, never the candidate wheel."""

from pathlib import Path
import warnings
import zipfile

import pytest

from tests.test_release_artifacts import release_artifacts as owner


@pytest.fixture
def source_resources(tmp_path):
    source = tmp_path / 'source'
    files = {
        'bcf_governance/tooling/analyzer.mjs': b'export {};\n',
        'bcf_governance/tooling/ordinary.py': b'# Ordinary package source.\n',
        'bcf_governance/pack/template-repo/scripts/_bcf_runtime/owner.py': b'# Private runtime.\n',
        'bcf_governance/pack/template-repo/scripts/_bcf_runtime/resources/schemas/proof.json': b'{"type":"object"}\n',
    }
    for name, data in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (source / 'pyproject.toml').write_text(
        '[tool.setuptools.package-data]\n'
        'bcf_governance = ["tooling/*.mjs", "pack/template-repo/**/*"]\n',
    )
    return source, files


def _wheel(tmp_path: Path, files):
    wheel = tmp_path / 'fixture.whl'
    with warnings.catch_warnings(), zipfile.ZipFile(wheel, 'w') as archive:
        warnings.simplefilter('ignore', UserWarning)
        for name, data in files:
            archive.writestr(name, data)
    return wheel


def test_metadata_cannot_exclude_private_schema_resources(source_resources):
    source, _ = source_resources
    (source / 'pyproject.toml').write_text(
        '[tool.setuptools.package-data]\nbcf_governance = ["tooling/*.mjs"]\n',
    )
    with pytest.raises(RuntimeError, match='package data excludes runtime assets'):
        owner.validate_package_data_contract(source)


def test_explicit_exclusion_cannot_hide_required_runtime_resources(source_resources):
    source, _ = source_resources
    with (source / 'pyproject.toml').open('a') as output:
        output.write('[tool.setuptools.exclude-package-data]\n'
                     'bcf_governance = ["pack/template-repo/**/*.json"]\n')
    with pytest.raises(RuntimeError, match='package data excludes runtime assets'):
        owner.validate_package_data_contract(source)


def test_recursive_pattern_covers_pack_root_files(source_resources):
    source, _ = source_resources
    root_file = source / 'bcf_governance/pack/template-repo/README.md'
    root_file.write_text('pack root resource\n')
    assert root_file.relative_to(source).as_posix() in owner.validate_package_data_contract(source)


def test_hidden_pack_resources_require_explicit_pattern_coverage(source_resources):
    source, _ = source_resources
    hidden = source / 'bcf_governance/pack/template-repo/.pack-state'
    hidden.write_text('owned hidden resource\n')
    with pytest.raises(RuntimeError, match='package data excludes runtime assets'):
        owner.validate_package_data_contract(source)
    project = source / 'pyproject.toml'
    project.write_text(project.read_text().replace(
        '"pack/template-repo/**/*"', '"pack/template-repo/**/*", "pack/template-repo/**/.*"',
    ))
    assert hidden.relative_to(source).as_posix() in owner.validate_package_data_contract(source)


@pytest.mark.parametrize('suffix', ['proof.json', 'owner.py'])
def test_wheel_cannot_omit_source_discovered_pack_resource(tmp_path, source_resources, suffix):
    source, files = source_resources
    wheel = _wheel(tmp_path, [(name, data) for name, data in files.items()
                              if not name.endswith(suffix)])
    with pytest.raises(RuntimeError, match='wheel missing runtime assets'):
        owner.validate_wheel_runtime_assets(wheel, source)


@pytest.mark.parametrize('suffix', ['proof.json', 'analyzer.mjs'])
def test_wheel_resource_bytes_must_equal_admitted_source(tmp_path, source_resources, suffix):
    source, files = source_resources
    wheel = _wheel(tmp_path, [(name, b'substituted' if name.endswith(suffix) else data)
                              for name, data in files.items()])
    with pytest.raises(RuntimeError, match='wheel runtime asset differs from source'):
        owner.validate_wheel_runtime_assets(wheel, source)


def test_duplicate_required_resource_is_not_collapsed_to_one_name(tmp_path, source_resources):
    source, files = source_resources
    member = next((name, data) for name, data in files.items() if name.endswith('.mjs'))
    wheel = _wheel(tmp_path, [*files.items(), member])
    with pytest.raises(RuntimeError, match='wheel runtime asset is duplicated'):
        owner.validate_wheel_runtime_assets(wheel, source)


def test_symlink_resource_cannot_silently_supply_external_bytes(source_resources):
    source, files = source_resources
    name = next(name for name in files if name.endswith('proof.json'))
    resource = source / name
    resource.unlink()
    resource.symlink_to(source / 'pyproject.toml')
    with pytest.raises(RuntimeError, match='runtime asset source is a symlink'):
        owner.discovered_wheel_runtime_assets(source)


def test_complete_resource_population_preserves_source_python_and_cache_rules(tmp_path, source_resources):
    source, files = source_resources
    cache = source / 'bcf_governance/pack/template-repo/scripts/_bcf_runtime/__pycache__/ignored.pyc'
    cache.parent.mkdir()
    cache.write_bytes(b'cache')
    expected = set(files) - {'bcf_governance/tooling/ordinary.py'}
    assert set(owner.discovered_wheel_runtime_assets(source)) == expected
    wheel = _wheel(tmp_path, files.items())
    owner.validate_wheel_runtime_assets(wheel, source)


def test_missing_resources_reject_before_installed_environment_allocation(
    tmp_path, source_resources, monkeypatch,
):
    source, files = source_resources
    wheel = _wheel(tmp_path, [(name, data) for name, data in files.items()
                              if not name.endswith('proof.json')])
    allocated = []
    def allocate(path):
        allocated.append(path)
        raise AssertionError('installed environment allocated before resource rejection')
    monkeypatch.setattr(owner, 'venv_environment', allocate)
    execution = tmp_path / 'execution'
    with pytest.raises(RuntimeError, match='wheel missing runtime assets'):
        owner.verify_wheel(wheel, execution, source)
    assert allocated == [] and not execution.exists()
