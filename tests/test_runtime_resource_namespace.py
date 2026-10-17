"""Metadata cannot expand the source namespace before its safety is known."""

import json

import pytest

from bcf_governance.tooling.governance_validation import source_inventory as owner
from tests.test_prebuild_runtime_resources import framework_source  # noqa: F401


def _configure(root, field, value):
    project = root / 'pyproject.toml'
    head = project.read_text().split('[tool.setuptools.package-data]')[0]
    if field == 'package-data':
        project.write_text(head + '\n[tool.setuptools.package-data]\n'
                           'bcf_governance=' + json.dumps(value) + '\n')
    else:
        project.write_text(head + '\n[tool.setuptools.package-data]\n'
                           'bcf_governance=["pack/template-repo/**/*"]\n'
                           '[tool.setuptools.exclude-package-data]\n'
                           'bcf_governance=' + json.dumps(value) + '\n')


@pytest.mark.parametrize('field', ['package-data', 'exclude-package-data'])
@pytest.mark.parametrize('pattern', ['/outside/**', '../outside/**', 'a/../../outside/*', r'..\outside\*', ''])
def test_unsafe_patterns_reject_before_any_glob(framework_source, monkeypatch, field, pattern):
    _configure(framework_source, field, [pattern])
    calls = []
    def expand(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError('glob expanded before all pattern validation')
    monkeypatch.setattr(owner, 'glob', expand)
    with pytest.raises(RuntimeError, match='package data pattern'):
        owner.validate_package_data_contract(framework_source)
    assert calls == []


@pytest.mark.parametrize('field', ['package-data', 'exclude-package-data'])
@pytest.mark.parametrize('value', [42, True, 'pack/template-repo/**/*', ['pack/template-repo/**/*', 42]])
def test_malformed_pattern_lists_reject_before_any_glob(framework_source, monkeypatch, field, value):
    _configure(framework_source, field, value)
    def expand(*args, **kwargs):
        raise AssertionError('glob expanded before pattern shape validation')
    monkeypatch.setattr(owner, 'glob', expand)
    with pytest.raises(RuntimeError, match='package data pattern'):
        owner.validate_package_data_contract(framework_source)


def test_symlinked_package_root_cannot_substitute_source_namespace(framework_source):
    _configure(framework_source, 'package-data', ['pack/template-repo/**/*'])
    package = framework_source / 'bcf_governance'
    outside = framework_source / 'external-package'
    package.rename(outside)
    package.symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match='runtime asset source is a symlink'):
        owner.discovered_wheel_runtime_assets(framework_source)


def test_contained_patterns_keep_existing_resource_population(framework_source):
    _configure(framework_source, 'package-data', ['pack/template-repo/**/*'])
    assert owner.validate_package_data_contract(framework_source) == (
        'bcf_governance/pack/template-repo/owned.txt',
    )
