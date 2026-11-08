"""Early and late phase guards have independent, runtime-local causal oracles."""
import importlib
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from tests.test_validate_governance_yaml import (
    VALIDATOR_MODULE,
    _copy_phase_triplet,
    _instantiate_fixture_repo,
)


def _owner(name):
    package = VALIDATOR_MODULE.validate_repo_root.__module__.rsplit('.', 1)[0]
    return importlib.import_module(f'{package}.{name}')


def _inputs(root):
    paths = {
        'product': 'plans/product-spec.yml', 'build': 'plans/build-plan.yml',
        'ledger': 'plans/phase-ledger.yml', 'manifest': 'governance/artifact-manifest.yml',
        'memory': 'MEMORY.yml', 'history': 'plans/phase-history.yml',
    }
    return {key: yaml.safe_load((root / path).read_text()) if (root / path).is_file() else None
            for key, path in paths.items()}


def _catalog(root, owner, data, cache):
    return owner._validate_declared_phase_catalog(
        root, cache, data['product'], data['build'], data['ledger'],
        data['manifest'], data['history'],
    )


@pytest.mark.parametrize('stage', ['early', 'catalog', 'active'])
def test_phase_owner_accepts_complete_valid_fixture(tmp_path: Path, stage):
    root = _instantiate_fixture_repo(tmp_path, 'valid_repo')
    if stage == 'early':
        assert _owner('authored_phase_state').validate_authored_phase_state(root)['phase_id'] == 'P01'
        return
    owner = _owner('phase_catalog')
    data, cache = _inputs(root), {}
    paths = _catalog(root, owner, data, cache)
    assert 'P01' in paths
    if stage == 'active':
        actual = owner._validate_active_phase(root, cache, data['ledger'], data['memory'], paths)
        assert len(actual) == 3 and all(path.is_file() for path in actual)


def test_late_catalog_owner_rejects_distinct_phase_populations(tmp_path: Path):
    root = _instantiate_fixture_repo(tmp_path, 'valid_repo')
    _copy_phase_triplet(root, '01', '02')
    owner, data = _owner('phase_catalog'), _inputs(root)
    extra = deepcopy(data['build']['phase_sequence'][0])
    extra['phase_id'] = 'P02'
    data['build']['phase_sequence'].append(extra)
    with pytest.raises(owner.GovernanceValidationError, match='same phase ids'):
        _catalog(root, owner, data, {})


def test_late_active_owner_rejects_stale_memory_path(tmp_path: Path):
    root = _instantiate_fixture_repo(tmp_path, 'valid_repo')
    owner, data, cache = _owner('phase_catalog'), _inputs(root), {}
    paths = _catalog(root, owner, data, cache)
    data['memory']['environment_facts']['active_artifacts']['active_phase_log'] = 'phases/stale-log.yml'
    with pytest.raises(owner.GovernanceValidationError, match=r'MEMORY\.yml active_artifacts.active_phase_log'):
        owner._validate_active_phase(root, cache, data['ledger'], data['memory'], paths)


def test_early_catalog_owner_rejects_distinct_phase_populations(tmp_path: Path):
    root = _instantiate_fixture_repo(tmp_path, 'valid_repo')
    owner, data = _owner('authored_phase_state'), _inputs(root)
    extra = deepcopy(data['build']['phase_sequence'][0])
    extra['phase_id'] = 'P02'
    data['build']['phase_sequence'].append(extra)
    (root / 'plans/build-plan.yml').write_text(yaml.safe_dump(data['build'], sort_keys=False))
    with pytest.raises(owner.AuthoredPhaseStateError, match='same phase identities'):
        owner.validate_authored_phase_state(root)


def test_early_memory_owner_rejects_stale_memory_path(tmp_path: Path):
    root = _instantiate_fixture_repo(tmp_path, 'valid_repo')
    owner, data = _owner('authored_phase_state'), _inputs(root)
    data['memory']['environment_facts']['active_artifacts']['active_phase_log'] = 'phases/stale-log.yml'
    (root / 'MEMORY.yml').write_text(yaml.safe_dump(data['memory'], sort_keys=False))
    with pytest.raises(owner.AuthoredPhaseStateError, match='MEMORY active_artifacts.active_phase_log'):
        owner.validate_authored_phase_state(root)
