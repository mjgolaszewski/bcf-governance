"""Declared inventory schemas reject deterministic defects before collection."""
from __future__ import annotations

import json
import sys

import pytest
import yaml

from bcf_governance.tooling import test_manifests as owner
from tests.test_test_manifests import reference_repo


@pytest.fixture
def schema_reference_repo(reference_repo):
    policy = reference_repo / 'governance/gate-contracts.yml'
    payload = yaml.safe_load(policy.read_text())
    descriptor = payload['gates']['test']['evidence']['test_contract']['reference_inventories'][0]
    descriptor.update(format='implementation_slice_bindings.v2', schema='inventory.schema.json')
    policy.write_text(yaml.safe_dump(payload))
    schema = {'type': 'object', 'required': ['implementation_slices'],
              'additionalProperties': False,
              'properties': {'implementation_slices': {'type': 'object'}}}
    (reference_repo / 'inventory.schema.json').write_text(json.dumps(schema))
    return reference_repo


def test_schema_bound_inventory_preserves_exact_reference_ownership(schema_reference_repo):
    result = owner.validate_authored_test_reference_inventories(
        schema_reference_repo, python_executable=sys.executable,
    )
    assert result == {'authority': False, 'execution_qualified': False,
                      'inventories_checked': 1, 'nodes_checked': 2}


@pytest.mark.parametrize('defect', ['unexpected-field', 'missing-required'])
def test_whole_inventory_schema_failure_precedes_collection(
    schema_reference_repo, monkeypatch, defect,
):
    path = schema_reference_repo / 'references.yml'
    payload = yaml.safe_load(path.read_text())
    if defect == 'unexpected-field':
        payload['unmodeled_authority'] = True
    else:
        del payload['implementation_slices']
    path.write_text(yaml.safe_dump(payload))
    monkeypatch.setattr(owner, 'collect_selector_maps', lambda *a, **k: pytest.fail(
        'collected inventory before whole-schema validation',
    ))
    with pytest.raises(owner.TestManifestError, match='reference inventory schema violation'):
        owner.validate_authored_test_reference_inventories(
            schema_reference_repo, python_executable=sys.executable,
        )


@pytest.mark.parametrize('defect', ['missing', 'invalid-json', 'invalid-schema',
                                  'remote-ref', 'file-ref', 'symlink', 'escape'])
def test_invalid_inventory_schema_precedes_collection(schema_reference_repo, monkeypatch, defect):
    path = schema_reference_repo / 'inventory.schema.json'
    if defect == 'missing':
        path.unlink()
    elif defect == 'invalid-json':
        path.write_text('{')
    elif defect == 'invalid-schema':
        path.write_text(json.dumps({'type': 'unknown-type'}))
    elif defect in ('remote-ref', 'file-ref'):
        path.write_text(json.dumps({'$ref': 'https://invalid.example/schema.json'
                                   if defect == 'remote-ref' else 'other.schema.json'}))
    elif defect == 'symlink':
        path.rename(schema_reference_repo / 'real.schema.json')
        path.symlink_to('real.schema.json')
    else:
        policy = schema_reference_repo / 'governance/gate-contracts.yml'
        payload = yaml.safe_load(policy.read_text())
        descriptor = payload['gates']['test']['evidence']['test_contract']['reference_inventories'][0]
        descriptor['schema'] = '../inventory.schema.json'
        policy.write_text(yaml.safe_dump(payload))
    monkeypatch.setattr(owner, 'collect_selector_maps', lambda *a, **k: pytest.fail(
        'collected inventory before schema admission',
    ))
    with pytest.raises(owner.TestManifestError, match='reference inventory schema'):
        owner.validate_authored_test_reference_inventories(
            schema_reference_repo, python_executable=sys.executable,
        )


def test_inventory_schema_movement_during_collection_blocks(schema_reference_repo, monkeypatch):
    def collect(*args, **kwargs):
        path = schema_reference_repo / 'inventory.schema.json'
        path.write_text(path.read_text() + '\n')
        return {'test': owner.PytestSelectorMap('test', (
            ('tests.test_sample::test_one', 'tests/test_sample.py::test_one'),
            ('tests.test_sample::test_two', 'tests/test_sample.py::test_two'),
        ))}
    monkeypatch.setattr(owner, 'collect_selector_maps', collect)
    with pytest.raises(owner.TestManifestError, match='reference inventory.*changed'):
        owner.validate_authored_test_reference_inventories(
            schema_reference_repo, python_executable=sys.executable,
        )
