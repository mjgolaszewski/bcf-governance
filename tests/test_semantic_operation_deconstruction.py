from __future__ import annotations

import json
from pathlib import Path

from bcf_governance.tooling import semantic_authority_contracts as contracts
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

ROOT = Path(__file__).parents[1]


def test_actual_public_operation_observations_match_pre_deconstruction_bytes():
    expected = (ROOT / 'audits/issue-394/operation-validator-before.json').read_bytes()
    inventory = discover_python_source(ROOT)
    observed = contracts.validate_application_operations(ROOT, inventory)
    assert len(observed) == 21
    assert json.dumps(observed, sort_keys=True, separators=(',', ':')).encode() == expected


def test_legacy_operation_validator_alias_has_one_implementation():
    from bcf_governance.tooling import semantic_authority_operations

    assert contracts._validate_operations is semantic_authority_operations._validate_operations


def test_extracted_validator_helpers_keep_resolved_source_owners():
    from bcf_governance.tooling.semantic_ownership_inventory import resolve_python_imports

    paths = [ROOT / 'bcf_governance/tooling/semantic_authority_contracts.py', ROOT / 'bcf_governance/tooling/semantic_authority_operations.py']
    inventory = resolve_python_imports(ROOT, discover_python_source(ROOT, files=paths, call_contracts_version='1.0'))
    function = next(row for row in inventory['functions'] if row['symbol'] == 'bcf_governance/tooling/semantic_authority_operations.py::_validate_operations')
    targets = {call['called_symbol'] for call in function['calls']}
    assert 'bcf_governance/tooling/semantic_authority_contracts.py::_schema' in targets
    assert 'bcf_governance/tooling/semantic_authority_contracts.py::_discover_population' in targets
