"""Concrete native frame evidence is distinct from source/runtime qualification."""
import json

import pytest

from bcf_governance.tooling import ci_commands
from tests.cli_value_origins_support import exercise


@pytest.mark.parametrize('mode', ['ordinary', 'invalid', 'ownership', 'constructor', 'parser'])
def test_actual_cli_parser_and_value_origins(mode):
    result = exercise(ci_commands, mode)
    assert result['authority'] is result['runtime_context_qualified'] is False
    assert result['qualification_port_calls'] == {'invalid': 0, 'parser': 0, 'ownership': 2}.get(mode, 1)
    print("value-origin-observation:" + json.dumps(result, sort_keys=True))
