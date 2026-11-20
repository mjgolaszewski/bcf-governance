"""The actual consuming boundary owns ordinary parsed string values."""
import json

import pytest

from bcf_governance.tooling import ci_commands
from tests.postparsed_cli_guard_support import exercise

MODES = ['default_word', 'converter_word', 'converter_effect', 'custom_list', 'custom_tuple',
    'mutated_list', 'native_list', 'native_tuple']


@pytest.mark.parametrize('mode', MODES)
def test_actual_postparsed_cli_boundary(mode):
    result = exercise(ci_commands, mode)
    assert result['authority'] is result['runtime_context_qualified'] is False
    print('postparse-observation:' + json.dumps(result, sort_keys=True))
