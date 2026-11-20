"""A real call cannot be redirected by changing inventory binding metadata."""
import pytest

from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError
from tests.test_independent_call_coverage import capture, consume, work

SOURCE = "STATE=0\ndef safe():\n    return 1\ndef mutate():\n    global STATE\n    STATE=1\n    return 1\ndef work():\n    return mutate()\nCOMMANDS={'work':work}\n"


@pytest.mark.parametrize("version", [None, "1.0"])
def test_redirected_callee_cannot_hide_native_witnessed_write(tmp_path, version):
    namespace = {}
    exec(compile(SOURCE, "runtime.py", "exec"), namespace)
    assert namespace['STATE'] == 0
    assert namespace['work']() == 1 and namespace['STATE'] == 1
    facts = capture(tmp_path, SOURCE, version)
    with pytest.raises(SemanticAuthorityError, match="undeclared write"):
        consume(tmp_path, facts)
    work(facts)['calls'][0]['called_symbol'] = 'runtime.py::safe'
    with pytest.raises(SemanticAuthorityError, match="Python source call binding"):
        consume(tmp_path, facts)


@pytest.mark.parametrize("version", [None, "1.0"])
def test_call_spelling_is_reconstructed_independently(tmp_path, version):
    facts = capture(tmp_path, version=version)
    assert consume(tmp_path, facts)
    work(facts)['calls'][0]['call_name'] = 'forged'
    with pytest.raises(SemanticAuthorityError, match="Python source call binding"):
        consume(tmp_path, facts)


@pytest.mark.parametrize("source", [
    "def helper():\n    return 1\ndef work():\n    return helper()\nCOMMANDS={'work':work}\n",
    "def hélper():\n    return 1\ndef work():\n    return hélper()\nCOMMANDS={'work':work}\n",
    "def helper():\n    return 1\ndef other(helper):\n    return helper()\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
    "def helper():\n    return 1\ndef other():\n    helper=lambda:1\n    return helper()\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
    "def helper():\n    return 1\ndef other():\n    def helper():\n        return 2\n    return helper()\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
    "from unknown import action as helper\ndef other():\n    return helper()\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
])
def test_ordinary_and_unresolved_source_scopes_stay_compatible(tmp_path, source):
    facts = capture(tmp_path, source)
    assert consume(tmp_path, facts)
