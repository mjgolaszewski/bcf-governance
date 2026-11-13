"""Actual constructor writes require allocation and caller-context evidence."""
from __future__ import annotations

from types import MemberDescriptorType

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


@pytest.mark.parametrize("source", [
    "class Record:\n def __init__(self,value):\n  self.value=value\ndef read():\n return Record(7).value\n",
    "class Parent:\n def __init__(self,value):\n  self.value=value\nclass Record(Parent):pass\ndef read():\n return Record(7).value\n",
    "class Record(ValueError):pass\ndef read():\n Record('ok')\n return 7\n",
    "class Record(ValueError):\n def __init__(self,message):\n  super().__init__(message)\n  self.value=7\ndef read():\n return Record('ok').value\n",
])
def test_literal_source_initializer_owns_only_its_new_receiver(tmp_path, source):
    path, facts = inventory(tmp_path, source)
    assert witness(path) == [7, 7]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


def test_initializer_global_effect_is_not_hidden_by_fresh_receiver(tmp_path):
    path, facts = inventory(tmp_path, """
        EVENTS=[]
        class Record:
            def __init__(self):
                EVENTS.append(7)
                self.value=7
        def read():
            Record()
            return len(EVENTS)
    """)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_initializer_escape_port_does_not_authorize_later_retained_write(tmp_path):
    path, facts = inventory(tmp_path, """
        KEPT=[]
        def retain(value):
            KEPT.append(value)
        class Record:
            def __init__(self):
                retain(self)
                self.value=7
        def read():
            Record()
            return KEPT[-1].value
    """)
    assert witness(path) == [7, 7]
    operation = {**OPERATION, "allowed_mutation_ports": ["consumer.py::retain"]}
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(operation, "consumer.py::read", facts)


def test_explicit_initializer_on_borrowed_receiver_remains_a_write(tmp_path):
    path, facts = inventory(tmp_path, """
        class Record:
            def __init__(self,value):
                self.value=value
        STATE=Record(0)
        def read():
            before=STATE.value
            Record.__init__(STATE,7)
            return before,STATE.value
    """)
    assert witness(path) == [[0, 7], [7, 7]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("declaration", [
    "class Parent:\n def __new__(cls):\n  EVENTS.append(7)\n  return object.__new__(cls)\nclass Record(Parent):pass\n",
    "class Meta(type):\n def __call__(cls,*args,**kwargs):\n  EVENTS.append(7)\n  return super().__call__(*args,**kwargs)\nclass Parent(metaclass=Meta):pass\nclass Record(Parent):pass\n",
])
def test_inherited_allocator_or_metaclass_does_not_get_a_fresh_frame(tmp_path, declaration):
    path, facts = inventory(tmp_path, "EVENTS=[]\n" + declaration + "def read():\n Record()\n return len(EVENTS)\n")
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("declaration,expression", [
    ("def __iter__(self):\n  EVENTS.append(7)\n  return iter([7])", "[value for value in PROBE]"),
    ("def __hash__(self):\n  EVENTS.append(7)\n  return 7", "{PROBE:7}"),
])
def test_fresh_receiver_does_not_close_unknown_input_protocols(tmp_path, declaration, expression):
    source = "EVENTS=[]\nclass Probe:\n " + declaration + "\nPROBE=Probe()\nclass Record:\n def __init__(self):\n  ignored=" + expression + "\ndef read():\n Record()\n return len(EVENTS)\n"
    path, facts = inventory(tmp_path, source)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("signature", ["def __del__(self, extra): pass", "async def __del__(self): pass"])
def test_invalid_noop_finalizer_is_not_pure(tmp_path, signature):
    path, facts = inventory(tmp_path, "class Record:\n " + signature + "\ndef read():\n Record()\n return 0\n")
    assert witness(path) == [0, 0]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_class_alias_cannot_replace_fresh_allocation(tmp_path):
    path, facts = inventory(tmp_path, """
        class Record:
            def __init__(self,value): self.value=value
        EXISTING=object.__new__(Record)
        EXISTING.value=0
        Alias=Record
        Alias.__new__=staticmethod(lambda cls,*args:EXISTING)
        def read():
            before=EXISTING.value
            Record(7)
            return before,EXISTING.value
    """)
    assert witness(path) == [[0, 7], [7, 7]]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_native_initializer_precedes_later_source_mixin(tmp_path):
    path, facts = inventory(tmp_path, """
        EVENTS=[]
        class Mixin:
            def __init__(self): EVENTS.append(7)
        class Record(ValueError, Mixin): pass
        def read():
            Record()
            return len(EVENTS)
    """)
    assert witness(path) == [0, 0]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


@pytest.mark.parametrize("argument", ["source()", "value"])
def test_source_produced_scalar_reaches_initializer_frame(tmp_path, argument):
    path, facts = inventory(tmp_path, """
        def source(): return 'ok'
        class Record:
            def __init__(self,value):
                if not value: raise ValueError('empty')
                self.value=value
        def read():
            value=source()
            return Record(ARGUMENT).value
    """.replace('ARGUMENT', argument))
    assert witness(path) == ['ok', 'ok']
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


def test_unknown_producer_truth_callback_is_not_a_scalar_annotation(tmp_path):
    path, facts = inventory(tmp_path, """
        EVENTS=[]
        class Probe:
            def __bool__(self):
                EVENTS.append(7)
                return True
        PROBE=Probe()
        def source() -> str: return PROBE
        class Record:
            def __init__(self,value):
                if not value: raise ValueError('empty')
                self.value=value
        def read():
            Record(source())
            return len(EVENTS)
    """)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize('escaped', [False, True])
def test_constructor_argument_ownership_cannot_survive_a_later_escape_argument(tmp_path, escaped):
    path, facts = inventory(tmp_path, """
        KEPT=[]
        def retain(value):
            KEPT.append(value)
            return 0
        class Record:
            def __init__(self,box,unused): box.append(7)
        def read():
            box=[]
            Record(box,SECOND)
            return len(box)
    """.replace('SECOND', 'retain(box)' if escaped else '0'))
    assert witness(path) == [1, 1]
    operation = {**OPERATION, 'allowed_mutation_ports': ['consumer.py::retain'] if escaped else []}
    if escaped:
        with pytest.raises(SemanticOperationEffectError):
            validate_operation_effects(operation, 'consumer.py::read', facts)
    else:
        assert validate_operation_effects(operation, 'consumer.py::read', facts) == (0, 0)


@pytest.mark.parametrize('shadowed', [False, True])
def test_exact_runtime_string_admission_precedes_unknown_protocol(tmp_path, shadowed):
    source="""
        EVENTS=[]
        class Probe:
            def __bool__(self):
                EVENTS.append(7)
                return True
        PROBE=Probe()
        SHADOW
        class Record:
            def __init__(self,value):
                if type(value) is not str: raise ValueError('string required')
                if not value: raise ValueError('empty')
                self.value=value
        def read():
            try: Record(PROBE)
            except ValueError: pass
            return len(EVENTS)
    """.replace('SHADOW', 'def type(value): return str' if shadowed else '')
    path,facts=inventory(tmp_path,source)
    assert witness(path) == ([1,2] if shadowed else [0,0])
    if shadowed:
        with pytest.raises(SemanticOperationEffectError):
            validate_operation_effects(OPERATION,'consumer.py::read',facts)
    else:
        assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


def test_github_client_rejects_protocol_objects_before_inspecting_them():
    from bcf_governance.tooling.ci_github_api import GitHubAPI, GitHubAPIError
    events=[]
    class Probe(str):
        def __bool__(self):
            events.append('bool')
            return True
        def startswith(self,*args):
            events.append('startswith')
            return True
        def rstrip(self,*args):
            events.append('rstrip')
            return 'https://example.test'
    with pytest.raises(GitHubAPIError):
        GitHubAPI(token=Probe('token'))
    with pytest.raises(GitHubAPIError):
        GitHubAPI(token='token',api_url=Probe('https://example.test'))
    assert events==[]
    GitHubAPI(token='token',api_url='https://example.test/')


@pytest.mark.parametrize('conversion', ['', '!s', '!r'])
def test_message_formatting_callback_is_not_hidden_by_string_result(tmp_path,conversion):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'ok'
            def __str__(self):
                EVENTS.append(7)
                return 'ok'
            def __repr__(self):
                EVENTS.append(7)
                return 'ok'
        PROBE=Probe()
        class Error(ValueError):pass
        def read():
            Error(f'message {PROBECONVERSION}')
            return len(EVENTS)
    """.replace('PROBECONVERSION','PROBE'+conversion))
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_private_literal_dictionary_keys_produce_a_safe_message(tmp_path):
    path,facts=inventory(tmp_path,"""
        class Error(ValueError):pass
        def read():
            supplied={'first':object(), 'second':object()}
            for key,value in supplied.items():
                Error(f'bad {key}')
            return 7
    """)
    assert witness(path)==[7,7]
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


def test_direct_formatted_output_does_not_hide_callback_writes(tmp_path):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'ok'
        PROBE=Probe()
        def read():
            message=f'{PROBE}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


@pytest.mark.parametrize('inspects', [False, True])
def test_borrowed_input_identity_is_not_a_constructor_callback(tmp_path, inspects):
    source="""
        STATE=[]
        class Record:
            def __init__(self,value):
                ACTION
                self.value=value
        def read():
            Record(STATE)
            return len(STATE)
    """.replace('ACTION','value.append(7)' if inspects else 'pass')
    path,facts=inventory(tmp_path,source)
    assert witness(path)==([1,2] if inspects else [0,0])
    if inspects:
        with pytest.raises(SemanticOperationEffectError):
            validate_operation_effects(OPERATION,'consumer.py::read',facts)
    else:
        assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


def test_caught_custom_exception_string_callback_remains_an_effect(tmp_path):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Error(ValueError):
            def __str__(self):
                EVENTS.append(7)
                return 'message'
        class Wrapper(ValueError):pass
        def read():
            try: raise Error('bad')
            except Error as exc: Wrapper(str(exc))
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


@pytest.mark.parametrize('kind',['subclass','argument'])
def test_caught_exception_native_or_inherited_formatting_keeps_real_callbacks(tmp_path,kind):
    source="""
        EVENTS=[]
        class Probe:
            def __str__(self):
                EVENTS.append(7)
                return 'message'
        class Error(ValueError):pass
        class Derived(Error):
            def __str__(self):
                EVENTS.append(7)
                return 'message'
        class Wrapper(ValueError):pass
        def read():
            try: raise EXPRESSION
            except Error as exc: Wrapper(str(exc))
            return len(EVENTS)
    """.replace('EXPRESSION', "Derived('bad')" if kind=='subclass' else 'Error(Probe())')
    path,facts=inventory(tmp_path,source)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_imported_caught_exception_string_callback_keeps_source_identity(tmp_path):
    from bcf_governance.tooling.semantic_ownership_inventory import (
        discover_python_source,
        resolve_python_imports,
    )
    dependency=tmp_path/'errors.py'
    dependency.write_text("EVENTS=[]\nclass Error(ValueError):\n def __str__(self):\n  EVENTS.append(7)\n  return 'message'\n")
    path=tmp_path/'consumer.py'
    path.write_text("from errors import Error,EVENTS\nclass Wrapper(ValueError):pass\ndef read():\n try: raise Error('bad')\n except Error as exc: Wrapper(str(exc))\n return len(EVENTS)\n")
    facts=resolve_python_imports(tmp_path,discover_python_source(tmp_path,[path,dependency]),('.',))
    assert _module_witness(tmp_path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


@pytest.mark.parametrize('error',[ValueError('message'),RuntimeError(7,'message'),OSError(2,'missing','file.txt')])
def test_native_exception_message_preserves_native_diagnostics(error):
    from bcf_governance.tooling.exception_messages import native_exception_message
    assert native_exception_message(error)==str(error)


@pytest.mark.parametrize('kind',['override','argument','property','metaclass'])
def test_native_exception_message_never_executes_custom_protocols(kind):
    from bcf_governance.tooling.exception_messages import native_exception_message
    events=[]
    class Probe:
        def __str__(self):
            events.append('str')
            return 'message'
        def __repr__(self):
            events.append('repr')
            return 'message'
    class Error(ValueError):
        def __str__(self):
            events.append('override')
            return 'message'
    class PropertyError(ValueError):
        @property
        def args(self):
            events.append('property')
            return (Probe(),)
    class Meta(type):
        def __getattribute__(cls,name):
            if name=='__str__':
                events.append('metaclass')
            return super().__getattribute__(name)
    class MetaError(ValueError,metaclass=Meta):
        pass
    error={'override':Error('message'),'argument':ValueError(Probe()),
           'property':PropertyError('message'),'metaclass':MetaError('message')}[kind]
    if kind in {'override','argument'}:
        with pytest.raises(TypeError):
            native_exception_message(error)
    else:
        assert native_exception_message(error)=='message'
    assert events==[]


def _module_witness(root):
    import json
    import subprocess
    import sys
    script="import sys,json;sys.path.insert(0,"+repr(str(root))+");import consumer;print(json.dumps([consumer.read(),consumer.read()]))"
    result=subprocess.run([sys.executable,'-I','-B','-c',script],capture_output=True,text=True,check=True,timeout=10)
    return json.loads(result.stdout)


def test_actual_native_message_boundary_source_is_readonly(tmp_path):
    from pathlib import Path

    from bcf_governance.tooling.semantic_ownership_inventory import (
        discover_python_source,
        resolve_python_imports,
    )
    helper=tmp_path/'helper.py'
    helper.write_bytes((Path(__file__).parents[1]/'bcf_governance/tooling/exception_messages.py').read_bytes())
    path=tmp_path/'consumer.py'
    path.write_text("from helper import native_exception_message\ndef read():\n return native_exception_message(ValueError('message'))\n")
    facts=resolve_python_imports(tmp_path,discover_python_source(tmp_path,[path,helper]),('.',))
    assert _module_witness(tmp_path)==['message','message']
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


@pytest.mark.parametrize('scalar,typename', [("'ok'",'str'),('7','int')])
def test_dominating_native_admission_proves_a_later_formatted_value(tmp_path,scalar,typename):
    path,facts=inventory(tmp_path,"""
        def source(): return SCALAR
        def read():
            try: pass
            except ValueError: pass
            value=source()
            if type(value) is not TYPE: raise ValueError('native value required')
            return f'value {value}'
    """.replace('SCALAR',scalar).replace('TYPE',typename))
    assert witness(path)==(['value ok','value ok'] if typename=='str' else ['value 7','value 7'])
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


@pytest.mark.parametrize('kind',['conditional','rebound','shadowed','global'])
def test_scalar_admission_cannot_escape_its_binding_or_dominance(tmp_path,kind):
    prefix="EVENTS=[]\nclass Probe:\n def __format__(self,spec):\n  EVENTS.append(7)\n  return 'message'\nPROBE=Probe()\n"
    if kind=='conditional':
        body=" value=PROBE\n if False:\n  if type(value) is not str: raise ValueError('native')\n return f'{value}'\n"
    elif kind=='rebound':
        body=" value='native'\n if type(value) is not str: raise ValueError('native')\n value=PROBE\n return f'{value}'\n"
    elif kind=='shadowed':
        prefix+="def type(value):return str\n"
        body=" value=PROBE\n if type(value) is not str: raise ValueError('native')\n return f'{value}'\n"
    else:
        prefix+="value='native'\ndef replace():\n global value\n value=PROBE\ndef reset():\n global value\n value='native'\n"
        body=" if type(value) is not str: raise ValueError('native')\n replace()\n return f'{value}'\n"
    reader="def read():\n "+('reset()\n ' if kind=='global' else '')+"format_value()\n return len(EVENTS)\n"
    path,facts=inventory(tmp_path,prefix+'def format_value():\n'+body+reader)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects({**OPERATION, 'allowed_mutation_ports': ['consumer.py::reset','consumer.py::replace'] if kind=='global' else []},'consumer.py::read',facts)


@pytest.mark.parametrize('field',[name for name,value in vars(OSError).items() if type(value) is MemberDescriptorType])
def test_native_os_message_rejects_protocol_objects_in_actual_storage(field):
    from bcf_governance.tooling.exception_messages import native_exception_message
    events=[]
    class Probe:
        def __str__(self):
            events.append('str')
            return 'message'
        def __repr__(self):
            events.append('repr')
            return 'message'
    error=OSError(2,'missing','file.txt')
    setattr(error,field,Probe())
    with pytest.raises(TypeError):
        native_exception_message(error)
    assert events==[]



def test_async_initializer_does_not_get_a_synchronous_fresh_receiver_contract(tmp_path):
    import subprocess
    import sys
    path,facts=inventory(tmp_path,"""
        class Record:
            async def __init__(self): pass
        def read():
            try: Record()
            except TypeError: pass
            return 7
    """)
    script="import runpy;n=runpy.run_path("+repr(str(path))+");print(n['read']())"
    result=subprocess.run([sys.executable,'-I','-Walways::RuntimeWarning','-c',script],capture_output=True,text=True,check=True,timeout=10)
    assert result.stdout.strip()=='7' and 'was never awaited' in result.stderr
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


@pytest.mark.parametrize('expression', ["'ok'",'None'])
def test_nullable_native_scalar_admission_preserves_both_values(tmp_path,expression):
    path,facts=inventory(tmp_path,"""
        def read():
            try: pass
            except ValueError: pass
            value=EXPRESSION
            if value is not None and type(value) is not str: raise ValueError('native')
            return f'value {value}'
    """.replace('EXPRESSION',expression))
    assert witness(path)==(['value ok','value ok'] if expression!="None" else ['value None','value None'])
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


@pytest.mark.parametrize('condition',[
    "type(value) is not str and other is not None",
    "type(value) is not str and value is None",
    "type(value) is not str and False",
])
def test_nullable_guard_requires_the_same_value_and_a_complete_native_admission(tmp_path,condition):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'message'
        PROBE=Probe()
        def read():
            value=PROBE
            other=None
            if CONDITION: raise ValueError('native')
            result=f'value {value}'
            return len(EVENTS)
    """.replace('CONDITION',condition))
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_loop_local_scalar_guard_dominates_nested_format(tmp_path):
    path,facts=inventory(tmp_path,"""
        def read():
            for value in ('native',):
                if type(value) is not str: raise ValueError('native')
                try: result=f'value {value}'
                except ValueError: raise
            return result
    """)
    assert witness(path)==['value native','value native']
    assert validate_operation_effects(OPERATION,'consumer.py::read',facts)==(0,0)


def test_conditional_scalar_guard_does_not_dominate_sibling_format(tmp_path):
    path,facts=inventory(tmp_path,"""
        EVENTS=[]
        class Probe:
            def __format__(self,spec):
                EVENTS.append(7)
                return 'message'
        PROBE=Probe()
        def read():
            for value in (PROBE,):
                if False:
                    if type(value) is not str: raise ValueError('native')
                result=f'value {value}'
            return len(EVENTS)
    """)
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,'consumer.py::read',facts)


def test_action_pin_native_boundary_preserves_pins_and_rejects_protocols():
    from bcf_governance.tooling.ci_github_actions import ACTION_PINS, action_pin
    events=[]
    class Foreign(str):
        def __hash__(self):
            events.append('hash')
            return super().__hash__()
        def __eq__(self,other):
            events.append('eq')
            return super().__eq__(other)
        def __format__(self,spec):
            events.append('format')
            return 'foreign'
    assert action_pin('checkout')==ACTION_PINS['checkout']
    assert action_pin('checkout',ACTION_PINS['checkout'])==ACTION_PINS['checkout']
    with pytest.raises(ValueError):
        action_pin(Foreign('checkout'))
    with pytest.raises(ValueError):
        action_pin('checkout',Foreign('foreign'))
    assert events==[]
    with pytest.raises(ValueError,match='unknown GitHub action pin: missing'):
        action_pin('missing')
    with pytest.raises(ValueError,match='unregistered immutable source'):
        action_pin('checkout','foreign')
