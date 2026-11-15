"""Exact shallow types and guarded borrowed data never create effect waivers."""
from __future__ import annotations

import pytest

from tests.prototypes.semantic_exact.inventory import module_inputs
from tests.prototypes.semantic_exact.semantic_python_exact_source import ExactSourceBodies
from tests.prototypes.semantic_exact.semantic_python_exact_values import (
    BOTTOM,
    INT,
    STR,
    UNKNOWN,
    ExactProtocolRefusal,
    ExactState,
    ExactValue,
    callback_free,
    union,
)
from tests.test_consumer_callback_contracts import inventory


def check(tmp_path, source, arguments=()):
    _, facts = inventory(tmp_path, source)
    proof = ExactSourceBodies(module_inputs(facts, tmp_path))
    result, state, _ = proof.call('consumer.py::read', list(arguments), {})
    return state.resolve(result), proof


def test_guarded_rows_prove_reads_without_owning_borrowed_children(tmp_path):
    result, _ = check(tmp_path, '''
        def read(rows):
            if type(rows) is not list: raise ValueError('rows')
            if any(type(row) is not dict or any(type(key) is not str for key in row) for row in rows):
                raise ValueError('keys')
            result=[]
            for row in rows:
                result.append(row.get('name'))
            return len(result)
    ''', [UNKNOWN])
    assert result == INT


@pytest.mark.parametrize('guard', [
    "if type(row) is not dict: raise ValueError('row')",
    "if isinstance(row, dict): pass",
])
def test_mapping_kind_without_exact_key_admission_cannot_prove_get(tmp_path, guard):
    with pytest.raises(ExactProtocolRefusal):
        check(tmp_path, 'def read(row):\n '+guard+"\n return row.get('name')\n", [UNKNOWN])


def test_borrowed_native_mapping_is_not_owned_for_writes(tmp_path):
    with pytest.raises(ExactProtocolRefusal, match='borrowed'):
        check(tmp_path, '''
            def read(row):
                if type(row) is not dict or any(type(key) is not str for key in row):
                    raise ValueError('row')
                row['name']='changed'
                return 7
        ''', [UNKNOWN])


def test_real_normal_return_guard_refines_caller_argument(tmp_path):
    result, proof = check(tmp_path, '''
        def require_count(value):
            if type(value) is not int or value < 0: raise ValueError('count')
            return value
        def read(value):
            require_count(value)
            return value+1
    ''', [UNKNOWN])
    assert result == INT
    assert 'consumer.py::require_count' in proof.checked


def test_frozen_slots_still_require_actual_field_guards(tmp_path):
    result, _ = check(tmp_path, '''
        from dataclasses import dataclass
        @dataclass(frozen=True, slots=True)
        class Record:
            value: str
        def read(record):
            if type(record) is not Record: raise ValueError('record')
            if type(record.value) is not str: raise ValueError('field')
            return record.value.casefold()
    ''', [UNKNOWN])
    assert result == STR


def test_annotation_alone_does_not_purify_frozen_field(tmp_path):
    with pytest.raises(ExactProtocolRefusal):
        check(tmp_path, '''
            from dataclasses import dataclass
            @dataclass(frozen=True, slots=True)
            class Record:
                value: str
            def read(record):
                if type(record) is not Record: raise ValueError('record')
                return record.value.casefold()
        ''', [UNKNOWN])


def test_field_alias_guard_refines_only_the_original_field(tmp_path):
    result, _ = check(tmp_path, '''
        from dataclasses import dataclass
        @dataclass(frozen=True, slots=True)
        class Record:
            value: object
        def read(record):
            if type(record) is not Record: raise ValueError('record')
            prefix=record.value
            if type(prefix) is not str: raise ValueError('prefix')
            return record.value.casefold()
    ''', [UNKNOWN])
    assert result == STR


def test_rebinding_alias_does_not_refine_its_replacement(tmp_path):
    with pytest.raises(ExactProtocolRefusal):
        check(tmp_path, '''
            def read(first, second):
                alias=first
                first=second
                if type(alias) is not str: raise ValueError('alias')
                return first.casefold()
        ''', [UNKNOWN, UNKNOWN])


def test_closed_literal_dictionary_views_are_native(tmp_path):
    result, _ = check(tmp_path, '''
        _COLUMNS={'accounts':'Accounts', 'transactions':'Transactions'}
        def read():
            result=[]
            for kind, field in _COLUMNS.items():
                result.append(kind.casefold())
            return len(result)
    ''')
    assert result == INT


def test_mutated_literal_is_not_treated_as_closed_native_data(tmp_path):
    with pytest.raises(ExactProtocolRefusal):
        check(tmp_path, '''
            _COLUMNS={'accounts':'Accounts'}
            def replace(value): _COLUMNS.update(value)
            def read(): return _COLUMNS.get('accounts')
        ''')


def test_unknown_context_never_receives_an_implicit_lifetime_waiver(tmp_path):
    with pytest.raises(ExactProtocolRefusal):
        check(tmp_path, '''
            async def read(provider):
                async with provider.open() as value:
                    return value
        ''', [UNKNOWN])


def test_heap_join_keeps_private_allocations_on_their_actual_paths():
    before = ExactState()
    left, right = before.copy(), before.copy()
    owned = left.allocate('left', ExactValue('list', (INT,)))
    joined = ExactState.join([left, right])
    assert joined.resolve(owned) == ExactValue('list', (INT,))
    assert not callback_free(ExactValue('dict', (STR, UNKNOWN)))
    assert union(BOTTOM, STR) == STR


def test_complete_immutable_tuple_validation_retains_real_field_facts(tmp_path):
    result, _ = check(tmp_path, '''
        from dataclasses import dataclass
        @dataclass(frozen=True, slots=True)
        class Entry:
            count: object
        def require_count(value):
            if type(value) is not int or value < 0: raise ValueError('count')
            return value
        def read(files):
            if type(files) is not tuple: raise ValueError('files')
            if any(type(entry) is not Entry for entry in files): raise ValueError('entry')
            for entry in files:
                require_count(entry.count)
            return files
    ''', [UNKNOWN])
    assert result.kind == 'tuple'
    assert result.children[0].member('count') == INT


@pytest.mark.parametrize('body', ['entry=other', 'continue', 'break'])
def test_replacement_or_unchecked_loop_path_does_not_validate_original_items(tmp_path, body):
    result, _ = check(tmp_path, '''
        from dataclasses import dataclass
        @dataclass(frozen=True, slots=True)
        class Entry:
            count: object
        def read(files, other):
            if type(files) is not tuple: raise ValueError('files')
            if any(type(entry) is not Entry for entry in files): raise ValueError('entry')
            for entry in files:
                BODY
            return files
    '''.replace('BODY', body), [UNKNOWN, UNKNOWN])
    assert result.children[0].member('count') == UNKNOWN


def test_classvar_alias_descriptor_is_not_a_native_storage_slot(tmp_path):
    with pytest.raises(ExactProtocolRefusal):
        check(tmp_path, '''
            from dataclasses import dataclass
            from typing import ClassVar as CV
            class Descriptor:
                def __get__(self, instance, owner):
                    emit_effect()
                    return 'foreign'
            @dataclass(frozen=True, slots=True)
            class Record:
                value: CV[object] = Descriptor()
            def read(record):
                if type(record) is not Record: raise ValueError('record')
                if type(record.value) is not str: raise ValueError('value')
                return record.value.casefold()
        ''', [UNKNOWN])


def test_unconsumed_generator_cannot_apply_a_future_heap_overwrite(tmp_path):
    with pytest.raises(ExactProtocolRefusal, match='deferred generator'):
        check(tmp_path, '''
            def replace(data):
                data['value']='native'
                return 0
            def read(value):
                data={'value':value}
                deferred=(replace(data) for unused in (0,))
                return f"{data['value']}"
        ''', [UNKNOWN])


def test_frozen_record_ordering_does_not_use_generated_equality_proof(tmp_path):
    with pytest.raises(ExactProtocolRefusal):
        check(tmp_path, '''
            from dataclasses import dataclass
            @dataclass(frozen=True, slots=True)
            class Record:
                value: str
                def __lt__(self, other):
                    emit_effect()
                    return True
            def read(left, right):
                if type(left) is not Record or type(right) is not Record: raise ValueError('record')
                if type(left.value) is not str or type(right.value) is not str: raise ValueError('value')
                return left < right
        ''', [UNKNOWN, UNKNOWN])


def test_actual_owned_ledger_uses_existing_body_proof_with_unknown_identity(tmp_path):
    from tests.test_semantic_key_admission import SOURCE
    result, proof = check(tmp_path, SOURCE + '''
def read(value):
    ledger=make_batch_export_identity_ledger(max_identities=7)
    ledger.observe_account(value)
    ledger.require_nonempty()
    return 7
''', [UNKNOWN])
    assert result.kind == 'int'
    assert 'consumer.py::BatchExportIdentityLedger.observe_account' in proof.checked

