"""Actual source algorithms, drift refusals, and separation from effect authority."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)
from tests.prototypes.semantic_exact.inventory import module_inputs
from tests.prototypes.semantic_exact.semantic_python_custody_algorithms import (
    NativeCustodyAlgorithms,
)
from tests.prototypes.semantic_exact.semantic_python_exact_values import ExactProtocolRefusal

FIXTURES = Path(__file__).parent / 'fixtures/source_custody_algorithms'
ROOT = 'scripts/contexts/runtime_storage/infrastructure/persistence/'


def facts(tmp_path, mutation=None, renamed=False):
    manifest = json.loads((FIXTURES / 'manifest.json').read_text())
    files = []
    for name, row in manifest['files'].items():
        source = (FIXTURES / row['fixture']).read_bytes()
        assert hashlib.sha256(source).hexdigest() == row['sha256']
        text = source.decode()
        if mutation is not None and name == mutation[0]:
            assert mutation[1] in text
            text = text.replace(mutation[1], mutation[2])
        if renamed:
            for before, after in [('await_custody_task', 'drain_work'), ('await_file_task', 'wait_work'),
                                  ('run_file_io', 'execute_work'), ('held_file_context', 'lease_work'), ('task', 'pending')]:
                text = re.sub(r'\b' + before + r'\b', after, text)
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        files.append(path)
    return module_inputs(resolve_python_imports(tmp_path, discover_python_source(tmp_path, files), ('.',)), tmp_path)


@pytest.mark.parametrize('renamed', [False, True])
def test_real_complete_acquisition_and_release_algorithms_bind_through_actual_imports(tmp_path, renamed):
    proof = NativeCustodyAlgorithms(facts(tmp_path, renamed=renamed))
    symbol = ROOT + 'async_file_custody.py::' + ('lease_work' if renamed else 'held_file_context')
    evidence = proof.file_context(symbol)
    assert evidence.algorithm == 'observable-acquire-and-drained-exit-v1'
    worker = evidence.dependencies[0]
    drain = worker.dependencies[0]
    assert drain.algorithm == 'drain-native-task-through-repeated-cancellation-v1'
    assert 'cancelled-is-None' in drain.required_inputs
    assert 'exact-native-asyncio-task' in drain.required_inputs
    assert not evidence.confers_effect_permission
    assert not worker.confers_effect_permission and not drain.confers_effect_permission
    assert not evidence.header_execution_qualified


@pytest.mark.parametrize('mutation', [
    ('scripts/shared/task_custody.py', 'while not task.done():', 'while False:'),
    ('scripts/shared/task_custody.py', 'await asyncio.shield(task)\n            except', 'await task\n            except'),
    ('scripts/shared/task_custody.py', 'if task.done() and not task.cancelled():', 'if task.done():'),
    ('scripts/shared/task_custody.py', 'cancelled: Event | None = None', 'cancelled: Event | None = Event()'),
    (ROOT + 'async_io.py', 'return await await_file_task(task)', 'return await task'),
    (ROOT + 'async_io.py', 'asyncio.to_thread(operation, *args, **kwargs)', 'operation(*args, **kwargs)'),
    (ROOT + 'async_file_custody.py', 'if entered.is_set():', 'if False:'),
    (ROOT + 'async_file_custody.py', 'context.__exit__, None, None, None', 'context.__enter__'),
    (ROOT + 'async_file_custody.py', 'finally:\n        await release()', 'finally:\n        pass'),
])
def test_any_incomplete_drain_acquisition_or_exit_is_refused(tmp_path, mutation):
    proof = NativeCustodyAlgorithms(facts(tmp_path, mutation=mutation))
    with pytest.raises(ExactProtocolRefusal):
        proof.file_context(ROOT + 'async_file_custody.py::held_file_context')


def test_known_late_native_member_rebinding_is_not_a_primitive(tmp_path):
    mutation = ('scripts/shared/task_custody.py', 'from threading import Event',
                'from threading import Event\nasyncio.shield = replacement')
    proof = NativeCustodyAlgorithms(facts(tmp_path, mutation=mutation))
    with pytest.raises(ExactProtocolRefusal):
        proof.task_drain('scripts/shared/task_custody.py::await_custody_task')
