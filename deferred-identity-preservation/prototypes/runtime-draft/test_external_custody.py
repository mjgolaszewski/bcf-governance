"""Actual live-process ancestry controls; no external service deployment claimed."""
from __future__ import annotations

import importlib
import multiprocessing
import os
from pathlib import Path
import sys
import types

import pytest

PACKAGE = '_bcf_owner_runtime'
if PACKAGE not in sys.modules:
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(Path(__file__).parent)]
    sys.modules[PACKAGE] = package
owner = importlib.import_module(PACKAGE + '.evidence_execution_owner')
external = importlib.import_module(PACKAGE + '.evidence_external_custody')
keeper = importlib.import_module(PACKAGE + '.evidence_lease_keeper')


def child_control(connection, budget):
    current = owner.ProcessIdentity.observe(os.getpid())
    try:
        external.require_external_custodian(current, budget)
    except owner.OwnerAdmissionError:
        connection.send('refused')
    else:
        connection.send('accepted')
    connection.recv()


def test_budget_descendant_is_not_independent_custody():
    parent, child = multiprocessing.Pipe()
    budget = owner.ProcessIdentity.observe(os.getpid())
    process = multiprocessing.Process(target=child_control, args=(child, budget))
    process.start()
    try:
        assert parent.poll(5) and parent.recv() == 'refused'
        parent.send('close')
        process.join(5)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
        process.join(5)
        parent.close()
        child.close()


def idle(connection):
    connection.send(os.getpid())
    connection.recv()


def test_actual_parent_can_be_outside_its_later_budget_child():
    parent, child = multiprocessing.Pipe()
    process = multiprocessing.Process(target=idle, args=(child,))
    process.start()
    try:
        assert parent.poll(5)
        budget = owner.ProcessIdentity.observe(parent.recv())
        external.require_external_custodian(owner.ProcessIdentity.observe(os.getpid()), budget)
        parent.send('close')
        process.join(5)
        assert process.exitcode == 0
        with pytest.raises(owner.OwnerAdmissionError):
            external.require_external_custodian(owner.ProcessIdentity.observe(os.getpid()), budget)
    finally:
        if process.is_alive():
            process.terminate()
        process.join(5)
        parent.close()
        child.close()


def test_budget_owner_cannot_call_itself_an_external_keeper():
    actual = owner.ProcessIdentity.observe(os.getpid())
    with pytest.raises(owner.OwnerAdmissionError, match='inside the consuming native budget'):
        external.require_external_custodian(actual, actual)


def test_keeper_cannot_be_constructed_without_outside_budget_registration(tmp_path):
    with pytest.raises(owner.OwnerAdmissionError, match='external budget ownership registration'):
        keeper.ExecutionLeaseKeeper(lease_descriptors=(), context_digest='a' * 64,
            evidence_root=tmp_path, timeout_seconds=1, cleanup_seconds=1)
