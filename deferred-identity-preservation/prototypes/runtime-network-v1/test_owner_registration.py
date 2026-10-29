"""Local registration/lifetime controls; no provider or JIT acceptance claim."""
from __future__ import annotations

import importlib
import multiprocessing
import os
from pathlib import Path
import socket
import sys
import time
import types

import pytest

PACKAGE = "_bcf_owner_runtime"
if PACKAGE not in sys.modules:
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(Path(__file__).parent)]
    sys.modules[PACKAGE] = package
owner = importlib.import_module(PACKAGE + ".evidence_execution_owner")
registration = importlib.import_module(PACKAGE + ".evidence_owner_registration")


def idle_owner(path, ready):
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        os.chmod(path, 0o600)
        listener.listen(1)
        ready.send(os.getpid())
        with listener.accept()[0] as connection:
            connection.recv(1)


@pytest.fixture
def installed(tmp_path, socket_root):
    children = []
    records = []
    for role in ("issuer", "custody"):
        endpoint = socket_root / (role + ".sock")
        parent, child = multiprocessing.Pipe(False)
        process = multiprocessing.Process(target=idle_owner, args=(str(endpoint), child))
        process.start()
        assert parent.poll(5)
        pid = parent.recv()
        parent.close()
        child.close()
        children.append(process)
        records.append(owner.OwnerRegistration(endpoint, owner.ProcessIdentity.observe(pid)))
    repo = tmp_path / "repository"
    repo.mkdir()
    scope = registration.RequiredOwnerScope(repo, frozenset({"runtime-smoke"}),
                                            frozenset({"direct-login"}),
                                            frozenset({"baseline"}),
                                            (registration.OwnerInvocationRoute("runtime-smoke", "direct-login", "baseline"),) * 2)
    binding = registration.InstalledOwnerBinding(
        owner.ProcessIdentity.observe(os.getpid()), scope, *records,
        time.monotonic() + 30, 2, 5)
    actual = registration.ActualInvocationIdentity(repo, "runtime-smoke", "direct-login", "baseline")
    yield binding, actual, children
    for process in children:
        if process.is_alive():
            process.terminate()
        process.join(5)
        assert not process.is_alive()


def test_missing_required_owner_refuses_without_provider_activity(tmp_path):
    actual = registration.ActualInvocationIdentity(tmp_path, "runtime-smoke", "direct-login", "baseline")
    with pytest.raises(owner.OwnerAdmissionError, match="unconfigured"):
        registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)
    assert registration.reserve_owner_invocation(actual, required=False, timeout_seconds=10) is None


def test_launcher_scope_requires_owner_independently_of_candidate_bit(installed):
    binding, actual, _ = installed
    with registration.bind_installed_execution_owner(binding):
        reserved = registration.reserve_owner_invocation(actual, required=False, timeout_seconds=10)
        assert reserved.binding is binding
        assert reserved.ordinal == 1
        assert reserved.deadline <= binding.absolute_deadline


def test_uncertain_reservations_consume_finite_aggregate_cap(installed):
    binding, actual, _ = installed
    with registration.bind_installed_execution_owner(binding):
        first = registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)
        second = registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)
        assert (first.ordinal, second.ordinal) == (1, 2)
        with pytest.raises(owner.OwnerAdmissionError, match="exhausted"):
            registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)


def test_owner_cannot_be_replaced_inside_live_controller_scope(installed):
    binding, _actual, _ = installed
    with registration.bind_installed_execution_owner(binding):
        with pytest.raises(owner.OwnerAdmissionError, match="replaced"):
            with registration.bind_installed_execution_owner(binding):
                raise AssertionError("replacement was admitted")


def test_wrong_actual_profile_refuses_before_owner_connection(installed):
    binding, actual, _ = installed
    wrong = registration.ActualInvocationIdentity(actual.repository, actual.producer, "other", actual.control)
    with registration.bind_installed_execution_owner(binding):
        with pytest.raises(owner.OwnerAdmissionError, match="profile or control"):
            registration.reserve_owner_invocation(wrong, required=False, timeout_seconds=10)


def copied_controller_attempt(actual, result):
    try:
        registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)
    except owner.OwnerAdmissionError:
        result.send("refused")
    else:
        result.send("admitted")


def test_forked_process_cannot_reuse_controller_binding(installed):
    binding, actual, _ = installed
    parent, child = multiprocessing.Pipe(False)
    with registration.bind_installed_execution_owner(binding):
        process = multiprocessing.get_context("fork").Process(
            target=copied_controller_attempt, args=(actual, child))
        process.start()
        try:
            assert parent.poll(5)
            assert parent.recv() == "refused"
        finally:
            if process.is_alive():
                process.terminate()
            process.join(5)
            parent.close()
            child.close()
            assert not process.is_alive()


def test_exited_independent_owner_invalidates_registration(installed):
    binding, actual, children = installed
    with registration.bind_installed_execution_owner(binding):
        children[0].terminate()
        children[0].join(5)
        with pytest.raises(owner.OwnerAdmissionError, match="peer"):
            registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)


@pytest.mark.parametrize("version", [True, 0, 2, "1"])
def test_unsupported_registration_api_refuses_before_any_owner_connection(installed, version):
    from dataclasses import replace
    binding, _actual, _ = installed
    with pytest.raises(owner.OwnerAdmissionError, match="API version"):
        with registration.bind_installed_execution_owner(replace(binding, api_version=version)):
            raise AssertionError("unsupported binding installed")


@pytest.mark.parametrize("field", ["repository", "producer"])
def test_installed_scope_cannot_fall_back_to_legacy_execution(installed, field):
    from dataclasses import replace
    binding, actual, _ = installed
    value = actual.repository.parent if field == "repository" else "unlisted-producer"
    wrong = replace(actual, **{field: value})
    with registration.bind_installed_execution_owner(binding):
        with pytest.raises(owner.OwnerAdmissionError, match="outside installed owner scope"):
            registration.reserve_owner_invocation(wrong, required=False, timeout_seconds=10)


def test_independent_sets_without_exact_allocation_are_not_authority(installed):
    from dataclasses import replace
    binding, _actual, _children = installed
    binding = replace(binding, scope=replace(binding.scope, allocation=()))
    with pytest.raises(owner.OwnerAdmissionError, match="exact invocation allocation"):
        with registration.bind_installed_execution_owner(binding):
            raise AssertionError("independent membership sets admitted an unspecified invocation plan")


def exact_two_route_binding(binding):
    from dataclasses import replace
    routes = (registration.OwnerInvocationRoute("runtime-smoke", "direct-login", "baseline"),
              registration.OwnerInvocationRoute("runtime-revoke", "direct-revoke", "actual-control"))
    scope = replace(binding.scope, producers=frozenset(r.producer for r in routes),
                    profiles=frozenset(r.profile for r in routes),
                    controls=frozenset(r.control for r in routes), allocation=routes)
    return replace(binding, scope=scope)


def test_exact_plan_refuses_cartesian_skipped_and_replayed_ordinals(installed):
    from dataclasses import replace
    binding, actual, _ = installed
    binding = exact_two_route_binding(binding)
    second = replace(actual, producer="runtime-revoke", profile="direct-revoke", control="actual-control")
    mixed = replace(actual, profile="direct-revoke")
    with registration.bind_installed_execution_owner(binding):
        for wrong in (mixed, second):
            with pytest.raises(owner.OwnerAdmissionError, match="next exact allocation ordinal"):
                registration.reserve_owner_invocation(wrong, required=False, timeout_seconds=10)
        first = registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)
        assert first.ordinal == 1 and first.allocation_digest == binding.scope.allocation_digest()
        with pytest.raises(owner.OwnerAdmissionError, match="next exact allocation ordinal"):
            registration.reserve_owner_invocation(actual, required=True, timeout_seconds=10)
        last = registration.reserve_owner_invocation(second, required=True, timeout_seconds=10)
        assert last.ordinal == 2 and last.allocation_digest == first.allocation_digest
        with pytest.raises(owner.OwnerAdmissionError, match="exhausted"):
            registration.reserve_owner_invocation(second, required=True, timeout_seconds=10)


def test_allocation_digest_commits_exact_tuple_order(installed):
    from dataclasses import replace
    binding, _actual, _ = installed
    scope = exact_two_route_binding(binding).scope
    assert scope.allocation_digest() == replace(scope).allocation_digest()
    assert scope.allocation_digest() != replace(scope, allocation=tuple(reversed(scope.allocation))).allocation_digest()


@pytest.mark.parametrize("cap", [True, 0, 1, 3])
def test_aggregate_cap_must_equal_exact_declared_invocations(installed, cap):
    from dataclasses import replace
    binding, _actual, _ = installed
    with pytest.raises(owner.OwnerAdmissionError, match="aggregate allocation"):
        with registration.bind_installed_execution_owner(replace(binding, maximum_invocations=cap)):
            raise AssertionError("undeclared capacity accepted")


def test_unlisted_scope_projection_cannot_broaden_plan(installed):
    from dataclasses import replace
    binding, _actual, _ = installed
    scope = replace(binding.scope, profiles=binding.scope.profiles | {"unallocated"})
    with pytest.raises(owner.OwnerAdmissionError, match="allocation projections"):
        scope.validate()


@pytest.mark.parametrize("mutation", ["mutable-allocation", "mutable-membership", "untyped-route", "empty-route"])
def test_allocation_requires_deeply_closed_typed_records(installed, mutation):
    from dataclasses import replace
    binding, _actual, _ = installed
    scope = binding.scope
    if mutation == "mutable-allocation":
        scope = replace(scope, allocation=list(scope.allocation))
    elif mutation == "mutable-membership":
        scope = replace(scope, producers=set(scope.producers))
    elif mutation == "untyped-route":
        scope = replace(scope, allocation=({"producer": "runtime-smoke"},))
    else:
        scope = replace(scope, allocation=(registration.OwnerInvocationRoute("", "direct-login", "baseline"),))
    with pytest.raises(owner.OwnerAdmissionError):
        scope.validate()
