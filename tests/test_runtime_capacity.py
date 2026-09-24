from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import shutil

import pytest

from bcf_governance.tooling.runtime_capacity import (
    STATE_MANIFEST,
    RuntimeCapacityError,
    allocate_execution_state,
    check_runtime_capacity,
    retire_execution_state,
)


def _contract() -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "runtime_root": ".artifacts/bcf/runtime",
        "minimum_free_bytes": 100,
        "maximum_owned_containers": 3,
        "database": {
            "storage": "repository_bind_mount",
            "relative_path": ".artifacts/bcf/runtime/database",
        },
        "cleanup": {
            "caller_globs": False,
            "daemon_global_prune": False,
            "exact_owner_revalidation": True,
            "remove_anonymous_volumes": True,
        },
        "execution_state": {
            "default_lifecycle": "ephemeral",
            "namespace_binding": ["session_id", "workload_id", "execution_id"],
            "unexplained_preexisting": "reject",
            "persistent_requires_workload_declaration": True,
            "terminal_cleanup": "exact_owned_namespace",
            "verify_removal": True,
        },
    }


def _disk(free: int):
    return lambda _path: shutil._ntuple_diskusage(1000, 1000 - free, free)


def test_capacity_passes_before_heavy_work_with_repository_bind_root(tmp_path: Path) -> None:
    report = check_runtime_capacity(
        tmp_path, _contract(), owned_containers=1, disk_usage=_disk(500)
    )
    assert report.status == "ready"
    assert report.database_root == ".artifacts/bcf/runtime/database"


@pytest.mark.parametrize(
    ("free", "owned", "message"),
    [(99, 0, "insufficient disk"), (500, 3, "container capacity")],
)
def test_capacity_budget_fails_before_expensive_work(
    tmp_path: Path, free: int, owned: int, message: str
) -> None:
    with pytest.raises(RuntimeCapacityError, match=message):
        check_runtime_capacity(
            tmp_path, _contract(), owned_containers=owned, disk_usage=_disk(free)
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"runtime_root": "../outside"}, "safe repository-relative"),
        ({"database": {"storage": "docker_volume", "relative_path": ".artifacts/bcf/runtime/database"}}, "repository-owned bind mount"),
        ({"cleanup": {"caller_globs": True, "daemon_global_prune": False, "exact_owner_revalidation": True, "remove_anonymous_volumes": True}}, "exact, scoped"),
        ({"cleanup": {"caller_globs": False, "daemon_global_prune": True, "exact_owner_revalidation": True, "remove_anonymous_volumes": True}}, "exact, scoped"),
        ({"execution_state": {"default_lifecycle": "persistent_shared"}}, "execution-state policy"),
    ],
)
def test_runtime_contract_rejects_escape_and_broad_cleanup(
    tmp_path: Path, mutation: dict[str, object], message: str
) -> None:
    contract = deepcopy(_contract())
    contract.update(mutation)
    with pytest.raises(RuntimeCapacityError, match=message):
        check_runtime_capacity(
            tmp_path, contract, owned_containers=0, disk_usage=_disk(500)
        )


def test_runtime_root_symlink_escape_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / ".artifacts").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeCapacityError, match="traverses a symlink"):
        check_runtime_capacity(
            tmp_path, _contract(), owned_containers=0, disk_usage=_disk(500)
        )


def _allocate(tmp_path: Path, execution_id: str = "positive"):
    return allocate_execution_state(
        tmp_path,
        _contract(),
        session_id="session-123456",
        workload_id="integration-tests",
        execution_id=execution_id,
        invocation={},
    )


def test_ephemeral_execution_state_is_exact_owned_and_retired(tmp_path: Path) -> None:
    lease = _allocate(tmp_path)

    assert lease.root.is_dir()
    assert lease.database_root.is_dir()
    assert lease.environment()["BCF_EXECUTION_STATE_NAMESPACE"] == lease.namespace
    report = retire_execution_state(lease)

    assert report["retired"] is True
    assert report["removal_verified"] is True
    assert not lease.root.exists()


def test_unexplained_preexisting_execution_state_fails_before_execution(
    tmp_path: Path,
) -> None:
    lease = _allocate(tmp_path)

    with pytest.raises(RuntimeCapacityError, match="unexplained pre-existing"):
        _allocate(tmp_path)

    retire_execution_state(lease)


def test_unrelated_unowned_state_fails_before_execution(tmp_path: Path) -> None:
    base = tmp_path / ".artifacts/bcf/runtime/database/unowned"
    base.mkdir(parents=True)

    with pytest.raises(RuntimeCapacityError, match="unexplained pre-existing"):
        _allocate(tmp_path)


def test_separately_owned_execution_namespaces_can_run_concurrently(
    tmp_path: Path,
) -> None:
    first = _allocate(tmp_path, "execution-one")
    second = _allocate(tmp_path, "execution-two")

    assert first.namespace != second.namespace
    retire_execution_state(first)
    assert second.root.is_dir()
    retire_execution_state(second)


def test_execution_state_retirement_revalidates_exact_ownership(tmp_path: Path) -> None:
    lease = _allocate(tmp_path)
    manifest = lease.root / STATE_MANIFEST
    manifest.chmod(0o600)
    manifest.write_text("{}\n", encoding="utf-8")

    with pytest.raises(RuntimeCapacityError, match="ownership is invalid"):
        retire_execution_state(lease)


def test_execution_state_retirement_fails_when_exact_namespace_remains(
    tmp_path: Path,
) -> None:
    lease = _allocate(tmp_path)

    with pytest.raises(RuntimeCapacityError, match="retirement was incomplete"):
        retire_execution_state(lease, remover=lambda _path: None)

    retire_execution_state(lease)


def test_persistent_state_requires_explicit_workload_namespace(tmp_path: Path) -> None:
    with pytest.raises(RuntimeCapacityError, match="requires an explicit safe"):
        allocate_execution_state(
            tmp_path,
            _contract(),
            session_id="session-123456",
            workload_id="integration-tests",
            execution_id="positive",
            invocation={"state": {"lifecycle": "persistent_shared"}},
        )


def test_explicit_persistent_workload_retains_only_its_declared_namespace(
    tmp_path: Path,
) -> None:
    invocation = {
        "state": {"lifecycle": "persistent_shared", "namespace": "shared-cache"}
    }
    first = allocate_execution_state(
        tmp_path,
        _contract(),
        session_id="session-123456",
        workload_id="integration-tests",
        execution_id="execution-one",
        invocation=invocation,
    )

    report = retire_execution_state(first)
    second = allocate_execution_state(
        tmp_path,
        _contract(),
        session_id="session-654321",
        workload_id="integration-tests",
        execution_id="execution-two",
        invocation=invocation,
    )

    assert report["retired"] is False
    assert second.preexisting is True
    shutil.rmtree(second.root)


def test_consecutive_executions_cannot_observe_predecessor_database_state(
    tmp_path: Path,
) -> None:
    first = _allocate(tmp_path, "execution-one")
    marker = first.database_root / "predecessor.sqlite"
    marker.write_text("predecessor", encoding="utf-8")
    retire_execution_state(first)

    second = _allocate(tmp_path, "execution-two")
    assert second.namespace != first.namespace
    assert not (second.database_root / marker.name).exists()
    retire_execution_state(second)
