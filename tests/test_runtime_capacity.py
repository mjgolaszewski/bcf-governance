from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import shutil

import pytest

from bcf_governance.tooling.runtime_capacity import (
    RuntimeCapacityError,
    check_runtime_capacity,
)


def _contract() -> dict[str, object]:
    return {
        "schema_version": "1.0",
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
