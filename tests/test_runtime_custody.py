from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bcf_governance.tooling.governance_install.runtime_custody import (
    RuntimeCustodyError,
    RuntimeCustodyFailure,
    RuntimeCustodyState,
    inspect_runtime_custody,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = REPO_ROOT / "schemas/bcf-runtime-lock.schema.json"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _lock(repo: Path, *, files: dict[str, str], preserved: dict[str, str]) -> Path:
    path = repo / "governance/bcf-runtime-lock.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "version": "2.1.4",
                "source_repository": "mjgolaszewski/bcf-governance",
                "source_repository_id": 1207503211,
                "source_commit": "a" * 40,
                "release_id": 1,
                "release_url": (
                    "https://github.com/mjgolaszewski/bcf-governance/"
                    "releases/tag/v2.1.4"
                ),
                "wheel_sha256": "b" * 64,
                "source_archive_sha256": "c" * 64,
                "checksum_manifest_sha256": "d" * 64,
                "official_installer_adaptations": {},
                "files": files,
                "preserved_consumer_files": preserved,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_absent_custody_is_typed_and_non_destructive(tmp_path: Path) -> None:
    snapshot = inspect_runtime_custody(tmp_path, schema_path=SCHEMA)

    assert snapshot.state is RuntimeCustodyState.ABSENT
    assert snapshot.runtime_owned == {}
    assert snapshot.consumer_preserved == {}
    assert snapshot.deletion_authorized is False


def test_complete_local_installation_is_distinct_from_absent_custody(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "governance-profile.yml"
    runtime = tmp_path / "scripts/_bcf_runtime/install_governance_pack.py"
    profile.write_text("profile: lite\n", encoding="utf-8")
    runtime.parent.mkdir(parents=True)
    runtime.write_text("# runtime\n", encoding="utf-8")

    snapshot = inspect_runtime_custody(tmp_path, schema_path=SCHEMA)

    assert snapshot.state is RuntimeCustodyState.LOCAL_UNRELEASED


@pytest.mark.parametrize(
    "relative",
    ["governance-profile.yml", "scripts/_bcf_runtime/install_governance_pack.py"],
)
def test_partial_local_installation_is_typed_before_upgrade(
    tmp_path: Path,
    relative: str,
) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("partial\n", encoding="utf-8")

    snapshot = inspect_runtime_custody(tmp_path, schema_path=SCHEMA)

    assert snapshot.state is RuntimeCustodyState.PARTIAL_UNEXPLAINED


def test_normalized_exact_custody_partitions_runtime_and_consumer_bytes(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "scripts/_bcf_runtime/tool.py"
    consumer = tmp_path / "governance/ci-graph.yml"
    runtime.parent.mkdir(parents=True)
    consumer.parent.mkdir(parents=True)
    runtime.write_text("runtime\n", encoding="utf-8")
    consumer.write_text("consumer\n", encoding="utf-8")
    _lock(
        tmp_path,
        files={runtime.relative_to(tmp_path).as_posix(): _digest(runtime)},
        preserved={consumer.relative_to(tmp_path).as_posix(): _digest(consumer)},
    )

    snapshot = inspect_runtime_custody(tmp_path, schema_path=SCHEMA)

    assert snapshot.state is RuntimeCustodyState.NORMALIZED_EXACT
    assert tuple(snapshot.runtime_owned) == ("scripts/_bcf_runtime/tool.py",)
    assert tuple(snapshot.consumer_preserved) == ("governance/ci-graph.yml",)
    assert snapshot.deletion_authorized is False


def test_exact_legacy_overlap_normalizes_toward_consumer_preservation(
    tmp_path: Path,
) -> None:
    shared = tmp_path / "schemas/architecture-boundaries.schema.json"
    shared.parent.mkdir(parents=True)
    shared.write_text("{}\n", encoding="utf-8")
    digest = _digest(shared)
    relative = shared.relative_to(tmp_path).as_posix()
    _lock(tmp_path, files={relative: digest}, preserved={relative: digest})

    snapshot = inspect_runtime_custody(tmp_path, schema_path=SCHEMA)

    assert snapshot.state is RuntimeCustodyState.LEGACY_OVERLAP_EXACT
    assert snapshot.runtime_owned == {}
    assert snapshot.consumer_preserved == {
        "schemas/architecture-boundaries.schema.json": digest
    }
    assert snapshot.legacy_overlap == ("schemas/architecture-boundaries.schema.json",)


@pytest.mark.parametrize(
    ("mutation", "failure"),
    [
        ("contradictory", RuntimeCustodyFailure.CONTRADICTORY_OVERLAP),
        ("owned_drift", RuntimeCustodyFailure.RUNTIME_OWNED_DRIFT),
        ("owned_missing", RuntimeCustodyFailure.RUNTIME_OWNED_DRIFT),
        ("owned_symlink", RuntimeCustodyFailure.RUNTIME_OWNED_DRIFT),
        ("preserved_drift", RuntimeCustodyFailure.CONSUMER_PRESERVED_DRIFT),
        ("preserved_missing", RuntimeCustodyFailure.CONSUMER_PRESERVED_DRIFT),
        ("preserved_symlink", RuntimeCustodyFailure.CONSUMER_PRESERVED_DRIFT),
    ],
)
def test_invalid_custody_states_fail_with_stable_classification(
    tmp_path: Path,
    mutation: str,
    failure: RuntimeCustodyFailure,
) -> None:
    owned = tmp_path / "scripts/_bcf_runtime/tool.py"
    preserved = tmp_path / "governance/ci-graph.yml"
    owned.parent.mkdir(parents=True)
    preserved.parent.mkdir(parents=True)
    owned.write_text("runtime\n", encoding="utf-8")
    preserved.write_text("consumer\n", encoding="utf-8")
    owned_digest = _digest(owned)
    preserved_digest = _digest(preserved)
    files = {owned.relative_to(tmp_path).as_posix(): owned_digest}
    preserved_files = {preserved.relative_to(tmp_path).as_posix(): preserved_digest}
    if mutation == "contradictory":
        preserved_files = {owned.relative_to(tmp_path).as_posix(): "f" * 64}
    _lock(tmp_path, files=files, preserved=preserved_files)
    if mutation == "owned_drift":
        owned.write_text("changed\n", encoding="utf-8")
    elif mutation == "owned_missing":
        owned.unlink()
    elif mutation == "owned_symlink":
        replacement = tmp_path / "runtime-link-target"
        replacement.write_text("runtime\n", encoding="utf-8")
        owned.unlink()
        owned.symlink_to(replacement)
    elif mutation == "preserved_drift":
        preserved.write_text("changed\n", encoding="utf-8")
    elif mutation == "preserved_missing":
        preserved.unlink()
    elif mutation == "preserved_symlink":
        replacement = tmp_path / "consumer-link-target"
        replacement.write_text("consumer\n", encoding="utf-8")
        preserved.unlink()
        preserved.symlink_to(replacement)

    with pytest.raises(RuntimeCustodyError) as raised:
        inspect_runtime_custody(tmp_path, schema_path=SCHEMA)

    assert raised.value.failure is failure


def test_malformed_lock_fails_before_any_state_is_inferred(tmp_path: Path) -> None:
    path = tmp_path / "governance/bcf-runtime-lock.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"version":"2.1.4"}\n', encoding="utf-8")

    with pytest.raises(RuntimeCustodyError) as raised:
        inspect_runtime_custody(tmp_path, schema_path=SCHEMA)

    assert raised.value.failure is RuntimeCustodyFailure.SCHEMA_INVALID


def test_predecessor_lock_without_local_schema_uses_packaged_contract(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "scripts/_bcf_runtime/tool.py"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("runtime\n", encoding="utf-8")
    _lock(
        tmp_path,
        files={runtime.relative_to(tmp_path).as_posix(): _digest(runtime)},
        preserved={},
    )

    snapshot = inspect_runtime_custody(tmp_path)

    assert snapshot.state is RuntimeCustodyState.NORMALIZED_EXACT
    assert snapshot.version == "2.1.4"


def test_present_symlinked_local_schema_never_falls_back_to_packaged_contract(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "scripts/_bcf_runtime/tool.py"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("runtime\n", encoding="utf-8")
    _lock(
        tmp_path,
        files={runtime.relative_to(tmp_path).as_posix(): _digest(runtime)},
        preserved={},
    )
    local_schema = tmp_path / "schemas/bcf-runtime-lock.schema.json"
    local_schema.parent.mkdir()
    local_schema.symlink_to(SCHEMA)

    with pytest.raises(RuntimeCustodyError) as raised:
        inspect_runtime_custody(tmp_path)

    assert raised.value.failure is RuntimeCustodyFailure.LOCK_UNREADABLE
