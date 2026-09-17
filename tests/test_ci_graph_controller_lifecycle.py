from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from bcf_governance.tooling.ci_graph_controller_lifecycle import (
    ControllerLifecycleState,
    controller_requirement_condition,
    resolve_controller_lifecycle,
)
from bcf_governance.tooling.ci_graph_errors import CIGraphError


ROOT = Path(__file__).resolve().parents[1]


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _repository(root: Path) -> tuple[str, str]:
    (root / "schemas").mkdir()
    shutil.copy2(
        ROOT / "schemas/recovery-reentry-authorization.schema.json",
        root / "schemas/recovery-reentry-authorization.schema.json",
    )
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "BCF Test")
    _git(root, "config", "user.email", "bcf@example.invalid")
    (root / "subject.txt").write_text("exact recovery re-entry source\n")
    _git(root, "add", "subject.txt")
    _git(root, "commit", "-qm", "subject")
    return _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD^{tree}")


def _binding(value: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _authorization(source_commit: str, source_tree: str) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0",
        "state": "authenticated-recovery-reentry",
        "repository_id": "101",
        "operation_id": "1" * 32,
        "reason_code": "ordinary_control_plane_bootstrap_deadlock",
        "receipt_artifact": {
            "id": "31",
            "name": "bcf-break-glass-recovery-receipt-" + "1" * 32,
            "provider_digest": "sha256:" + "2" * 64,
            "payload_sha256": "3" * 64,
        },
        "installed_controller_commit": "c" * 40,
        "recovery_subject": {"commit": "c" * 40, "tree": "d" * 40},
        "authorized_source": {"commit": source_commit, "tree": source_tree},
        "provenance": {
            "build_run_id": "11",
            "build_run_attempt": "1",
            "build_artifact_id": "12",
            "build_artifact_digest": "sha256:" + "4" * 64,
            "install_run_id": "21",
            "install_run_attempt": "1",
            "probe_run_id": "22",
            "probe_run_attempt": "1",
        },
        "permitted_authority_class": "exact-main-admission",
        "recovery_only": True,
        "governance_certified": False,
    }
    value["binding_sha256"] = _binding(value)
    return value


def _runner(target: str, installed: str, authorization: object = None) -> dict[str, object]:
    runner: dict[str, object] = {
        "trusted_controller_artifact": {
            "BCF_BOOTSTRAP_COMMIT_SHA": target,
            "BCF_BOOTSTRAP_REPOSITORY_ID": "101",
        },
        "trusted_controller_installation": {
            "installed_commit_sha": installed,
            "subject_commit_sha": installed,
            "subject_tree_sha": "d" * 40,
            "bootstrap_run_id": "21",
            "bootstrap_run_attempt": "1",
            "probe_run_id": "22",
            "probe_run_attempt": "1",
        },
    }
    if authorization is not None:
        runner["trusted_controller_recovery_reentry"] = authorization
    return runner


def test_five_state_controller_lifecycle_and_requirement_resolution(tmp_path: Path) -> None:
    source_commit, source_tree = _repository(tmp_path)
    current = resolve_controller_lifecycle(tmp_path, _runner("a" * 40, "a" * 40))
    assert current.state is ControllerLifecycleState.ORDINARY_CURRENT
    assert controller_requirement_condition(current, "current") is None
    assert controller_requirement_condition(current, "current-or-recovery-reentry") is None

    pending = resolve_controller_lifecycle(tmp_path, _runner("b" * 40, "a" * 40))
    assert pending.state is ControllerLifecycleState.ORDINARY_PENDING_ROTATION
    assert controller_requirement_condition(pending, "current") == "${{ false }}"
    assert controller_requirement_condition(
        pending, "current-or-recovery-reentry"
    ) == "${{ false }}"

    authorization = _authorization(source_commit, source_tree)
    reentry = resolve_controller_lifecycle(
        tmp_path, _runner("b" * 40, "c" * 40, authorization)
    )
    assert reentry.state is ControllerLifecycleState.AUTHENTICATED_RECOVERY_REENTRY
    assert controller_requirement_condition(reentry, "current") == "${{ false }}"
    guard = controller_requirement_condition(reentry, "current-or-recovery-reentry")
    assert guard is not None and source_commit in guard and "github.repository_id" in guard

    stale_guard = guard.replace(source_commit, "f" * 40)
    assert stale_guard != guard

    normalized = resolve_controller_lifecycle(tmp_path, _runner("e" * 40, "e" * 40))
    assert normalized.state is ControllerLifecycleState.ORDINARY_CURRENT
    with pytest.raises(CIGraphError, match="cannot retain active"):
        resolve_controller_lifecycle(
            tmp_path, _runner("e" * 40, "e" * 40, authorization)
        )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("repository_id",), "102"),
        (("operation_id",), "2" * 32),
        (("receipt_artifact", "id"), "32"),
        (("receipt_artifact", "provider_digest"), "sha256:" + "5" * 64),
        (("installed_controller_commit",), "e" * 40),
        (("recovery_subject", "commit"), "e" * 40),
        (("recovery_subject", "tree"), "e" * 40),
        (("provenance", "build_run_id"), "13"),
        (("provenance", "build_run_attempt"), "2"),
        (("provenance", "install_run_id"), "23"),
        (("provenance", "install_run_attempt"), "2"),
        (("provenance", "probe_run_id"), "24"),
        (("provenance", "probe_run_attempt"), "2"),
        (("recovery_only",), False),
        (("governance_certified",), True),
    ],
)
def test_recovery_reentry_mutations_fail_closed(
    tmp_path: Path, path: tuple[str, ...], value: object
) -> None:
    source_commit, source_tree = _repository(tmp_path)
    authorization = _authorization(source_commit, source_tree)
    target = authorization
    for key in path[:-1]:
        target = target[key]  # type: ignore[index,assignment]
    target[path[-1]] = value  # type: ignore[index]
    with pytest.raises(CIGraphError):
        resolve_controller_lifecycle(
            tmp_path, _runner("b" * 40, "c" * 40, authorization)
        )


def test_recovery_reentry_unknown_multiple_and_wrong_source_fail_closed(
    tmp_path: Path,
) -> None:
    source_commit, source_tree = _repository(tmp_path)
    authorization = _authorization(source_commit, source_tree)
    unknown = copy.deepcopy(authorization)
    unknown["candidate_assertion"] = True
    with pytest.raises(CIGraphError, match="schema violation"):
        resolve_controller_lifecycle(tmp_path, _runner("b" * 40, "c" * 40, unknown))
    with pytest.raises(CIGraphError, match="one object"):
        resolve_controller_lifecycle(
            tmp_path, _runner("b" * 40, "c" * 40, [authorization, authorization])
        )

    wrong_source = copy.deepcopy(authorization)
    wrong_source["authorized_source"]["tree"] = "f" * 40  # type: ignore[index]
    wrong_source["binding_sha256"] = _binding(
        {key: value for key, value in wrong_source.items() if key != "binding_sha256"}
    )
    with pytest.raises(CIGraphError, match="source commit and tree"):
        resolve_controller_lifecycle(
            tmp_path, _runner("b" * 40, "c" * 40, wrong_source)
        )


def test_recovery_reentry_binding_rejects_caller_tampering(tmp_path: Path) -> None:
    source_commit, source_tree = _repository(tmp_path)
    authorization = _authorization(source_commit, source_tree)
    authorization["receipt_artifact"]["id"] = "99"  # type: ignore[index]
    with pytest.raises(CIGraphError, match="binding is invalid"):
        resolve_controller_lifecycle(
            tmp_path, _runner("b" * 40, "c" * 40, authorization)
        )
