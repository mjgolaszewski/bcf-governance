from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.evidence_execution import (
    EvidenceError,
    _execution_env,
    _run_with_execution_state,
)


def _runtime_contract(repo: Path) -> None:
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/ci-runtime.yml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.1",
                "runtime_root": ".artifacts/runtime",
                "minimum_free_bytes": 1,
                "maximum_owned_containers": 1,
                "database": {
                    "storage": "repository_bind_mount",
                    "relative_path": ".artifacts/runtime/database",
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
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _contract(script: str) -> dict[str, object]:
    return {
        "target": "integration-state",
        "execution_timeout_seconds": 30,
        "invocation": {
            "argv": ["python3", script],
            "cwd": ".",
            "env": {},
            "required_env": [],
        },
    }


def test_consecutive_evidence_executions_receive_isolated_retired_state(
    tmp_path: Path,
) -> None:
    _runtime_contract(tmp_path)
    (tmp_path / "probe.py").write_text(
        """import os
from pathlib import Path
root = Path(os.environ['BCF_EXECUTION_DATABASE_ROOT'])
marker = root / 'predecessor.sqlite'
if marker.exists():
    raise SystemExit('predecessor state visible')
marker.write_text(os.environ['BCF_EXECUTION_STATE_NAMESPACE'])
print(os.environ['BCF_EXECUTION_STATE_NAMESPACE'])
""",
        encoding="utf-8",
    )
    roots: list[str] = []
    namespaces: list[str] = []

    for execution_id in ("execution-one", "execution-two"):
        result, env, _metadata, report = _run_with_execution_state(
            tmp_path,
            tmp_path,
            _contract("probe.py"),
            [sys.executable, "probe.py"],
            Path(sys.executable),
            session_id="session-123456",
            execution_id=execution_id,
            require_state=True,
        )
        assert result.returncode == 0
        assert report is not None and report["removal_verified"] is True
        roots.append(env["BCF_EXECUTION_STATE_ROOT"])
        namespaces.append(env["BCF_EXECUTION_STATE_NAMESPACE"])
        assert not Path(roots[-1]).exists()

    assert namespaces[0] != namespaces[1]


def test_failed_evidence_execution_still_retires_exact_namespace(tmp_path: Path) -> None:
    _runtime_contract(tmp_path)
    (tmp_path / "fail.py").write_text("raise SystemExit(7)\n", encoding="utf-8")

    result, env, _metadata, report = _run_with_execution_state(
        tmp_path,
        tmp_path,
        _contract("fail.py"),
        [sys.executable, "fail.py"],
        Path(sys.executable),
        session_id="session-123456",
        execution_id="adversarial:failure",
        require_state=True,
    )

    assert result.returncode == 7
    assert report is not None and report["retired"] is True
    assert not Path(env["BCF_EXECUTION_STATE_ROOT"]).exists()


def test_workload_cannot_override_canonical_state_environment(tmp_path: Path) -> None:
    contract = _contract("probe.py")
    contract["invocation"]["env"] = {"BCF_EXECUTION_DATABASE_ROOT": "forged"}

    with pytest.raises(EvidenceError, match="cannot override execution-state"):
        _execution_env(tmp_path, contract, Path(sys.executable))
