from __future__ import annotations

import json
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_MODULE_PATH = Path(
    os.environ.get(
        "BCF_EVIDENCE_MODULE_PATH",
        str(REPO_ROOT / "scripts/governance_evidence.py"),
    )
).resolve()
spec = importlib.util.spec_from_file_location(
    "governance_evidence_under_test", EVIDENCE_MODULE_PATH
)
if spec is None or spec.loader is None:
    raise RuntimeError(f"unable to load evidence module from {EVIDENCE_MODULE_PATH}")
EVIDENCE_MODULE = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(EVIDENCE_MODULE_PATH.parent))
try:
    spec.loader.exec_module(EVIDENCE_MODULE)
finally:
    sys.path.pop(0)
EvidenceError = EVIDENCE_MODULE.EvidenceError
capture_gate = EVIDENCE_MODULE.capture_gate
allocate_session = EVIDENCE_MODULE.allocate_session
local_producer_identity = EVIDENCE_MODULE.local_producer_identity


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def test_evidence_run_captures_process_artifacts_test_counts_and_negative_control(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "governance").mkdir()
    (repo / ".gitignore").write_text(".artifacts/\n", encoding="utf-8")
    (repo / "gate.py").write_text(
        """import pathlib
import sys
PASS = True
failure = '' if PASS else '<failure>mutated</failure>'
path = pathlib.Path('.artifacts/test.junit.xml')
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(f'<testsuite tests="1" failures="{int(not PASS)}"><testcase classname="tests/test_gate.py" name="test_gate">{failure}</testcase></testsuite>')
print('collected 1 item')
print('1 passed' if PASS else '1 failed')
sys.exit(0 if PASS else 1)
""",
        encoding="utf-8",
    )
    (repo / "Makefile").write_text("test:\n\tpython gate.py\n", encoding="utf-8")
    (repo / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "profile": {"selected": "standard"},
                "release_gate_profile": {
                    "gates": {
                        "test": {
                            "target": "test",
                            "status": "required",
                            "command_policy": "automated_tests",
                        }
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (repo / "governance/evidence-policy.yml").write_text(
        yaml.safe_dump(
            {
                "gate_overrides": {
                    "test": {
                        "evidence_kind": "test_suite",
                            "test_contract": {
                                "junit_xml": ".artifacts/test.junit.xml",
                                "min_collected": 1,
                            "min_executed": 1,
                            "max_skipped": 0,
                        },
                            "negative_controls": [
                            {
                                "id": "break-test",
                                    "mutation": {
                                    "path": "gate.py",
                                    "search": "PASS = True",
                                        "replace": "PASS = False",
                                    },
                                    "oracle": {
                                        "kind": "test_node_failure",
                                        "node_ids": ["tests/test_gate.py::test_gate"],
                                    },
                                }
                            ],
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (repo / "governance/gate-contracts.yml").write_text(
        yaml.safe_dump(
            {
                "document": {
                    "kind": "gate_contract_registry",
                    "version": "1.0",
                    "path": "governance/gate-contracts.yml",
                },
                "schema_version": "1.0",
                "target_profile": "standard",
                "gates": {
                    "test": {
                        "invocation": {
                            "argv": ["python3", "gate.py"],
                            "cwd": ".",
                            "env": {},
                            "required_env": [],
                        },
                        "evidence": {
                            "kind": "test_suite",
                            "test_contract": {
                                "junit_xml": ".artifacts/test.junit.xml",
                                "min_collected": 1,
                                "min_executed": 1,
                                "max_skipped": 0,
                            },
                        },
                        "negative_controls": [],
                    }
                },
                "provenance": {},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    _git(repo, "init")
    _git(repo, "config", "user.email", "evidence@example.test")
    _git(repo, "config", "user.name", "Evidence Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "gate")

    receipt_path = capture_gate(repo, "test", tmp_path / "evidence")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert receipt["subject"]["binding"] == "exact_tree"
    assert receipt["subject"]["tracked_clean"] is True
    assert receipt["observations"]["exit_code"] == 0
    assert receipt["observations"]["test_counts"]["executed"] == 1
    assert receipt["observations"]["test_counts"]["skipped"] == 0
    assert receipt["behavioral_probes"][0]["mutation_applied"] is True
    assert receipt["behavioral_probes"][0]["observed_exit_code"] != 0
    assert all(len(artifact["sha256"]) == 64 for artifact in receipt["artifacts"])


def _make_diagnostic_gate_repo(
    tmp_path: Path,
    source: str,
    *,
    argv: list[str] | None = None,
    mutation_path: str = "gate.py",
    oracle_regex: str = "expected policy violation",
) -> Path:
    repo = tmp_path / "diagnostic-repo"
    repo.mkdir()
    (repo / "governance").mkdir()
    (repo / ".gitignore").write_text(".artifacts/\n", encoding="utf-8")
    (repo / "gate.py").write_text(source, encoding="utf-8")
    control = {
        "id": "break-gate",
        "mutation": {
            "path": mutation_path,
            "search": "BROKEN = False",
            "replace": "BROKEN = True",
        },
        "oracle": {
            "kind": "diagnostic",
            "exit_codes": [1],
            "stream": "stderr",
            "regex": oracle_regex,
        },
    }
    (repo / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "profile": {"selected": "standard"},
                "release_gate_profile": {
                    "gates": {
                        "gate": {
                            "target": "gate",
                            "status": "required",
                            "command_policy": "governance_validation",
                        }
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (repo / "governance/evidence-policy.yml").write_text(
        yaml.safe_dump(
            {"gate_overrides": {"gate": {"evidence_kind": "gate", "negative_controls": [control]}}},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (repo / "governance/gate-contracts.yml").write_text(
        yaml.safe_dump(
            {
                "gates": {
                    "gate": {
                        "invocation": {
                            "argv": argv or ["python3", "gate.py"],
                            "cwd": ".",
                            "env": {},
                            "required_env": [],
                        }
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    _git(repo, "init")
    _git(repo, "config", "user.email", "evidence@example.test")
    _git(repo, "config", "user.name", "Evidence Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "gate")
    return repo


def test_capture_rejects_nonignored_untracked_helper_before_execution(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "import helper\nBROKEN = False\nprint(helper.VALUE)\n",
    )
    (repo / "helper.py").write_text("VALUE = 'untracked influence'\n", encoding="utf-8")

    with pytest.raises(EvidenceError, match="non-ignored untracked"):
        capture_gate(repo, "gate", tmp_path / "evidence")


def test_ignored_helper_cannot_influence_isolated_positive_execution(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "import helper\nBROKEN = False\nprint(helper.VALUE)\n",
    )
    with (repo / ".gitignore").open("a", encoding="utf-8") as stream:
        stream.write("helper.py\n")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-m", "ignore local helper")
    (repo / "helper.py").write_text("VALUE = 'ignored influence'\n", encoding="utf-8")

    receipt = json.loads(
        capture_gate(repo, "gate", tmp_path / "evidence").read_text(encoding="utf-8")
    )

    assert receipt["result"] == "failed"
    assert receipt["observations"]["exit_code"] != 0
    assert receipt["behavioral_probes"] == []


def test_escaping_negative_control_cannot_touch_outside_worktree(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("BROKEN = False\n", encoding="utf-8")
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "import sys\nBROKEN = False\nprint('ok')\n",
        mutation_path="../outside.py",
    )

    receipt = json.loads(
        capture_gate(repo, "gate", tmp_path / "evidence").read_text(encoding="utf-8")
    )

    assert receipt["result"] == "failed"
    assert receipt["behavioral_probes"][0]["mutation_applied"] is False
    assert outside.read_text(encoding="utf-8") == "BROKEN = False\n"


def test_arbitrary_crash_does_not_satisfy_typed_diagnostic_oracle(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "BROKEN = False\nif BROKEN:\n    raise RuntimeError('arbitrary crash')\nprint('ok')\n",
    )

    receipt = json.loads(
        capture_gate(repo, "gate", tmp_path / "evidence").read_text(encoding="utf-8")
    )

    probe = receipt["behavioral_probes"][0]
    assert probe["observed_exit_code"] == 1
    assert probe["oracle_observation"]["satisfied"] is False
    assert receipt["result"] == "failed"


def test_positive_gate_that_mutates_tracked_file_is_not_evidence(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "from pathlib import Path\nBROKEN = False\nPath('tracked.txt').write_text('changed')\nprint('ok')\n",
    )
    (repo / "tracked.txt").write_text("original\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-m", "tracked output")

    receipt = json.loads(
        capture_gate(repo, "gate", tmp_path / "evidence").read_text(encoding="utf-8")
    )

    assert receipt["observations"]["execution_tree_clean"] is False
    assert receipt["result"] == "failed"


def test_missing_executable_is_infrastructure_failure_not_negative_control(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "BROKEN = False\nprint('unused')\n",
        argv=["bcf-command-that-does-not-exist"],
    )

    receipt = json.loads(
        capture_gate(repo, "gate", tmp_path / "evidence").read_text(encoding="utf-8")
    )

    assert receipt["observations"]["exit_code"] == 126
    assert receipt["behavioral_probes"] == []
    assert receipt["result"] == "failed"


def test_capture_rejects_tracked_symlink_that_escapes_repository(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "BROKEN = False\nprint('ok')\n",
    )
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (repo / "escape-link").symlink_to(outside)
    _git(repo, "add", "escape-link")
    _git(repo, "commit", "-m", "unsafe link")

    with pytest.raises(EvidenceError, match="tracked symlink escapes"):
        capture_gate(repo, "gate", tmp_path / "evidence")


def test_selected_python_overrides_host_path_and_reaches_detached_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loader_marker = "/bcf/test/loader"
    inherited_loader = os.environ.get("LD_LIBRARY_PATH", "")
    selected_loader = os.pathsep.join(
        value for value in (inherited_loader, loader_marker) if value
    )
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        """import os
import sys
BROKEN = False
if not os.environ.get('LD_LIBRARY_PATH', '').endswith('/bcf/test/loader'):
    raise SystemExit('selected loader environment missing')
if BROKEN:
    print('expected policy violation', file=sys.stderr)
    raise SystemExit(1)
print(sys.executable)
""",
    )
    lexical_bin = tmp_path / "selected-venv" / "bin"
    lexical_bin.mkdir(parents=True)
    selected_python = lexical_bin / "python"
    selected_python.symlink_to(sys.executable)
    hostile_bin = tmp_path / "host-python"
    hostile_bin.mkdir()
    hostile_python = hostile_bin / "python3"
    hostile_python.write_text("#!/bin/sh\nexit 91\n", encoding="utf-8")
    hostile_python.chmod(0o755)
    monkeypatch.setenv("PATH", f"{hostile_bin}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("LD_LIBRARY_PATH", selected_loader)

    receipt = json.loads(
        capture_gate(
            repo,
            "gate",
            tmp_path / "evidence",
            python_executable=selected_python,
        ).read_text(encoding="utf-8")
    )

    interpreter = receipt["observations"]["execution_environment"][
        "selected_interpreter"
    ]
    assert receipt["result"] == "passed"
    assert receipt["invocation"]["argv"] == ["python3", "gate.py"]
    assert interpreter["role"] == "project_python"
    assert interpreter["executable_name"] == "python"
    assert len(interpreter["binary_sha256"]) == 64
    assert len(interpreter["lexical_path_sha256"]) == 64
    assert len(interpreter["runtime_environment_sha256"]) == 64
    assert receipt["behavioral_probes"][0]["oracle_observation"]["satisfied"] is True


def test_missing_selected_python_fails_before_gate_execution(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "BROKEN = False\nprint('must not execute')\n",
    )

    with pytest.raises(EvidenceError, match="selected Python executable is not executable"):
        capture_gate(
            repo,
            "gate",
            tmp_path / "evidence",
            python_executable=tmp_path / "missing-python",
        )


def test_evidence_sessions_are_fresh_private_and_immutable(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "BROKEN = False\nprint('ok')\n",
    )
    artifact_root = tmp_path / "evidence"

    first = allocate_session(repo, artifact_root, ["gate"])
    second = allocate_session(repo, artifact_root, ["gate"])

    assert first.root != second.root
    assert len(first.payload["session_id"]) >= 32
    assert stat.S_IMODE(first.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(first.manifest_path.stat().st_mode) == 0o400
    assert first.payload["subject"]["commit_sha"] == subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_evidence_session_rejects_symlinked_artifact_root(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "BROKEN = False\nprint('ok')\n",
    )
    real_root = tmp_path / "real-evidence"
    real_root.mkdir()
    linked_root = tmp_path / "linked-evidence"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(EvidenceError, match="contains a symlink"):
        allocate_session(repo, linked_root, ["gate"])


def test_profile_v2_capture_requires_and_binds_one_session(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        """import sys
BROKEN = False
if BROKEN:
    print('expected policy violation', file=sys.stderr)
    raise SystemExit(1)
print('ok')
""",
    )
    profile_path = repo / "governance-profile.yml"
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile["profile_contract_version"] = "2.0"
    profile_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    _git(repo, "add", "governance-profile.yml")
    _git(repo, "commit", "-m", "enable profile v2")

    with pytest.raises(EvidenceError, match="requires --session-manifest"):
        capture_gate(repo, "gate", tmp_path / "unbound")

    session = allocate_session(repo, tmp_path / "evidence", ["gate"])
    output = session.root / "gates" / "gate"
    receipt = json.loads(
        capture_gate(
            repo,
            "gate",
            output,
            session_manifest=session.manifest_path,
        ).read_text(encoding="utf-8")
    )

    observation = receipt["observations"]["evidence_session"]
    assert receipt["result"] == "passed"
    assert observation == {
        "session_id": session.payload["session_id"],
        "manifest_sha256": session.digest,
    }
    manifest_artifact = next(
        value for value in receipt["artifacts"] if value["path"] == "evidence-session.json"
    )
    assert manifest_artifact["sha256"] == session.digest
    assert (output / "evidence-session.json").read_bytes() == session.manifest_path.read_bytes()


def test_explicit_local_session_ignores_ambient_github_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "BROKEN = False\nprint('ok')\n",
    )
    profile_path = repo / "governance-profile.yml"
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile["profile_contract_version"] = "2.0"
    profile_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    _git(repo, "add", "governance-profile.yml")
    _git(repo, "commit", "-m", "enable profile v2")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "outer/provider-repository")
    monkeypatch.setenv("GITHUB_REPOSITORY_ID", "12345")
    monkeypatch.setenv("GITHUB_RUN_ID", "98765")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    monkeypatch.setenv("GITHUB_JOB", "outer-job")

    session = allocate_session(
        repo,
        tmp_path / "evidence",
        ["gate"],
        expected_producers=["nested-local"],
        producer_identity=local_producer_identity(repo, "nested-local"),
    )
    receipt = json.loads(
        capture_gate(
            repo,
            "gate",
            session.root / "gate",
            session_manifest=session.manifest_path,
        ).read_text(encoding="utf-8")
    )

    assert session.payload["producer"] == {
        "kind": "local",
        "provider": "local",
        "repository": repo.name,
        "repository_id": "local",
        "run_id": "nested-local",
        "run_attempt": "1",
        "producer_id": "nested-local",
    }
    assert receipt["producer"]["kind"] == "service"
    assert receipt["invocation"]["workflow"] == {
        "provider": "local",
        "path": "local",
        "job": "nested-local",
        "run_id": "nested-local",
        "run_attempt": "1",
        "matrix": {"gate": "gate"},
    }


def test_session_gate_inventory_is_closed(tmp_path: Path) -> None:
    repo = _make_diagnostic_gate_repo(
        tmp_path,
        "BROKEN = False\nprint('ok')\n",
    )
    session = allocate_session(repo, tmp_path / "evidence", ["different-gate"])

    with pytest.raises(EvidenceError, match="not admitted"):
        capture_gate(
            repo,
            "gate",
            session.root / "gates" / "gate",
            session_manifest=session.manifest_path,
        )
