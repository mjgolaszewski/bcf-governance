from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.ci_graph_contracts import CIGraphError, validate_ci_graph
from bcf_governance.tooling.ci_graph_audit import audit_ci_graph
from bcf_governance.tooling.ci_graph_execution import (
    job_execution_issues,
    job_required_environment,
    workflow_input_issues,
)
from bcf_governance.tooling.ci_graph_defaults import build_reference_ci_graph
from bcf_governance.tooling.ci_graph_diagnostics import diagnose_ci_graph
from bcf_governance.tooling.ci_graph_import import inventory_github_workflows
from bcf_governance.tooling.ci_graph_locks import (
    apply_ci_graph_locks,
    check_ci_graph_locks,
)
from bcf_governance.tooling.ci_graph_render import (
    _executor_steps,
    apply_ci_graph,
    check_ci_graph,
    render_ci_graph,
)
from bcf_governance.tooling.ci_graph_values import resolve_graph_values
from bcf_governance.tooling.truth_workflow_graph import graph_workflow_gate_issues


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_graph_values_resolve_registered_list_members_without_duplicate_authority(
    tmp_path: Path,
) -> None:
    source = tmp_path / "producer.yml"
    source.write_text("producers:\n- actor_id: 49699333\n", encoding="utf-8")
    graph = {
        "value_sources": {
            "producer": {
                "path": "producer.yml",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
        },
        "condition": (
            "github.event.pull_request.user.id == "
            "{source:producer:producers.0.actor_id}"
        ),
    }

    resolved, inputs = resolve_graph_values(tmp_path, graph)

    assert resolved["condition"] == "github.event.pull_request.user.id == 49699333"
    assert inputs == (("producer.yml", hashlib.sha256(source.read_bytes()).hexdigest()),)


def _job(
    job_id: str,
    role: str,
    *,
    resource: str = "hosted-candidate",
    trust: str = "candidate",
    needs: list[str] | None = None,
    executor: dict[str, object] | None = None,
    produces: list[str] | None = None,
    consumes: list[str] | None = None,
    components: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": job_id,
        "display_name": role.replace("-", " ").title(),
        "semantic_role": role,
        "resource_class": resource,
        "trust": trust,
        "needs": needs or [],
        "condition": "success",
        "timeout_minutes": 35,
        "permissions": {"contents": "read"},
        "checkout": trust == "candidate",
        "components": components
        if components is not None
        else (
            ["checkout", "python"]
            if trust == "candidate"
            else (["python"] if (executor or {}).get("kind") == "authority" else [])
        ),
        "executor": executor or {"kind": "command", "command": "preflight"},
        "produces": produces or [],
        "consumes": consumes or [],
        "required": True,
    }


def _graph() -> dict[str, object]:
    return {
        "document": {
            "kind": "ci_graph",
            "name": "Fixture CI graph",
            "id": "fixture-ci-graph",
            "version": "1.0.0",
            "status": "active",
            "path": "governance/ci-graph.yml",
        },
        "schema_version": "1.0",
        "provider": "github",
        "profile_contract_version": "2.0",
        "default_branch": "main",
        "trusted_controller": {"kind": "executable", "executable": "bcf"},
        "value_sources": {},
        "extension_points": [
            "preflight",
            "evidence-lane",
            "before-truth",
            "after-truth",
            "exact-main-producer",
            "trusted-control",
            "scheduled-lane",
            "release-role",
        ],
        "extensions": [],
        "resource_classes": {
            "hosted-candidate": {
                "runner": "ubuntu-24.04",
                "trust": "candidate",
                "hosted": True,
                "capabilities": ["python"],
            },
            "trusted-control": {
                "runner": ["self-hosted", "bcf-trusted-control"],
                "trust": "trusted",
                "hosted": False,
                "capabilities": ["provider-api"],
            },
        },
        "artifacts": {
            "session": {"path": ".artifacts/bcf/sessions", "kind": "session", "scope": "run-attempt", "retention_days": 30},
            "receipts": {"path": ".artifacts/bcf/sessions", "kind": "lane-input", "scope": "run-attempt", "retention_days": 30},
        },
        "conditions": {},
        "commands": {
            "preflight": {
                "argv": ["{python}", "scripts/preflight_governance.py", "--repo-root", "."],
                "cwd": ".",
                "environment": {},
            },
            "truth": {
                "argv": ["{python}", "scripts/governance_truth.py", "--repo-root", "."],
                "cwd": ".",
                "environment": {},
            },
            "scheduled-controls": {
                "argv": ["{python}", ".github/scripts/run_validator_mutants.py", "--profile", "high-value"],
                "cwd": ".",
                "environment": {},
            },
        },
        "step_components": {},
        "workflows": [
            {
                "id": "governance",
                "path": ".github/workflows/governance.yml",
                "display_name": "Governance pull-request evidence",
                "role": "pull-request",
                "events": [{"type": "pull_request"}, {"type": "workflow_call"}],
                "permissions": {"contents": "read"},
                "jobs": [
                    _job("preflight", "cheap-preflight", produces=["session"]),
                    _job(
                        "evidence",
                        "required-evidence",
                        needs=["preflight"],
                        executor={"kind": "gate_group", "gates": ["test", "lint"]},
                        produces=["receipts"],
                        consumes=["session"],
                        components=["checkout", "python", "restore-private-modes"],
                    ),
                    _job(
                        "truth",
                        "terminal-truth",
                        needs=["evidence"],
                        executor={"kind": "truth", "command": "truth"},
                        consumes=["receipts"],
                        components=["checkout", "python", "restore-private-modes"],
                    ),
                ],
            },
            {
                "id": "exact-main",
                "path": ".github/workflows/bcf-exact-main.yml",
                "display_name": "Exact-main admission and producers",
                "role": "exact-main",
                "events": [{"type": "push", "branches": ["main"]}],
                "permissions": {"contents": "read"},
                "jobs": [
                    _job(
                        "admit",
                        "exact-main-admission",
                        resource="trusted-control",
                        trust="trusted",
                        executor={"kind": "authority", "operation": "admit"},
                    )
                ],
            },
            {
                "id": "scheduled-controls",
                "path": ".github/workflows/governance-controls.yml",
                "display_name": "Scheduled governance controls",
                "role": "scheduled",
                "events": [
                    {"type": "schedule", "cron": ["17 4 * * 1"]},
                    {"type": "workflow_dispatch"},
                ],
                "permissions": {"contents": "read"},
                "jobs": [
                    _job(
                        "controls",
                        "scheduled-controls",
                        executor={"kind": "command", "command": "scheduled-controls"},
                    )
                ],
            },
        ],
        "policy": {
            "exact_gate_once": True,
            "complete_evidence_fan_in": True,
            "single_push_authority": True,
            "generated_workflows_only": True,
            "forbid_hosted_waiters": True,
            "hosted_orchestration": "run_and_done",
            "forbidden_hosted_tokens": [
                "sleep", "poll", "watch", "wait", "while", "until",
                "wait-for-runner", "lease-runner",
            ],
        },
    }


def test_direct_event_command_inputs_require_mechanical_fallback() -> None:
    raw = "${{ inputs.evaluation_mode }}"

    def command_argv(graph: dict[str, object], job: dict[str, object]) -> None:
        graph["commands"][job["executor"]["command"]]["argv"].append(raw)

    def command_environment(graph: dict[str, object], job: dict[str, object]) -> None:
        graph["commands"][job["executor"]["command"]]["environment"]["MODE"] = raw

    def action_input(graph: dict[str, object], job: dict[str, object]) -> None:
        graph["step_components"]["raw-action"] = {
            "kind": "action", "with": {"mode": raw}, "environment": {}
        }
        job["executor"] = {"kind": "component_sequence", "components": ["raw-action"]}

    def reusable_input(graph: dict[str, object], job: dict[str, object]) -> None:
        job["executor"] = {
            "kind": "reusable_workflow", "path": ".github/workflows/called.yml",
            "inputs": {"mode": raw},
        }

    def job_output(_: dict[str, object], job: dict[str, object]) -> None:
        job["outputs"] = {"mode": raw}

    for mutation in (
        command_argv, command_environment, action_input, reusable_input, job_output
    ):
        graph = _graph()
        workflow = graph["workflows"][0]
        job = workflow["jobs"][0]
        mutation(graph, job)
        issues = workflow_input_issues(graph, workflow)
        assert len(issues) == 1
        assert "must provide an input fallback" in issues[0]

    graph = _graph()
    workflow = graph["workflows"][0]
    command_id = workflow["jobs"][0]["executor"]["command"]
    graph["commands"][command_id]["argv"].append(
        "${{ inputs.evaluation_mode || 'pr' }}"
    )
    assert workflow_input_issues(graph, workflow) == ()


def _write_graph(repo: Path, payload: dict[str, object] | None = None) -> Path:
    (repo / "governance/ci-extensions").mkdir(parents=True, exist_ok=True)
    (repo / "schemas").mkdir(parents=True, exist_ok=True)
    for name in ("ci-graph.schema.json", "ci-graph-extension.schema.json"):
        (repo / "schemas" / name).write_bytes((REPO_ROOT / "schemas" / name).read_bytes())
    path = repo / "governance/ci-graph.yml"
    path.write_text(yaml.safe_dump(payload or _graph(), sort_keys=False), encoding="utf-8")
    return path


def _write_required_gates(repo: Path, *targets: str) -> None:
    (repo / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "profile_contract_version": "2.0",
                "release_gate_profile": {
                    "gates": {
                        f"gate-{index}": {"target": target, "status": "required"}
                        for index, target in enumerate(targets)
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _add_self_controller_release_job(
    repo: Path, graph: dict[str, object], *, target: str, installed: str,
) -> None:
    policy_path = repo / "governance/self-governance-policy.yml"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        yaml.safe_dump(
            {
                "runner_security": {
                    "trusted_controller_artifact": {
                        "BCF_BOOTSTRAP_COMMIT_SHA": target,
                    },
                    "trusted_controller_installation": {
                        "installed_commit_sha": installed,
                    },
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    graph["trusted_controller"] = {
        "kind": "self_governance_policy",
        "policy_path": "governance/self-governance-policy.yml",
    }
    graph["commands"]["release-authorize"] = {
        "argv": [
            "{controller}", "ci-github", "release", "authorize",
            "--repository", "${{ github.repository }}",
        ],
        "cwd": ".",
        "environment": {},
    }
    graph["step_components"]["release-authorize"] = {
        "kind": "command",
        "name": "Authorize release",
        "command": "release-authorize",
        "environment": {},
        "produces": [],
        "consumes": [],
    }
    graph["step_components"]["setup-release-python"] = {
        "kind": "action",
        "name": "Provision the declared Python runtime",
        "action": "setup-python",
        "with": {"python-version": "3.12"},
        "environment": {},
        "produces": [],
        "consumes": [],
    }
    job = _job(
        "authorize",
        "release-authorizer",
        resource="trusted-control",
        trust="trusted",
        executor={
            "kind": "component_sequence",
            "components": ["setup-release-python", "release-authorize"],
        },
        components=[],
    )
    job["controller_requirement"] = "current"
    graph["workflows"].append(
        {
            "id": "release",
            "path": ".github/workflows/release.yml",
            "display_name": "Release authority",
            "role": "release",
            "events": [{"type": "workflow_dispatch"}],
            "permissions": {},
            "jobs": [job],
        }
    )


def _extension() -> dict[str, object]:
    job = _job(
        "security-review",
        "security-review-extension",
        needs=["evidence"],
        executor={"kind": "command", "command": "security-review"},
        produces=["security-review-receipt"],
    )
    return {
        "document": {
            "kind": "ci_graph_extension",
            "name": "Fixture security extension",
            "id": "fixture-security-extension",
            "version": "1.0.0",
            "status": "active",
            "path": "governance/ci-extensions/security.yml",
        },
        "schema_version": "1.0",
        "extension": {
            "id": "security",
            "owner": "fixture",
            "rationale": "prove bounded project extension composition",
            "attachment_point": "before-truth",
            "applicability": ["pull_request", "workflow_call"],
            "required_controls": {
                "positive": ["security-review-positive"],
                "negative": ["security-review-negative"],
                "topology": ["security-review-topology"],
                "cleanup": ["security-review-cleanup"],
            },
        },
        "artifacts": {
            "security-review-receipt": {"path": ".artifacts/bcf/security-review", "kind": "lane-input", "scope": "run-attempt", "retention_days": 30}
        },
        "conditions": {},
        "commands": {
            "security-review": {"argv": ["{python}", "scripts/security_review.py"], "cwd": ".", "environment": {}}
        },
        "step_components": {},
        "workflows": [],
        "jobs": [{"workflow": "governance", **job}],
    }


def test_graph_validates_and_composes_registered_extension(tmp_path: Path) -> None:
    graph = _graph()
    extension = _extension()
    extension_path = tmp_path / "governance/ci-extensions/security.yml"
    extension_path.parent.mkdir(parents=True)
    extension_bytes = yaml.safe_dump(extension, sort_keys=False).encode()
    extension_path.write_bytes(extension_bytes)
    graph["extensions"] = [
        {
            "id": "security",
            "path": "governance/ci-extensions/security.yml",
            "sha256": hashlib.sha256(extension_bytes).hexdigest(),
        }
    ]
    _write_graph(tmp_path, graph)

    compiled = validate_ci_graph(tmp_path)

    governance = next(item for item in compiled.workflows if item["id"] == "governance")
    assert [job["id"] for job in governance["jobs"]] == [
        "preflight",
        "evidence",
        "security-review",
        "truth",
    ]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda graph: graph["workflows"][0]["jobs"][0].update({"needs": ["truth"]}), "cycle"),
        (lambda graph: graph["workflows"][1]["jobs"][0].update({"semantic_role": "cheap-preflight"}), "semantic role"),
        (lambda graph: graph["workflows"][0]["jobs"][2].update({"consumes": []}), "fan-in"),
        (lambda graph: graph["workflows"][0]["jobs"][0].update({"resource_class": "missing"}), "resource class"),
        (lambda graph: graph["workflows"][2]["events"].append({"type": "push", "branches": ["main"]}), "push authority"),
        (lambda graph: graph["commands"]["preflight"].update({"argv": ["sleep", "60"]}), "hosted waiter"),
        (lambda graph: graph["commands"]["preflight"].update({"argv": ["gh", "run", "watch"]}), "hosted waiter"),
    ],
)
def test_graph_rejects_semantic_defect_classes(tmp_path: Path, mutate, message: str) -> None:
    graph = copy.deepcopy(_graph())
    mutate(graph)
    _write_graph(tmp_path, graph)

    with pytest.raises(CIGraphError, match=message):
        validate_ci_graph(tmp_path)


def test_evidence_job_timeout_must_contain_inner_gate_deadline_and_headroom(
    tmp_path: Path,
) -> None:
    graph = _graph()
    graph["policy"]["minimum_gate_timeout_headroom_seconds"] = 300
    graph["workflows"][0]["jobs"][1]["timeout_minutes"] = 34
    _write_graph(tmp_path, graph)

    with pytest.raises(CIGraphError, match="cannot contain.*gate timeout.*headroom"):
        validate_ci_graph(tmp_path)


def test_graph_growth_preserves_deterministic_gate_ownership_and_rendering(
    tmp_path: Path,
) -> None:
    graph = _graph()
    graph["workflows"][0]["jobs"][1]["executor"]["gates"] = [
        f"gate-{index:03d}" for index in range(128)
    ]
    _write_graph(tmp_path, graph)

    compiled = validate_ci_graph(tmp_path)
    first = render_ci_graph(tmp_path)
    second = render_ci_graph(tmp_path)

    assert compiled.workflows[0]["jobs"][1]["executor"]["gates"][-1] == "gate-127"
    assert first == second


def _make_explicit_private_transport(graph: dict[str, object]) -> None:
    graph["commands"].update(
        {
            "restore": {"argv": ["python", "restore.py", "--root", ".artifacts/bcf/sessions"], "cwd": ".", "environment": {}},
            "capture": {"argv": ["python", "capture.py"], "cwd": ".", "environment": {}},
        }
    )
    graph["step_components"].update(
        {
            "download-session": {
                "kind": "action", "name": "Download session", "action": "download-artifact",
                "with": {}, "environment": {}, "produces": [], "consumes": ["session"],
            },
            "restore-session": {
                "kind": "command", "name": "Restore session", "command": "restore",
                "restores_private_artifacts": ["session"], "environment": {},
                "produces": [], "consumes": [],
            },
            "capture": {
                "kind": "command", "name": "Capture", "command": "capture",
                "environment": {}, "produces": ["receipts"], "consumes": [],
            },
        }
    )
    evidence = graph["workflows"][0]["jobs"][1]
    evidence["components"] = []
    evidence["executor"] = {
        "kind": "gate_shard", "gates": ["test", "lint"], "shard_key": "shard",
        "shard_count": 2, "components": ["download-session", "restore-session", "capture"],
    }
    evidence["strategy"] = {"fail_fast": True, "matrix": {"shard": [0, 1]}}


@pytest.mark.parametrize("mutation", ["missing", "late", "wrong-condition", "wrong-root"])
def test_explicit_private_artifact_transport_requires_immediate_mode_restore(
    tmp_path: Path, mutation: str,
) -> None:
    graph = copy.deepcopy(_graph())
    _make_explicit_private_transport(graph)
    components = graph["workflows"][0]["jobs"][1]["executor"]["components"]
    if mutation == "missing":
        graph["step_components"]["restore-session"]["restores_private_artifacts"] = []
    elif mutation == "late":
        components[:] = ["download-session", "capture", "restore-session"]
    elif mutation == "wrong-condition":
        graph["conditions"]["never-here"] = "needs.missing.result == 'success'"
        graph["step_components"]["restore-session"]["condition"] = "never-here"
    else:
        graph["commands"]["restore"]["argv"][-1] = ".artifacts/bcf/fan-in"
    _write_graph(tmp_path, graph)

    with pytest.raises(CIGraphError, match="private artifact modes|private mode restoration|condition references unavailable"):
        validate_ci_graph(tmp_path)


def test_job_condition_cannot_reference_an_unavailable_dependency(tmp_path: Path) -> None:
    graph = _graph()
    graph["conditions"]["impossible"] = "needs.missing.result == 'success'"
    graph["workflows"][0]["jobs"][0]["condition"] = "impossible"
    _write_graph(tmp_path, graph)

    with pytest.raises(CIGraphError, match="condition references unavailable needs"):
        validate_ci_graph(tmp_path)


def test_selected_python_must_be_provisioned_before_governed_command(
    tmp_path: Path,
) -> None:
    graph = _graph()
    graph["step_components"].update(
        {
            "invoke-preflight": {
                "kind": "command",
                "name": "Invoke preflight",
                "command": "preflight",
                "environment": {},
                "produces": ["session"],
                "consumes": [],
            },
            "setup-selected-python": {
                "kind": "action",
                "name": "Set up Python",
                "action": "setup-python",
                "with": {"python-version": "3.12"},
                "environment": {},
                "produces": [],
                "consumes": [],
            },
        }
    )
    job = graph["workflows"][0]["jobs"][0]
    job["components"] = []
    job["executor"] = {
        "kind": "component_sequence",
        "components": ["invoke-preflight", "setup-selected-python"],
    }
    _write_graph(tmp_path, graph)

    with pytest.raises(CIGraphError, match="provision selected Python before"):
        validate_ci_graph(tmp_path)


@pytest.mark.parametrize("executable", ["{controller}", "{ephemeral_controller}"])
def test_every_python_backed_governed_executable_requires_selected_runtime(
    tmp_path: Path, executable: str
) -> None:
    graph = _graph()
    graph["commands"]["preflight"]["argv"] = [executable, "--help"]
    job = graph["workflows"][0]["jobs"][0]
    job["components"] = []
    _write_graph(tmp_path, graph)

    with pytest.raises(CIGraphError, match="provision selected Python before"):
        validate_ci_graph(tmp_path)


def test_required_environment_is_bound_once_and_validated_before_checkout(
    tmp_path: Path,
) -> None:
    graph = _graph()
    workflow = graph["workflows"][0]
    job = workflow["jobs"][0]
    graph["commands"]["preflight"]["required_environment"] = ["REQUIRED_TOKEN"]
    job["environment"] = {"REQUIRED_TOKEN": "${{ secrets.REQUIRED_TOKEN }}"}
    _write_graph(tmp_path, graph)

    compiled = validate_ci_graph(tmp_path)
    rendered = yaml.safe_load(render_ci_graph(tmp_path)[".github/workflows/governance.yml"])
    steps = rendered["jobs"]["preflight"]["steps"]
    assert steps[0]["name"] == "Validate all required environment inputs before work"
    assert steps[0]["env"] == {"REQUIRED_TOKEN": "${{ secrets.REQUIRED_TOKEN }}"}
    assert steps[1]["name"] == "Check out the exact candidate commit"
    bindings, issues = job_required_environment(
        compiled.graph,
        next(item for item in compiled.workflows if item["id"] == "governance"),
        next(
            item
            for item in next(
                value for value in compiled.workflows if value["id"] == "governance"
            )["jobs"]
            if item["id"] == "preflight"
        ),
        job["executor"],
    )
    assert bindings == {"REQUIRED_TOKEN": "${{ secrets.REQUIRED_TOKEN }}"}
    assert issues == ()


def test_missing_or_conflicting_required_environment_fails_at_graph_compile(
    tmp_path: Path,
) -> None:
    graph = _graph()
    graph["commands"]["preflight"]["required_environment"] = ["REQUIRED_TOKEN"]
    _write_graph(tmp_path, graph)
    with pytest.raises(CIGraphError, match="missing required environment binding"):
        validate_ci_graph(tmp_path)

    graph["workflows"][0]["jobs"][0]["environment"] = {
        "REQUIRED_TOKEN": "job-value"
    }
    graph["commands"]["preflight"]["environment"]["REQUIRED_TOKEN"] = (
        "command-value"
    )
    _write_graph(tmp_path, graph)
    with pytest.raises(CIGraphError, match="conflicting required environment binding"):
        validate_ci_graph(tmp_path)


def test_graph_diagnostics_cover_every_frozen_prerequisite_kind(tmp_path: Path) -> None:
    graph = _graph()
    graph["commands"]["preflight"]["required_environment"] = ["REQUIRED_TOKEN"]
    graph["workflows"][0]["jobs"][0]["environment"] = {
        "REQUIRED_TOKEN": "${{ secrets.REQUIRED_TOKEN }}"
    }
    _write_graph(tmp_path, graph)

    report = diagnose_ci_graph(tmp_path)

    assert report["status"] == "pass"
    assert {item["kind"] for item in report["diagnostics"]} == {
        "runner",
        "tool",
        "permission",
        "secret",
        "event",
        "graph_input",
    }
    assert all(
        set(item) == {"kind", "identifier", "status", "remediation"}
        for item in report["diagnostics"]
    )


@pytest.mark.parametrize(
    ("mutate", "kind"),
    [
        (
            lambda graph: graph["workflows"][0]["jobs"][0].update(
                {"resource_class": "absent-runner"}
            ),
            "runner",
        ),
        (
            lambda graph: graph["commands"]["preflight"].update(
                {"required_environment": ["ABSENT_TOKEN"]}
            ),
            "secret",
        ),
        (
            lambda graph: graph["workflows"][0]["jobs"][0]["permissions"].update(
                {"statuses": "write"}
            ),
            "permission",
        ),
        (
            lambda graph: graph["workflows"][2]["events"].append(
                {"type": "push", "branches": ["main"]}
            ),
            "event",
        ),
    ],
)
def test_graph_diagnostics_classify_prerequisite_failures(
    tmp_path: Path, mutate, kind: str
) -> None:
    graph = _graph()
    mutate(graph)
    _write_graph(tmp_path, graph)

    report = diagnose_ci_graph(tmp_path)

    assert report["status"] == "fail"
    assert report["diagnostics"][0]["kind"] == kind


def test_trusted_no_checkout_command_rejects_repository_relative_input(
    tmp_path: Path,
) -> None:
    graph = _graph()
    graph["commands"]["trusted-probe"] = {
        "argv": ["{python}", "scripts/probe.py"],
        "cwd": ".",
        "environment": {},
    }
    graph["step_components"].update(
        {
            "setup-selected-python": {
                "kind": "action",
                "name": "Set up Python",
                "action": "setup-python",
                "with": {"python-version": "3.12"},
                "environment": {},
                "produces": [],
                "consumes": [],
            },
            "trusted-probe": {
                "kind": "command",
                "name": "Probe trusted control",
                "command": "trusted-probe",
                "environment": {},
                "produces": [],
                "consumes": [],
            },
        }
    )
    job = graph["workflows"][1]["jobs"][0]
    job["executor"] = {
        "kind": "component_sequence",
        "components": ["setup-selected-python", "trusted-probe"],
    }
    _write_graph(tmp_path, graph)

    with pytest.raises(CIGraphError, match="repository-relative inputs"):
        validate_ci_graph(tmp_path)


def test_trusted_no_checkout_rejects_every_execution_input_surface() -> None:
    def command_environment(graph: dict[str, object], executor: dict[str, object]) -> None:
        graph["commands"]["trusted"]["environment"] = {
            "POLICY": "governance/policy.yml"
        }

    def action_input(graph: dict[str, object], executor: dict[str, object]) -> None:
        graph["step_components"]["subject"] = {
            "kind": "action", "action": "download-artifact",
            "with": {"path": ".artifacts/input"}
        }

    def action_environment(graph: dict[str, object], executor: dict[str, object]) -> None:
        graph["step_components"]["subject"] = {
            "kind": "action", "action": "download-artifact", "with": {},
            "environment": {"POLICY": "governance/policy.yml"},
        }

    def directory_input(graph: dict[str, object], executor: dict[str, object]) -> None:
        graph["step_components"]["subject"] = {
            "kind": "directory_setup", "paths": [".artifacts/output"]
        }

    for mutation in (
        command_environment, action_input, action_environment, directory_input
    ):
        graph: dict[str, object] = {
            "commands": {
                "trusted": {"argv": ["{controller}"], "cwd": ".", "environment": {}}
            },
            "step_components": {
                "setup-python": {"kind": "action", "action": "setup-python"},
                "subject": {"kind": "command", "command": "trusted"},
            },
        }
        executor: dict[str, object] = {
            "kind": "component_sequence", "components": ["setup-python", "subject"]
        }
        job: dict[str, object] = {
            "id": "trusted", "trust": "trusted", "checkout": False,
            "environment": {},
        }
        mutation(graph, executor)
        issues = job_execution_issues(graph, job, executor)
        assert len(issues) == 1
        assert "repository-relative inputs" in issues[0]


def test_renderer_binds_selected_python_to_setup_action_output() -> None:
    rendered = render_ci_graph(REPO_ROOT)
    seen = 0
    for content in rendered.values():
        workflow = yaml.safe_load(content)
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                environment = step.get("env", {})
                if "BCF_PYTHON" not in environment:
                    continue
                seen += 1
                assert environment["BCF_PYTHON"] == (
                    "${{ env.pythonLocation }}/bin/python"
                )
    assert seen > 0


def test_every_rendered_controller_invocation_has_selected_python_first() -> None:
    rendered = render_ci_graph(REPO_ROOT)
    seen = 0
    for path, content in rendered.items():
        workflow = yaml.safe_load(content)
        for job_id, job in workflow["jobs"].items():
            steps = job.get("steps", [])
            setup_indexes = [
                index
                for index, step in enumerate(steps)
                if "setup-python" in step.get("uses", "")
            ]
            for index, step in enumerate(steps):
                if "/bin/bcf" not in step.get("run", ""):
                    continue
                seen += 1
                assert setup_indexes and min(setup_indexes) < index, (
                    f"{path}:{job_id} invokes a Python-backed controller before "
                    "provisioning the selected runtime"
                )
    assert seen > 0


def test_graph_rejects_unregistered_or_changed_extension(tmp_path: Path) -> None:
    _write_graph(tmp_path)
    extension_path = tmp_path / "governance/ci-extensions/security.yml"
    extension_path.write_text(yaml.safe_dump(_extension(), sort_keys=False), encoding="utf-8")
    with pytest.raises(CIGraphError, match="unregistered"):
        validate_ci_graph(tmp_path)


def test_graph_lock_repairs_registered_extension_digest(tmp_path: Path) -> None:
    graph = _graph()
    extension_path = tmp_path / "governance/ci-extensions/security.yml"
    extension_path.parent.mkdir(parents=True)
    extension_path.write_text(yaml.safe_dump(_extension(), sort_keys=False), encoding="utf-8")
    graph["extensions"] = [
        {"id": "security", "path": "governance/ci-extensions/security.yml", "sha256": "0" * 64}
    ]
    _write_graph(tmp_path, graph)
    assert check_ci_graph_locks(tmp_path).status == "drift"
    assert apply_ci_graph_locks(tmp_path).status == "applied"
    assert check_ci_graph_locks(tmp_path).status == "clean"
    assert validate_ci_graph(tmp_path).extension_sha256[0][0] == (
        "governance/ci-extensions/security.yml"
    )

    graph = _graph()
    graph["extensions"] = [
        {"id": "security", "path": "governance/ci-extensions/security.yml", "sha256": "0" * 64}
    ]
    _write_graph(tmp_path, graph)
    with pytest.raises(CIGraphError, match="digest"):
        validate_ci_graph(tmp_path)


def test_extension_requires_all_control_classes_and_exact_applicability(
    tmp_path: Path,
) -> None:
    extension = _extension()
    extension["extension"]["required_controls"].pop("negative")
    extension_path = tmp_path / "governance/ci-extensions/security.yml"
    extension_path.parent.mkdir(parents=True)
    extension_bytes = yaml.safe_dump(extension, sort_keys=False).encode()
    extension_path.write_bytes(extension_bytes)
    graph = _graph()
    graph["extensions"] = [
        {
            "id": "security",
            "path": "governance/ci-extensions/security.yml",
            "sha256": hashlib.sha256(extension_bytes).hexdigest(),
        }
    ]
    _write_graph(tmp_path, graph)
    with pytest.raises(CIGraphError, match="schema"):
        validate_ci_graph(tmp_path)

    extension = _extension()
    extension["extension"]["applicability"] = ["pull_request"]
    extension_bytes = yaml.safe_dump(extension, sort_keys=False).encode()
    extension_path.write_bytes(extension_bytes)
    graph["extensions"][0]["sha256"] = hashlib.sha256(extension_bytes).hexdigest()
    _write_graph(tmp_path, graph)
    with pytest.raises(CIGraphError, match="applicability"):
        validate_ci_graph(tmp_path)


def test_graph_schema_rejects_raw_shell_fragment(tmp_path: Path) -> None:
    graph = _graph()
    graph["workflows"][0]["jobs"][0]["run"] = "curl example.invalid | sh"
    _write_graph(tmp_path, graph)
    with pytest.raises(CIGraphError, match="schema"):
        validate_ci_graph(tmp_path)


def test_release_controller_jobs_fail_closed_until_target_is_installed(
    tmp_path: Path,
) -> None:
    graph = _graph()
    current = "1" * 40
    pending = "2" * 40
    _add_self_controller_release_job(
        tmp_path, graph, target=pending, installed=current,
    )
    _write_graph(tmp_path, graph)

    compiled = validate_ci_graph(tmp_path)
    assert compiled.trusted_controller_current is False
    release = yaml.safe_load(render_ci_graph(tmp_path)[".github/workflows/release.yml"])
    assert release["jobs"]["authorize"]["if"] == "${{ false }}"

    graph["workflows"][-1]["jobs"][0].pop("controller_requirement")
    _write_graph(tmp_path, graph)
    with pytest.raises(CIGraphError, match="must require the current controller"):
        validate_ci_graph(tmp_path)


def test_release_controller_jobs_activate_only_after_mechanical_confirmation(
    tmp_path: Path,
) -> None:
    graph = _graph()
    current = "3" * 40
    _add_self_controller_release_job(
        tmp_path, graph, target=current, installed=current,
    )
    _write_graph(tmp_path, graph)

    compiled = validate_ci_graph(tmp_path)
    assert compiled.trusted_controller_current is True
    release = yaml.safe_load(render_ci_graph(tmp_path)[".github/workflows/release.yml"])
    assert "if" not in release["jobs"]["authorize"]


def test_bcf_exact_main_admission_waits_for_current_controller() -> None:
    graph = yaml.safe_load((REPO_ROOT / "governance/ci-graph.yml").read_text())
    exact_main = next(
        workflow for workflow in graph["workflows"] if workflow["id"] == "exact-main"
    )
    admission = next(job for job in exact_main["jobs"] if job["id"] == "admit")

    assert admission["controller_requirement"] == "current"


def test_pull_request_gate_ownership_exactly_matches_profile(tmp_path: Path) -> None:
    graph = _graph()
    _write_graph(tmp_path, graph)
    _write_required_gates(tmp_path, "test", "lint")
    validate_ci_graph(tmp_path)

    _write_required_gates(tmp_path, "test", "lint", "security-review")
    with pytest.raises(CIGraphError, match=r"missing=\['security-review'\]"):
        validate_ci_graph(tmp_path)


def test_truth_events_are_scoped_to_the_declared_workflow_roots(tmp_path: Path) -> None:
    _write_graph(tmp_path)
    apply_ci_graph(tmp_path)

    issues = graph_workflow_gate_issues(
        tmp_path,
        paths=[".github/workflows/governance.yml"],
        required_events=["push"],
        gate_ids={"test", "lint"},
    )

    assert issues == ["workflow_event_push_missing"]


def test_truth_resolves_bcf_gate_shards_from_the_canonical_graph() -> None:
    profile = yaml.safe_load((REPO_ROOT / "governance-profile.yml").read_text())
    policy = yaml.safe_load(
        (REPO_ROOT / "governance/evidence-policy.yml").read_text()
    )
    workflow = policy["workflow_contract"]
    gates = {
        gate["target"]
        for gate in profile["release_gate_profile"]["gates"].values()
        if gate["status"] == "required"
    }

    assert graph_workflow_gate_issues(
        REPO_ROOT,
        paths=workflow["paths"],
        required_events=workflow["required_events"],
        gate_ids=gates,
    ) == []


def test_renderer_is_deterministic_and_parity_owned(tmp_path: Path) -> None:
    _write_graph(tmp_path)
    first = render_ci_graph(tmp_path)
    second = render_ci_graph(tmp_path)
    assert first == second
    assert set(first) == {
        ".github/workflows/bcf-exact-main.yml",
        ".github/workflows/governance-controls.yml",
        ".github/workflows/governance.yml",
    }
    assert all(value.startswith(b"# Generated by BCF") for value in first.values())

    applied = apply_ci_graph(tmp_path)
    assert applied.status == "applied"
    assert check_ci_graph(tmp_path).status == "clean"
    path = tmp_path / ".github/workflows/governance.yml"
    path.write_bytes(path.read_bytes() + b"# manual drift\n")
    report = check_ci_graph(tmp_path)
    assert report.status == "drift"
    assert report.changed_paths == (".github/workflows/governance.yml",)


def test_standard_reference_graph_is_rich_single_push_authority(tmp_path: Path) -> None:
    gates = [
        "governance-validate",
        "architecture-test",
        "lint",
        "test",
        "security-secret-scan",
        "runtime-smoke",
    ]
    graph = build_reference_ci_graph(
        project_id="fixture",
        profile="standard",
        profile_contract_version="2.0",
        gates=gates,
        candidate_labels=["ubuntu-24.04"],
        trusted_labels=["self-hosted", "fixture-trusted"],
        candidate_hosted=True,
        trusted_hosted=False,
    )
    _write_graph(tmp_path, graph)

    compiled = validate_ci_graph(tmp_path)

    governance = next(item for item in compiled.workflows if item["id"] == "governance")
    expected_producers = [
        job["id"]
        for job in governance["jobs"]
        if job["executor"]["kind"] == "gate_group"
    ]
    argv = compiled.commands["preflight"]["argv"]
    assert [
        argv[index + 1]
        for index, value in enumerate(argv)
        if value == "--expected-producer"
    ] == expected_producers
    assert {event["type"] for event in governance["events"]} == {
        "pull_request",
        "workflow_call",
    }
    assert [job["id"] for job in governance["jobs"]] == [
        "cheap-preflight",
        "structural-evidence",
        "quality-evidence",
        "security-evidence",
        "runtime-evidence",
        "governance-truthfulness",
    ]
    push_workflows = [
        item
        for item in compiled.workflows
        if any(event["type"] == "push" for event in item["events"])
    ]
    assert [item["id"] for item in push_workflows] == ["exact-main"]
    assert {item["id"] for item in compiled.workflows} >= {
        "governance",
        "exact-main",
        "exact-main-finalizer",
        "exact-main-publisher",
        "scheduled-high-value",
        "scheduled-full",
    }
    assert all(
        "sleep" not in " ".join(command["argv"])
        for command in compiled.commands.values()
    )
    assert compiled.graph["policy"]["hosted_orchestration"] == "run_and_done"
    assert set(compiled.graph["policy"]["forbidden_hosted_tokens"]) >= {
        "sleep", "poll", "watch", "wait", "while", "until",
        "wait-for-runner", "lease-runner",
    }


def test_self_graph_run_and_done_policy_is_mechanically_complete() -> None:
    compiled = validate_ci_graph(REPO_ROOT)
    workflows = {workflow["id"]: workflow for workflow in compiled.workflows}
    source = workflows["evidence-storage-qualification-source"]["jobs"][0]
    qualification = {
        job["id"]: job
        for job in workflows["evidence-storage-qualification"]["jobs"]
    }
    publisher = qualification["publish-evidence-input"]
    consumer = qualification["reconstruct-evidence-input"]

    assert compiled.graph["policy"]["hosted_orchestration"] == "run_and_done"
    assert compiled.graph["resource_classes"][source["resource_class"]]["hosted"] is True
    assert compiled.graph["resource_classes"][publisher["resource_class"]]["hosted"] is False
    assert compiled.graph["resource_classes"][consumer["resource_class"]]["hosted"] is True
    assert publisher["needs"] == []
    assert consumer["needs"] == ["publish-evidence-input"]


def test_gate_group_uses_the_canonical_session_selector_before_capture() -> None:
    step = _executor_steps(
        None,
        {"executor": {"kind": "gate_group", "gates": ["test", "lint"]}},
    )[0]

    assert "select-session --session-root .artifacts/bcf/sessions" in step["run"]
    assert "find .artifacts/bcf/sessions" not in step["run"]
    assert step["run"].index("select-session") < step["run"].index("for gate")


@pytest.mark.parametrize(
    ("roots", "copies", "expected_calls"),
    [(0, 0, 0), (1, 0, 2), (1, 4, 2), (2, 0, 0), (2, 4, 0), (0, 4, 0)],
)
def test_rendered_gate_group_selects_only_one_canonical_root_before_capture(
    tmp_path: Path, roots: int, copies: int, expected_calls: int
) -> None:
    sessions = tmp_path / ".artifacts/bcf/sessions"
    sessions.mkdir(parents=True)
    session_ids = [f"{index + 1:032x}" for index in range(max(roots, 1))]
    for session_id in session_ids[:roots]:
        root = sessions / session_id
        root.mkdir(mode=0o700)
        manifest = root / "evidence-session.json"
        manifest.write_text(
            json.dumps({"schema_version": "1.0", "session_id": session_id}) + "\n",
            encoding="utf-8",
        )
        manifest.chmod(0o400)
    for index in range(copies):
        copy = sessions / session_ids[0] / f"gate-{index}" / "evidence-session.json"
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_text("{\"retained\":true}\n", encoding="utf-8")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    observer = scripts / "governance_evidence.py"
    observer.write_text(
        """from pathlib import Path
import sys
from bcf_governance.tooling.evidence_sessions import select_session
if "select-session" in sys.argv:
    root = Path(sys.argv[sys.argv.index("--session-root") + 1])
    try:
        print(select_session(root).manifest_path)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)
else:
    gate = sys.argv[sys.argv.index("--gate") + 1]
    with Path("calls.txt").open("a", encoding="utf-8") as stream:
        stream.write(gate + "\\n")
""",
        encoding="utf-8",
    )
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sessions.rglob("*")
        if path.is_file()
    }
    step = _executor_steps(
        None,
        {"executor": {"kind": "gate_group", "gates": ["test", "lint"]}},
    )[0]

    result = subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "BCF_PYTHON": sys.executable,
            "BCF_GATES": step["env"]["BCF_GATES"],
        },
        capture_output=True,
        text=True,
        check=False,
    )

    calls = (tmp_path / "calls.txt").read_text().splitlines() if (tmp_path / "calls.txt").exists() else []
    assert result.returncode == (0 if roots == 1 else 1)
    assert len(calls) == expected_calls
    assert {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sessions.rglob("*")
        if path.is_file()
    } == before


def test_capture_surfaces_do_not_reimplement_session_root_selection() -> None:
    renderer = (REPO_ROOT / "bcf_governance/tooling/ci_graph_render.py").read_text()
    shard = (REPO_ROOT / ".github/scripts/capture_governance_shard.py").read_text()

    assert "find .artifacts/bcf/sessions" not in renderer
    assert "select-session --session-root" in renderer
    for forbidden in ("evidence-session.json", ".glob(", ".rglob(", ".iterdir("):
        assert forbidden not in shard
    assert "select_session(" in shard


def test_lite_reference_graph_has_no_release_or_trusted_control(tmp_path: Path) -> None:
    graph = build_reference_ci_graph(
        project_id="lite-fixture",
        profile="lite",
        profile_contract_version="1.0",
        gates=["governance-validate", "governance-exposure-scan"],
        candidate_labels=["ubuntu-24.04"],
        trusted_labels=["ubuntu-24.04"],
        candidate_hosted=True,
        trusted_hosted=True,
    )
    _write_graph(tmp_path, graph)
    compiled = validate_ci_graph(tmp_path)
    assert [item["id"] for item in compiled.workflows] == ["governance"]
    assert compiled.workflows[0]["role"] == "exact-main"
    assert {event["type"] for event in compiled.workflows[0]["events"]} == {
        "pull_request",
        "workflow_call",
        "push",
    }


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def test_importer_captures_exact_workflow_shape_and_subject(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "ci-graph@example.invalid")
    _git(tmp_path, "config", "user.name", "CI Graph Test")
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """name: Identity CI
on:
  pull_request:
  schedule:
    - cron: '17 4 * * 1'
permissions:
  contents: read
concurrency:
  group: identity-${{ github.ref }}
  cancel-in-progress: true
jobs:
  preflight:
    name: Cheap preflight
    runs-on: [self-hosted, Linux, X64, identity]
    strategy:
      matrix:
        shard: [one, two]
    steps:
      - uses: actions/checkout@0123456789012345678901234567890123456789
      - name: Scoped cleanup
        if: always()
        run: ./scripts/cleanup.sh
""",
        encoding="utf-8",
    )
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "fixture")

    inventory = inventory_github_workflows(tmp_path)

    assert inventory["subject"] == {
        "commit": _git(tmp_path, "rev-parse", "HEAD"),
        "tree": _git(tmp_path, "rev-parse", "HEAD^{tree}"),
    }
    imported = inventory["workflows"][0]
    assert imported["path"] == ".github/workflows/ci.yml"
    assert set(imported["events"]) == {"pull_request", "schedule"}
    job = imported["jobs"][0]
    assert job["id"] == "preflight"
    assert job["runs_on"] == ["self-hosted", "Linux", "X64", "identity"]
    assert job["matrix"] == {"shard": ["one", "two"]}
    assert job["cleanup_steps"] == [1]
    assert job["definition_sha256"]


def test_bcf_ci_authority_audit_reports_the_complete_effective_graph() -> None:
    report = audit_ci_graph(REPO_ROOT)
    compiled = validate_ci_graph(REPO_ROOT)
    expected_workflow_count = len(compiled.workflows)
    expected_job_count = sum(len(workflow["jobs"]) for workflow in compiled.workflows)

    assert report["status"] == "pass"
    assert report["repository_state"]["available"] is True
    assert report["repository_state"]["status_sha256"]
    assert report["inventory"]["workflow_count"] == expected_workflow_count
    assert report["inventory"]["job_count"] == expected_job_count
    assert report["inventory"]["semantic_role_count"] == expected_job_count
    assert len(report["effective_graph"]) == expected_workflow_count
    assert len(report["inventory"]["gates"]) == 21
    assert sum(
        item["node_count"] for item in report["inventory"]["test_manifests"]
    ) >= 1
    assert report["inventory"]["artifacts"]["governance-receipts"]["scope"] == "run-attempt"
    assert report["inventory"]["receipt_schemas"][0]["sha256"]
    assert "release_ready" in report["inventory"]["truth_claim_dependencies"]
    assert not report["mechanical_findings"]
    assert report["inventory"]["gate_count"] == 21
    assert report["inventory"]["required_status_checks"] == [
        {"context": "bcf/pr-certification", "integration_id": 15368}
    ]
    assert report["timeout_contract"] == {
        "default_gate_seconds": 1800,
        "per_gate_seconds": {},
        "minimum_outer_headroom_seconds": 300,
    }
    assert {item["fact"] for item in report["authority_map"]} >= {
        "workflow_topology",
        "artifact_and_receipt_contracts",
        "workflow_identity_and_expected_jobs",
        "gate_and_outer_job_timeouts",
        "automation_dependency_versions_and_changelog",
    }
    assert report["mechanical_findings"] == []
