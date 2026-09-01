"""Reference CI graph construction for fresh Lite and Standard repositories."""

from __future__ import annotations

import re
from typing import Any


EXTENSION_POINTS = [
    "preflight",
    "evidence-lane",
    "before-truth",
    "after-truth",
    "exact-main-producer",
    "trusted-control",
    "scheduled-lane",
    "release-role",
]


def _identifier(value: str) -> str:
    result = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-")
    return result or "project"


def _resource(
    labels: list[str], *, trust: str, hosted: bool, capabilities: list[str]
) -> dict[str, Any]:
    return {
        "runner": labels[0] if len(labels) == 1 else labels,
        "trust": trust,
        "hosted": hosted,
        "python_version": "3.12",
        "capabilities": capabilities,
    }


def _job(
    job_id: str,
    role: str,
    *,
    resource: str = "candidate-python",
    trust: str = "candidate",
    needs: list[str] | None = None,
    condition: str = "success",
    executor: dict[str, Any],
    produces: list[str] | None = None,
    consumes: list[str] | None = None,
    components: list[str] | None = None,
    permissions: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "id": job_id,
        "display_name": role.replace("-", " ").title(),
        "semantic_role": role,
        "resource_class": resource,
        "trust": trust,
        "needs": needs or [],
        "condition": condition,
        "timeout_minutes": 45 if trust == "candidate" else 5,
        "permissions": permissions or {"contents": "read"},
        "checkout": trust == "candidate" and executor["kind"] != "reusable_workflow",
        "components": components
        if components is not None
        else (["checkout", "python", "governance-dependencies"] if trust == "candidate" else []),
        "executor": executor,
        "produces": produces or [],
        "consumes": consumes or [],
        "required": True,
    }


def _lane_groups(gates: list[str]) -> list[tuple[str, list[str]]]:
    groups: dict[str, list[str]] = {
        "structural": [],
        "quality": [],
        "security": [],
        "runtime": [],
    }
    for gate in gates:
        if gate.startswith(("governance-", "architecture-", "semantic-ownership")):
            groups["structural"].append(gate)
        elif gate.startswith("security-"):
            groups["security"].append(gate)
        elif gate.startswith("runtime-"):
            groups["runtime"].append(gate)
        else:
            groups["quality"].append(gate)
    return [(name, values) for name, values in groups.items() if values]


def _preflight_argv(expected_producers: list[str]) -> list[str]:
    return [
        "{python}",
        "scripts/preflight_governance.py",
        "--repo-root",
        ".",
        "--mode",
        "{env:BCF_PREFLIGHT_MODE}",
        "--python",
        "{python}",
        "--artifact-root",
        ".artifacts/bcf",
        *[
            value
            for producer in expected_producers
            for value in ("--expected-producer", producer)
        ],
        "--format",
        "text",
    ]


def build_reference_ci_graph(
    *,
    project_id: str,
    profile: str,
    profile_contract_version: str,
    gates: list[str],
    candidate_labels: list[str],
    trusted_labels: list[str],
    candidate_hosted: bool,
    trusted_hosted: bool,
    include_release_roles: bool = False,
) -> dict[str, Any]:
    """Build the complete graph contract; rendering is owned elsewhere."""

    project = _identifier(project_id)
    if profile not in {"lite", "standard", "regulated"}:
        raise ValueError(f"unsupported CI graph profile {profile}")
    if not gates or not candidate_labels or not trusted_labels:
        raise ValueError("CI graph requires gates and explicit candidate/trusted runner mappings")
    lane_groups = _lane_groups(gates)
    lane_producers = [f"{lane}-evidence" for lane, _ in lane_groups]
    artifacts: dict[str, Any] = {
        "evidence-session": {
            "path": ".artifacts/bcf/sessions",
            "kind": "session",
            "scope": "run-attempt",
            "retention_days": 30,
        },
        "truth-report": {
            "path": ".artifacts/bcf/truth-report.json",
            "kind": "terminal",
            "scope": "run-attempt",
            "retention_days": 30,
        },
        "exact-main-certification": {
            "path": ".artifacts/bcf/exact-main-certification",
            "kind": "control",
            "scope": "run-attempt",
            "retention_days": 30,
        },
    }
    commands: dict[str, Any] = {
        "preflight": {
            "argv": _preflight_argv(lane_producers),
            "cwd": ".",
            "environment": {
                "BCF_PREFLIGHT_MODE": "${{ github.event_name == 'pull_request' && 'pr' || 'release' }}",
                "BCF_ENFORCE_PR_CHANGELOG": "${{ github.event_name == 'pull_request' }}",
                "BCF_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
            },
        },
        "truth": {
            "argv": [
                "{python}",
                "scripts/governance_truth.py",
                "--repo-root",
                ".",
                "--evidence-dir",
                ".artifacts/bcf",
                "--evaluation-mode",
                "{env:BCF_TRUTH_MODE}",
                "--format",
                "json",
                "--durable-ref",
                "github-actions://${{ github.repository }}/runs/${{ github.run_id }}/attempts/${{ github.run_attempt }}/bcf-governance-truth",
                "--output",
                ".artifacts/bcf/truth-report.json",
            ],
            "cwd": ".",
            "environment": {
                "BCF_TRUTH_MODE": "${{ github.event_name == 'pull_request' && 'pr' || 'closure' }}"
            },
        },
    }
    lane_jobs: list[dict[str, Any]] = []
    lane_artifacts: list[str] = []
    for lane, lane_gates in lane_groups:
        artifact = f"{lane}-receipts"
        artifacts[artifact] = {
            "path": ".artifacts/bcf/sessions",
            "kind": "lane-input",
            "scope": "run-attempt",
            "retention_days": 30,
        }
        lane_artifacts.append(artifact)
        lane_jobs.append(
            _job(
                f"{lane}-evidence",
                f"{lane}-evidence",
                needs=["cheap-preflight"],
                executor={"kind": "gate_group", "gates": lane_gates},
                produces=[artifact],
                consumes=["evidence-session"],
                components=[
                    "checkout",
                    "python",
                    "governance-dependencies",
                    "download-evidence",
                    "restore-private-modes",
                ],
            )
        )
    governance_jobs = [
        _job(
            "cheap-preflight",
            "cheap-preflight",
            executor={"kind": "command", "command": "preflight"},
            produces=["evidence-session"],
        ),
        *lane_jobs,
        _job(
            "governance-truthfulness",
            "terminal-governance-truth",
            needs=[job["id"] for job in lane_jobs],
            condition="always",
            executor={"kind": "truth", "command": "truth"},
            produces=["truth-report"],
            consumes=lane_artifacts,
            components=[
                "checkout",
                "python",
                "governance-dependencies",
                "download-evidence",
                "restore-private-modes",
            ],
        ),
    ]
    workflows: list[dict[str, Any]] = [
        {
            "id": "governance",
            "path": ".github/workflows/governance.yml",
            "display_name": "Governance pull-request evidence",
            "role": "pull-request",
            "events": [{"type": "pull_request"}, {"type": "workflow_call"}],
            "permissions": {"contents": "read"},
            "concurrency": {
                "group": f"{project}-pr-${{{{ github.event.pull_request.number || github.ref }}}}",
                "cancel_in_progress": True,
            },
            "jobs": governance_jobs,
        }
    ]
    if profile != "lite":
        def scheduled_workflow(
            workflow_id: str,
            path: str,
            display_name: str,
            cron: str,
            scheduled_gates: list[str],
        ) -> dict[str, Any]:
            session_artifact = f"{workflow_id}-session"
            receipt_artifact = f"{workflow_id}-receipts"
            truth_artifact = f"{workflow_id}-truth"
            artifacts.update(
                {
                    session_artifact: {
                        "path": ".artifacts/bcf/sessions",
                        "kind": "session",
                        "scope": "run-attempt",
                        "retention_days": 30,
                    },
                    receipt_artifact: {
                        "path": ".artifacts/bcf/sessions",
                        "kind": "lane-input",
                        "scope": "run-attempt",
                        "retention_days": 30,
                    },
                    truth_artifact: {
                        "path": ".artifacts/bcf/truth-report.json",
                        "kind": "terminal",
                        "scope": "run-attempt",
                        "retention_days": 30,
                    },
                }
            )
            preflight_id = f"{workflow_id}-preflight"
            controls_id = f"{workflow_id}-controls"
            preflight_command = f"{workflow_id}-preflight"
            commands[preflight_command] = {
                **commands["preflight"],
                "argv": _preflight_argv([controls_id]),
            }
            return {
                "id": workflow_id,
                "path": path,
                "display_name": display_name,
                "role": "scheduled",
                "events": [
                    {"type": "schedule", "cron": [cron]},
                    {"type": "workflow_dispatch"},
                ],
                "permissions": {"contents": "read"},
                "jobs": [
                    _job(
                        preflight_id,
                        f"{workflow_id}-cheap-preflight",
                        executor={"kind": "command", "command": preflight_command},
                        produces=[session_artifact],
                    ),
                    _job(
                        controls_id,
                        f"{workflow_id}-controls",
                        needs=[preflight_id],
                        executor={"kind": "gate_group", "gates": scheduled_gates},
                        produces=[receipt_artifact],
                        consumes=[session_artifact],
                        components=[
                            "checkout",
                            "python",
                            "governance-dependencies",
                            "download-evidence",
                            "restore-private-modes",
                        ],
                    ),
                    _job(
                        f"{workflow_id}-truth",
                        f"{workflow_id}-truth",
                        needs=[controls_id],
                        condition="always",
                        executor={"kind": "truth", "command": "truth"},
                        produces=[truth_artifact],
                        consumes=[receipt_artifact],
                        components=[
                            "checkout",
                            "python",
                            "governance-dependencies",
                            "download-evidence",
                            "restore-private-modes",
                        ],
                    ),
                ],
            }
        workflows.extend(
            [
                {
                    "id": "exact-main",
                    "path": ".github/workflows/bcf-exact-main.yml",
                    "display_name": "BCF exact-main admission",
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
                            permissions={"actions": "read", "contents": "read", "statuses": "write"},
                        ),
                        _job(
                            "governance-producer",
                            "exact-main-governance-producer",
                            needs=["admit"],
                            executor={
                                "kind": "reusable_workflow",
                                "path": ".github/workflows/governance.yml",
                                "inputs": {},
                            },
                            components=[],
                        ),
                    ],
                },
                {
                    "id": "exact-main-finalizer",
                    "path": ".github/workflows/bcf-trusted-finalizer.yml",
                    "display_name": "BCF exact-main trusted finalizer",
                    "role": "trusted-control",
                    "events": [{"type": "workflow_run", "workflows": ["BCF exact-main admission"], "types": ["completed"]}],
                    "permissions": {"actions": "read", "contents": "read"},
                    "jobs": [
                        _job(
                            "finalize",
                            "exact-main-trusted-finalizer",
                            resource="trusted-control",
                            trust="trusted",
                            condition="always",
                            executor={"kind": "authority", "operation": "finalize"},
                            produces=["exact-main-certification"],
                            permissions={"actions": "read", "contents": "read"},
                        )
                    ],
                },
                {
                    "id": "exact-main-publisher",
                    "path": ".github/workflows/bcf-status-publisher.yml",
                    "display_name": "BCF exact-main status publisher",
                    "role": "trusted-control",
                    "events": [{"type": "workflow_run", "workflows": ["BCF exact-main trusted finalizer"], "types": ["completed"]}],
                    "permissions": {"actions": "read", "contents": "read", "statuses": "write"},
                    "jobs": [
                        _job(
                            "publish",
                            "exact-main-status-publisher",
                            resource="trusted-control",
                            trust="trusted",
                            condition="always",
                            executor={"kind": "authority", "operation": "publish"},
                            consumes=["exact-main-certification"],
                            permissions={"actions": "read", "contents": "read", "statuses": "write"},
                        )
                    ],
                },
                scheduled_workflow(
                    "scheduled-high-value",
                    ".github/workflows/governance-mutants-nightly.yml",
                    "Nightly high-value governance controls",
                    "17 4 * * *",
                    gates,
                ),
                scheduled_workflow(
                    "scheduled-full",
                    ".github/workflows/governance-mutants-weekly.yml",
                    "Weekly full governance controls",
                    "31 5 * * 0",
                    gates,
                ),
            ]
        )
    if profile == "lite":
        workflows[0]["events"].append({"type": "push", "branches": ["main"]})
        workflows[0]["role"] = "exact-main"
    return {
        "document": {
            "kind": "ci_graph",
            "name": f"{project_id} CI Graph",
            "id": f"{project}-ci-graph",
            "version": "1.0.0",
            "status": "active",
            "path": "governance/ci-graph.yml",
        },
        "schema_version": "1.0",
        "provider": "github",
        "profile_contract_version": profile_contract_version,
        "default_branch": "main",
        "trusted_controller": {"kind": "executable", "executable": "bcf"},
        "value_sources": {},
        "extension_points": EXTENSION_POINTS,
        "extensions": [],
        "resource_classes": {
            "candidate-python": _resource(
                candidate_labels,
                trust="candidate",
                hosted=candidate_hosted,
                capabilities=["python", "git"],
            ),
            "trusted-control": _resource(
                trusted_labels,
                trust="trusted",
                hosted=trusted_hosted,
                capabilities=["provider-api"],
            ),
        },
        "artifacts": artifacts,
        "conditions": {},
        "commands": commands,
        "step_components": {},
        "workflows": workflows,
        "policy": {
            "exact_gate_once": True,
            "complete_evidence_fan_in": True,
            "single_push_authority": True,
            "generated_workflows_only": True,
            "forbid_hosted_waiters": True,
            "forbidden_hosted_tokens": ["sleep", "poll", "wait-for-runner", "lease-runner"],
        },
    }
