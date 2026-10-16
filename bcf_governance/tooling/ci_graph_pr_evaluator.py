"""Canonical ordinary-adopter PR evaluator graph projection."""

from __future__ import annotations

from typing import Any

from .ci_graph_builders import component, job
from .ci_graph_execution import (
    CANDIDATE_MATERIALIZATION_RELATIVE,
    CANDIDATE_MATERIALIZATION_ROOT,
)


def apply_standard_pr_evaluator(graph: dict[str, Any]) -> None:
    """Project candidate-independent Standard-v3 merge evaluation."""

    graph["policy"]["reserved_status_contexts"] = [{
        "context": "bcf/pr-certification",
        "semantic_role": "pr-certification-status-publisher",
    }]
    graph["artifacts"]["pr-finalization"] = {
        "path": ".artifacts/bcf/pr-finalization", "kind": "control",
        "scope": "run-attempt", "retention_days": 30,
    }
    graph["conditions"].update({
        "pr-producer-completed": "github.event.workflow_run.event == 'pull_request'",
        "pr-finalizer-success": "github.event.workflow_run.conclusion == 'success'",
    })
    graph["commands"].update({
        "pr-finalize-protected-base": {
            "argv": [
                "{python}", "-m", "bcf_governance.cli", "ci-github", "pr", "finalize",
                "--repository", "${{ github.repository }}", "--output",
                "${{ runner.temp }}/bcf-pr-finalization", "--candidate-root",
                CANDIDATE_MATERIALIZATION_ROOT,
            ], "cwd": ".", "environment": {},
        },
        "pr-publish-protected-base": {
            "argv": [
                "{python}", "-m", "bcf_governance.cli", "ci-github", "pr", "publish",
                "--repository", "${{ github.repository }}", "--bundle",
                "${{ runner.temp }}/bcf-pr-finalization", "--target-url",
                "https://github.com/${{ github.repository }}/actions/runs/${{ github.event.workflow_run.id }}",
            ], "cwd": ".", "environment": {},
        },
    })
    graph["step_components"].update({
        "checkout-protected-pr-base": component(
            kind="action", name="Check out the exact protected PR base evaluator",
            action="checkout", **{"with": {
                "ref": "${{ github.workflow_sha }}",
                "persist-credentials": False,
            }},
        ),
        "checkout-protected-finalizer-base": component(
            kind="action", name="Check out the exact protected finalizer base evaluator",
            action="checkout", **{"with": {
                "ref": "${{ github.workflow_sha }}",
                "persist-credentials": False,
            }},
        ),
        "checkout-pr-candidate-material": component(
            kind="action", name="Materialize the exact candidate without executing its evaluator",
            action="checkout", **{"with": {
                "ref": "${{ github.event.workflow_run.head_sha }}",
                "path": CANDIDATE_MATERIALIZATION_RELATIVE,
                "persist-credentials": False,
            }},
        ),
        "pr-finalize-protected-base": component(
            kind="command", name="Evaluate the exact candidate with protected-base authority",
            command="pr-finalize-protected-base",
            environment={"GITHUB_TOKEN": "${{ github.token }}"},
            produces=["pr-finalization"],
        ),
        "upload-pr-finalization": component(
            kind="action", name="Upload the authenticated PR observation",
            action="upload-artifact", produces=["pr-finalization"], **{"with": {
                "name": "bcf-pr-finalization-${{ github.run_id }}-${{ github.run_attempt }}",
                "path": "${{ runner.temp }}/bcf-pr-finalization",
                "if-no-files-found": "error", "retention-days": 30,
            }},
        ),
        "download-pr-finalization": component(
            kind="action", name="Download only the triggering finalizer observation",
            action="download-artifact", consumes=["pr-finalization"], **{"with": {
                "name": "bcf-pr-finalization-${{ github.event.workflow_run.id }}-${{ github.event.workflow_run.run_attempt }}",
                "github-token": "${{ github.token }}", "repository": "${{ github.repository }}",
                "run-id": "${{ github.event.workflow_run.id }}",
                "path": "${{ runner.temp }}/bcf-pr-finalization",
            }},
        ),
        "pr-publish-protected-base": component(
            kind="command", name="Publish the exact independent PR certification",
            command="pr-publish-protected-base",
            environment={"GITHUB_TOKEN": "${{ github.token }}"},
        ),
    })
    graph["workflows"].extend([
        {
            "id": "pr-finalizer", "path": ".github/workflows/bcf-pr-finalizer.yml",
            "display_name": "bcf/pr-finalizer", "role": "trusted-control",
            "events": [{"type": "workflow_run", "workflows": [
                "Governance pull-request evidence"
            ], "types": ["completed"]}],
            "permissions": {"actions": "read", "contents": "read", "pull-requests": "read"},
            "jobs": [job(
                "finalize", "pr-certification-finalizer", resource="trusted-control",
                trust="trusted", condition="pr-producer-completed", checkout=False,
                executor={"kind": "component_sequence", "evaluator_source": "protected_base",
                    "components": ["checkout-protected-pr-base", "checkout-pr-candidate-material",
                        "setup-python", "install-governance", "pr-finalize-protected-base",
                        "upload-pr-finalization"]},
                produces=["pr-finalization"],
                permissions={"actions": "read", "contents": "read", "pull-requests": "read"},
            )],
        },
        {
            "id": "pr-status-publisher", "path": ".github/workflows/bcf-pr-status-publisher.yml",
            "display_name": "bcf/pr-status-publisher", "role": "trusted-control",
            "events": [{"type": "workflow_run", "workflows": ["bcf/pr-finalizer"],
                "types": ["completed"]}],
            "permissions": {"actions": "read", "checks": "write", "contents": "read",
                "pull-requests": "read"},
            "jobs": [job(
                "publish", "pr-certification-status-publisher", resource="trusted-control",
                trust="trusted", condition="pr-finalizer-success", checkout=False,
                executor={"kind": "component_sequence", "evaluator_source": "protected_base",
                    "components": ["checkout-protected-finalizer-base", "setup-python",
                        "install-governance", "download-pr-finalization",
                        "pr-publish-protected-base"]},
                consumes=["pr-finalization"],
                permissions={"actions": "read", "checks": "write", "contents": "read",
                    "pull-requests": "read"},
            )],
        },
    ])
