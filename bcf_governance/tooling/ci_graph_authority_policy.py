"""Cross-surface CI graph authority and required-check ownership rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ci_graph_errors import CIGraphError
from .github_protection import load_protection


def validate_graph_authority_policy(repo_root: Path, graph: dict[str, Any]) -> None:
    workflows = graph["workflows"]
    workflow_names = [str(item["display_name"]) for item in workflows]
    if len(workflow_names) != len(set(workflow_names)):
        raise CIGraphError("CI graph workflow display names must be globally unique")
    job_names = [
        str(job["display_name"])
        for workflow in workflows
        for job in workflow["jobs"]
    ]
    if len(job_names) != len(set(job_names)):
        raise CIGraphError("CI graph job display names must be globally unique")
    policy = graph["policy"]
    reserved = policy.get("reserved_status_contexts", [])
    contexts = [str(item["context"]) for item in reserved]
    if len(contexts) != len(set(contexts)):
        raise CIGraphError("CI graph reserved status contexts must be unique")
    jobs_by_role = {
        str(job["semantic_role"]): job
        for workflow in workflows
        for job in workflow["jobs"]
    }
    for owner in reserved:
        job = jobs_by_role.get(str(owner["semantic_role"]))
        if job is None or job["trust"] != "trusted":
            raise CIGraphError(
                f"reserved status context {owner['context']} lacks one trusted semantic owner"
            )
        if job["permissions"].get("checks") != "write":
            raise CIGraphError(
                f"reserved status context {owner['context']} owner lacks checks write"
            )
    check_writers = [
        job
        for workflow in workflows
        for job in workflow["jobs"]
        if job["permissions"].get("checks") == "write"
    ]
    owners = {str(item["semantic_role"]) for item in reserved}
    unexpected = sorted(
        str(job["semantic_role"])
        for job in check_writers
        if job["semantic_role"] not in owners
    )
    if unexpected:
        raise CIGraphError(f"CI graph has unregistered check publishers: {unexpected}")
    protection_path = repo_root / "governance/github-protection.yml"
    if not protection_path.exists():
        return
    protection = load_protection(repo_root)
    declared_context = protection["pr_certification"]["context"]
    if contexts != [declared_context]:
        raise CIGraphError("CI graph and provider protection status contexts differ")
    by_path = {workflow["path"]: workflow for workflow in workflows}
    for producer in protection["pr_certification"]["producer_workflows"]:
        workflow = by_path.get(producer["path"])
        if workflow is None:
            raise CIGraphError(f"PR certification producer is absent: {producer['path']}")
        actual_names = {job["display_name"] for job in workflow["jobs"]}
        missing = sorted(set(producer["required_job_names"]) - actual_names)
        if missing:
            raise CIGraphError(
                f"PR certification producer {producer['id']} lacks jobs {missing}"
            )
