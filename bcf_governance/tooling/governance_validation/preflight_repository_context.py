"""Cheap provider-independent repository context checks for preflight."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
from typing import Any


def pr_context(repo_root: Path, mode: str) -> dict[str, Any]:
    """Authenticate event-owned comparison context independently of intent."""

    declared_event = os.environ.get("BCF_PROVIDER_EVENT", "")
    ambient_event = os.environ.get("GITHUB_EVENT_NAME", "")
    if declared_event and ambient_event and declared_event != ambient_event:
        raise ValueError("provider comparison event does not match GITHUB_EVENT_NAME")
    event = declared_event or ambient_event
    if not event:
        if mode != "pr":
            return {"applicable": False}
        event = "pull_request"
    if event not in {"pull_request", "pull_request_target", "push", "workflow_call"}:
        raise ValueError("repository comparison event is not supported")
    base = os.environ.get("BCF_COMPARISON_BASE_SHA", "")
    if not base and event in {"pull_request", "pull_request_target"}:
        base = os.environ.get("BCF_PR_BASE_SHA", "")
    if not re.fullmatch(r"[a-f0-9]{40,64}", base):
        raise ValueError("repository preflight requires exact comparison base SHA")
    if set(base) == {"0"}:
        raise ValueError("repository comparison base SHA cannot be the zero object")
    if event in {"pull_request", "pull_request_target"}:
        pr_base = os.environ.get("BCF_PR_BASE_SHA", "")
        if pr_base != base:
            raise ValueError("pull-request comparison base does not match BCF_PR_BASE_SHA")
    available = subprocess.run(
        ["git", "cat-file", "-e", f"{base}^{{commit}}"],
        cwd=repo_root,
        check=False,
    )
    if available.returncode != 0:
        raise ValueError("repository comparison base commit is unavailable")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, "HEAD"],
        cwd=repo_root,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("repository comparison base SHA is not an ancestor of HEAD")
    return {
        "applicable": True,
        "event": event,
        "base_sha": base,
        "provenance": (
            "pull_request.base.sha"
            if event in {"pull_request", "pull_request_target"}
            else "push.before" if event == "push" else "workflow_call.input"
        ),
    }
