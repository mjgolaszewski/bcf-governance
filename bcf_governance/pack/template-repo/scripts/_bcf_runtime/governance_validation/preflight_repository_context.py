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
    if event in {"schedule", "workflow_dispatch"}:
        if mode != "release":
            raise ValueError("non-comparison provider event requires release preflight mode")
        forbidden = {
            name: os.environ.get(name, "")
            for name in (
                "BCF_COMPARISON_BASE_SHA",
                "BCF_ORIGIN_COMPARISON_BASE_SHA",
                "BCF_CALLER_COMPARISON_BASE_SHA",
                "BCF_PR_BASE_SHA",
            )
        }
        if any(forbidden.values()):
            raise ValueError("non-comparison provider event cannot carry comparison identity")
        return {
            "applicable": False,
            "event": event,
            "provenance": "authenticated_non_comparison_event",
        }
    if event not in {"pull_request", "push"}:
        raise ValueError("repository comparison event is not supported")
    invocation = os.environ.get("BCF_INVOCATION_KIND", "")
    if invocation not in {"direct_event", "reusable_call"}:
        raise ValueError("repository comparison invocation kind is missing or unsupported")
    base = os.environ.get("BCF_COMPARISON_BASE_SHA", "")
    if not base and event == "pull_request":
        base = os.environ.get("BCF_PR_BASE_SHA", "")
    if not re.fullmatch(r"[a-f0-9]{40,64}", base):
        raise ValueError("repository preflight requires exact comparison base SHA")
    if set(base) == {"0"}:
        raise ValueError("repository comparison base SHA cannot be the zero object")
    origin_base = os.environ.get("BCF_ORIGIN_COMPARISON_BASE_SHA", "")
    caller_base = os.environ.get("BCF_CALLER_COMPARISON_BASE_SHA", "")
    if origin_base != base:
        raise ValueError("repository comparison base does not match provider origin")
    if invocation == "reusable_call":
        if not caller_base or caller_base != base:
            raise ValueError("reusable comparison base does not match caller input")
    elif caller_base:
        raise ValueError("direct event cannot carry a reusable caller comparison base")
    if event == "pull_request":
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
        "invocation_kind": invocation,
        "base_sha": base,
        "provenance": (
            "pull_request.base.sha"
            if invocation == "direct_event" and event == "pull_request"
            else "push.before"
            if invocation == "direct_event"
            else "workflow_call.input"
        ),
    }
