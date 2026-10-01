"""Canonical provider-event comparison context projections."""

from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Iterator


PROVIDER_EVENT_EXPRESSION = "${{ github.event_name }}"
PULL_REQUEST_BASE_EXPRESSION = "${{ github.event.pull_request.base.sha }}"
DIRECT_COMPARISON_BASE_EXPRESSION = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.base.sha || github.event_name == 'push' && "
    "github.event.before || inputs.comparison_base_sha || '' }}"
)
DIRECT_EVENT_COMPARISON_BASE_EXPRESSION = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.base.sha || github.event.before }}"
)


def direct_comparison_environment(*, explicit_call: bool = True) -> dict[str, str]:
    """Project one canonical event-owned comparison context."""

    return {
        "BCF_PROVIDER_EVENT": PROVIDER_EVENT_EXPRESSION,
        "BCF_COMPARISON_BASE_SHA": (
            DIRECT_COMPARISON_BASE_EXPRESSION
            if explicit_call
            else DIRECT_EVENT_COMPARISON_BASE_EXPRESSION
        ),
        "BCF_PR_BASE_SHA": PULL_REQUEST_BASE_EXPRESSION,
    }


@contextmanager
def local_push_environment(*, base_sha: str, head_sha: str) -> Iterator[None]:
    """Project the exact direct-push context used after protected merge."""

    values: dict[str, str | None] = {
        "BCF_PROVIDER_EVENT": "push",
        "BCF_COMPARISON_BASE_SHA": base_sha,
        "BCF_ENFORCE_PR_CHANGELOG": "false",
        "BCF_PR_BASE_SHA": None,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_SHA": head_sha,
    }
    previous = {key: os.environ.get(key) for key in values}
    for key, value in values.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
