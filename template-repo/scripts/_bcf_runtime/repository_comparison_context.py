"""Canonical provider-event comparison context projections."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from .bootstrap.contracts import ScopedExecutionEnvironment
from .bootstrap.environment import (
    scoped_execution_environment as _default_scoped_execution_environment,
)

PROVIDER_EVENT_EXPRESSION = "${{ github.event_name }}"
PULL_REQUEST_BASE_EXPRESSION = "${{ github.event.pull_request.base.sha }}"
PUSH_COMPARISON_BASE_EXPRESSION = "${{ github.event.before }}"
CALLER_COMPARISON_BASE_EXPRESSION = "${{ inputs.comparison_base_sha || '' }}"
ORIGIN_COMPARISON_BASE_EXPRESSION = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.base.sha || github.event_name == 'push' && "
    "github.event.before || '' }}"
)
INVOCATION_KIND_EXPRESSION = (
    "${{ inputs.comparison_base_sha != '' && 'reusable_call' || 'direct_event' }}"
)
DIRECT_COMPARISON_BASE_EXPRESSION = (
    "${{ inputs.comparison_base_sha || github.event_name == 'pull_request' && "
    "github.event.pull_request.base.sha || github.event_name == 'push' && "
    "github.event.before || '' }}"
)
DIRECT_EVENT_COMPARISON_BASE_EXPRESSION = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.base.sha || github.event.before }}"
)


def comparison_base_input_contract() -> dict[str, object]:
    """Return the one reusable-workflow comparison input contract."""

    return {
        "description": "Exact repository comparison base for explicit calls",
        "required": True,
        "type": "string",
    }


def push_comparison_inputs(**inputs: object) -> dict[str, object]:
    """Bind reusable execution inputs to the authenticated outer push."""

    return {"comparison_base_sha": PUSH_COMPARISON_BASE_EXPRESSION, **inputs}


def direct_comparison_environment(*, explicit_call: bool = True) -> dict[str, str]:
    """Project one canonical event-owned comparison context."""

    return {
        "BCF_PROVIDER_EVENT": PROVIDER_EVENT_EXPRESSION,
        "BCF_INVOCATION_KIND": INVOCATION_KIND_EXPRESSION,
        "BCF_CALLER_COMPARISON_BASE_SHA": CALLER_COMPARISON_BASE_EXPRESSION,
        "BCF_ORIGIN_COMPARISON_BASE_SHA": ORIGIN_COMPARISON_BASE_EXPRESSION,
        "BCF_COMPARISON_BASE_SHA": (
            DIRECT_COMPARISON_BASE_EXPRESSION
            if explicit_call
            else DIRECT_EVENT_COMPARISON_BASE_EXPRESSION
        ),
        "BCF_PR_BASE_SHA": PULL_REQUEST_BASE_EXPRESSION,
    }


@contextmanager
def local_push_environment(
    *,
    base_sha: str,
    head_sha: str,
    scoped_environment: ScopedExecutionEnvironment | None=None,
) -> Iterator[None]:
    """Project the exact direct-push context used after protected merge."""
    scoped_environment = _default_scoped_execution_environment() if scoped_environment is None else scoped_environment

    values: dict[str, str | None] = {
        "BCF_PROVIDER_EVENT": "push",
        "BCF_INVOCATION_KIND": "direct_event",
        "BCF_CALLER_COMPARISON_BASE_SHA": None,
        "BCF_ORIGIN_COMPARISON_BASE_SHA": base_sha,
        "BCF_COMPARISON_BASE_SHA": base_sha,
        "BCF_ENFORCE_PR_CHANGELOG": "false",
        "BCF_PR_BASE_SHA": None,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_SHA": head_sha,
    }
    with scoped_environment.comparison(values):
        yield
