from __future__ import annotations

from contextlib import ExitStack

import pytest

from bcf_governance.tooling.local_execution_admission import (
    LocalExecutionAdmissionError,
    local_gate_lease,
)


def test_competing_local_gate_fails_busy_before_work() -> None:
    first = "a" * 40
    second = "b" * 40
    with ExitStack() as stack:
        stack.enter_context(local_gate_lease(first))
        with pytest.raises(LocalExecutionAdmissionError, match="busy_deferred"):
            stack.enter_context(local_gate_lease(second))


def test_local_gate_requires_exact_execution_identity() -> None:
    with pytest.raises(LocalExecutionAdmissionError, match="identity"):
        with local_gate_lease("branch-name"):
            pass
