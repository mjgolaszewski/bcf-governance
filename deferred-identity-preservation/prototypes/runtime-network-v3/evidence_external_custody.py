"""Mechanical ancestry prerequisite for independently surviving native custody.

The installed outside launcher must select the real immutable native guardian
as budget owner. Passing a PID or an ancestry result is not a registration or
provider grant. This query cannot turn a child of the budget owner into a safe
keeper merely by calling it a separate process or starting a new session.
"""
from __future__ import annotations

import os
from pathlib import Path

from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity


def require_external_custodian(custodian: ProcessIdentity, budget_owner: ProcessIdentity) -> None:
    """Refuse both direct and reparented descendants of the registered budget."""
    if type(custodian) is not ProcessIdentity or type(budget_owner) is not ProcessIdentity:
        raise OwnerAdmissionError("external custody requires actual registered process lifetimes")
    if (ProcessIdentity.observe(custodian.pid) != custodian
            or ProcessIdentity.observe(budget_owner.pid) != budget_owner):
        raise OwnerAdmissionError("external custody process lifetime changed")
    current = custodian.pid
    seen: set[int] = set()
    for _ in range(128):
        if current == budget_owner.pid:
            raise OwnerAdmissionError("lease keeper is inside the consuming native budget tree")
        if current <= 1:
            break
        if current in seen:
            raise OwnerAdmissionError("external custody ancestry is inconsistent")
        seen.add(current)
        try:
            root = Path('/proc', str(current))
            before = (root / 'stat').read_bytes().rsplit(b')', 1)[1].split()
            parent = int(before[1])
            after = (root / 'stat').read_bytes().rsplit(b')', 1)[1].split()
            if before[19] != after[19] or before[1] != after[1]:
                raise OwnerAdmissionError("external custody ancestry changed during observation")
            current = parent
        except (OSError, ValueError, IndexError) as error:
            raise OwnerAdmissionError("external custody ancestry is unproven") from error
    else:
        raise OwnerAdmissionError("external custody ancestry exceeds its finite bound")
    if (ProcessIdentity.observe(custodian.pid) != custodian
            or ProcessIdentity.observe(budget_owner.pid) != budget_owner):
        raise OwnerAdmissionError("external custody process lifetime changed")


def require_current_external_custodian(budget_owner: ProcessIdentity | None) -> None:
    if budget_owner is None:
        raise OwnerAdmissionError("external budget ownership registration is required")
    require_external_custodian(ProcessIdentity.observe(os.getpid()), budget_owner)
