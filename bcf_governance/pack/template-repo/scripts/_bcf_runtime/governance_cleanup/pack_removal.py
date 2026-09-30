"""Apply the typed custody operation contract before pack removal."""

from __future__ import annotations

from pathlib import Path

from ..governance_install.runtime_custody import inspect_runtime_custody
from ..governance_install.runtime_custody_operations import (
    RuntimeCustodyOperation,
    decide_runtime_custody_operation,
)
from ..install_governance_pack import _template_root


def governed_pack_removal_paths(repo_root: Path) -> tuple[str, ...]:
    """Reject removal until an independent deletion-authority contract exists."""

    snapshot = inspect_runtime_custody(
        repo_root,
        schema_path=_template_root() / "schemas/bcf-runtime-lock.schema.json",
    )
    decision = decide_runtime_custody_operation(
        snapshot,
        RuntimeCustodyOperation.REMOVE_RUNTIME,
    )
    raise ValueError(decision.disposition.value)
