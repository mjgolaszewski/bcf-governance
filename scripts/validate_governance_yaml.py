"""Validate core YAML governance artifacts for the template governance pack."""

from __future__ import annotations

from pathlib import Path
import sys

_SCRIPT_ROOT = Path(__file__).resolve().parent
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))

from governance_validation.runner import (  # noqa: E402
    GovernanceValidationError,
    main,
    validate_repo_root,
)
from governance_validation.common import (  # noqa: E402
    MAKE_INVOKED_TARGET_PATTERN,
    PLACEHOLDER_PATTERN,
    RELEASE_GATE_INACTIVE_STATUSES,
    RELEASE_GATE_PLACEHOLDER_MARKERS,
    _load_yaml,
)
from governance_validation.release_gates import (  # noqa: E402
    _makefile_target_bodies,
    _meaningful_make_commands,
    _release_gate_makefile_path,
    _release_gates_from_profile,
    _validate_release_gate_command_semantics,
)

__all__ = [
    "GovernanceValidationError",
    "MAKE_INVOKED_TARGET_PATTERN",
    "PLACEHOLDER_PATTERN",
    "RELEASE_GATE_INACTIVE_STATUSES",
    "RELEASE_GATE_PLACEHOLDER_MARKERS",
    "_load_yaml",
    "_makefile_target_bodies",
    "_meaningful_make_commands",
    "_release_gate_makefile_path",
    "_release_gates_from_profile",
    "_validate_release_gate_command_semantics",
    "main",
    "validate_repo_root",
]


if __name__ == "__main__":
    main()
