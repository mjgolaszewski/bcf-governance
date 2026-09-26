"""Compatibility wrapper for the canonical portable shard owner."""

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bcf_governance.tooling.evidence_shards import (  # noqa: E402
    partition_required_gates,
    required_gate_targets,
    workflow_shard_matrix,
    main,
)


if __name__ == "__main__":
    main()
