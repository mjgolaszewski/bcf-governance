"""Compatibility wrapper for the canonical portable mode owner."""

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bcf_governance.tooling.evidence_modes import main, restore  # noqa: E402


if __name__ == "__main__":
    main()
