"""Thin self-governance entry point for canonical controller construction."""

from __future__ import annotations

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bcf_governance.tooling.ci_controller_builder import main


if __name__ == "__main__":
    main()
