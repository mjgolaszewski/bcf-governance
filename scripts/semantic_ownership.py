#!/usr/bin/env python3
"""Thin public wrapper for semantic-ownership enforcement."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bcf_governance.tooling.semantic_ownership_scan import main


if __name__ == "__main__":
    main()
