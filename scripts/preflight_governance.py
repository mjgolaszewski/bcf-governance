#!/usr/bin/env python3
"""Thin public wrapper for the deterministic governance preflight."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bcf_governance.tooling.preflight import main


if __name__ == "__main__":
    main()
