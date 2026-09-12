#!/usr/bin/env python3
"""Thin repository wrapper for BCF durable evidence storage operations."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bcf_governance.tooling.evidence_storage_commands import main


if __name__ == "__main__":
    main()
