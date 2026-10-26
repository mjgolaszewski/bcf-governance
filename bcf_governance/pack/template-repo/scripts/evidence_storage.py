#!/usr/bin/env python3
"""Thin repository wrapper for BCF durable evidence storage operations."""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._bcf_runtime.evidence_storage_commands import main
else:
    from _bcf_runtime.evidence_storage_commands import main


if __name__ == "__main__":
    main()
