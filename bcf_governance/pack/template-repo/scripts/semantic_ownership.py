#!/usr/bin/env python3
"""Thin public wrapper for vendored semantic-ownership enforcement."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._bcf_runtime.semantic_ownership_scan import main
else:
    from _bcf_runtime.semantic_ownership_scan import main


if __name__ == "__main__":
    main()
