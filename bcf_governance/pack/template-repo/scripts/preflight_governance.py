#!/usr/bin/env python3
"""Thin public wrapper for the vendored deterministic governance preflight."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._bcf_runtime.preflight import main
else:
    from _bcf_runtime.preflight import main


if __name__ == "__main__":
    main()
