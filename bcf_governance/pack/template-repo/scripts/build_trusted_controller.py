#!/usr/bin/env python3
"""Thin installed-pack entry point for canonical controller construction."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._bcf_runtime.ci_controller_builder import main
else:
    from _bcf_runtime.ci_controller_builder import main


if __name__ == "__main__":
    main()
