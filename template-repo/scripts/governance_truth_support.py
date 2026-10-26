"""Compatibility exports for the private BCF runtime."""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._bcf_runtime import governance_truth_support as _implementation
else:
    from _bcf_runtime import governance_truth_support as _implementation
globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if name != "__name__"})
