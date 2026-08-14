"""Compatibility exports for the private BCF runtime."""
from _bcf_runtime import governance_truth_support as _implementation
globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if name != "__name__"})
