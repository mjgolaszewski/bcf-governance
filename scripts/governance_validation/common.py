"""Compatibility wrapper for packaged BCF tooling."""
from bcf_governance.tooling.governance_validation import common as _implementation
globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if name != "__name__"})
