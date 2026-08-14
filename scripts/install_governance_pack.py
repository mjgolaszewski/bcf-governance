"""Compatibility wrapper for packaged BCF tooling."""
from bcf_governance.tooling import install_governance_pack as _implementation
globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if name != "__name__"})
if __name__ == "__main__":
    _implementation.main()
