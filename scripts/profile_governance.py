"""Compatibility wrapper for packaged BCF tooling."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bcf_governance.tooling import profile_governance as _implementation
globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if name != "__name__"})
if __name__ == "__main__":
    _implementation.main()
