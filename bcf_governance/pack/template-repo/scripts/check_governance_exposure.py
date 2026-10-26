"""Standalone wrapper for the private BCF runtime."""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._bcf_runtime.check_governance_exposure import main
else:
    from _bcf_runtime.check_governance_exposure import main
if __name__ == "__main__":
    main()
