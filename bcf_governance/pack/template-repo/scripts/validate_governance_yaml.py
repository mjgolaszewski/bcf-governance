"""Standalone wrapper for the private BCF runtime."""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._bcf_runtime.validate_governance_yaml import main
else:
    from _bcf_runtime.validate_governance_yaml import main
if __name__ == "__main__":
    main()
