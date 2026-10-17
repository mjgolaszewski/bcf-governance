"""Compatibility entrypoint for the canonical source inventory owner."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bcf_governance.tooling.governance_validation.source_inventory import (
    main,
    tracked_source_inventory as tracked_source_inventory,
    sdist_source_inventory as sdist_source_inventory,
    validate_sdist_source_inventory as validate_sdist_source_inventory,
    validate_sdist_manifest_coverage as validate_sdist_manifest_coverage,
)

if __name__ == "__main__":
    main()
