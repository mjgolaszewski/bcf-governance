from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._bcf_runtime.evidence_shards import main
else:
    from _bcf_runtime.evidence_shards import main


if __name__ == "__main__":
    main()
