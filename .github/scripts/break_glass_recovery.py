from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bcf_governance.tooling.break_glass_recovery import main  # noqa: E402


if __name__ == "__main__":
    main()
