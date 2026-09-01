"""Restore private evidence modes after exact artifact transport."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def restore(root: Path) -> int:
    resolved = root.resolve()
    if root.is_symlink() or not resolved.is_dir():
        raise ValueError("evidence root must be one nonsymlink directory")
    manifests = sorted(resolved.rglob("evidence-session.json"))
    if not manifests:
        raise ValueError("evidence root contains no session manifests")
    for manifest in manifests:
        if manifest.is_symlink() or not manifest.parent.resolve().is_relative_to(resolved):
            raise ValueError("evidence session escapes the declared root")
        os.chmod(manifest.parent, 0o700)
        os.chmod(manifest, 0o400)
    return len(manifests)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print(f"restored_evidence_sessions={restore(args.root)}")


if __name__ == "__main__":
    main()
