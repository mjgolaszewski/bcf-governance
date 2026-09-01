"""Verify one installed trusted controller against canonical custody policy."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

import yaml


def probe(policy_path: Path, tool_cache: Path) -> dict[str, str]:
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    runner = policy["runner_security"]
    artifact = runner["trusted_controller_artifact"]
    installation = runner["trusted_controller_installation"]
    commit = installation["installed_commit_sha"]
    if commit != artifact["BCF_BOOTSTRAP_COMMIT_SHA"]:
        raise ValueError("installed and artifact controller commits differ")
    cache = tool_cache.resolve()
    if tool_cache.is_symlink() or not cache.is_dir():
        raise ValueError("runner tool cache is unsafe")
    root = cache / "bcf-governance" / commit
    if root.is_symlink() or not root.is_dir() or not root.is_relative_to(cache):
        raise ValueError("trusted controller installation is unsafe")
    metadata_path = root / "INSTALL-METADATA.json"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError("trusted controller installation metadata is missing")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = {
        "artifact_id": artifact["BCF_BOOTSTRAP_ARTIFACT_ID"],
        "artifact_digest": artifact["BCF_BOOTSTRAP_ARTIFACT_DIGEST"],
        "artifact_run_id": artifact["BCF_BOOTSTRAP_RUN_ID"],
        "commit_sha": commit,
        "wheel_sha256": artifact["BCF_BOOTSTRAP_WHEEL_SHA256"],
    }
    if metadata != expected:
        raise ValueError("trusted controller installation metadata is stale")
    executable = root / "bin/bcf"
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("trusted controller executable is unsafe")
    subprocess.run([str(executable), "--version"], check=True)
    subprocess.run([str(executable), "ci-github", "--help"], check=True)
    return {"commit_sha": commit, "install_root": str(root), "status": "valid"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--tool-cache", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(probe(args.policy, args.tool_cache), sort_keys=True))


if __name__ == "__main__":
    main()
