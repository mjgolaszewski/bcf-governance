"""Safe filesystem staging for mechanically selected release evidence."""

from __future__ import annotations

from pathlib import Path
import shutil

from .ci_github_identity import GitHubControllerError


def _empty_directory(path: Path, *, label: str) -> None:
    if path.is_symlink() or (path.exists() and any(path.iterdir())):
        raise GitHubControllerError(
            f"{label} must begin as an empty nonsymlink path"
        )
    path.mkdir(parents=True, exist_ok=True)


def stage_verifier_bundle(
    destination: Path,
    *,
    build_manifest: Path,
    runtime_report: Path,
    verification: Path,
) -> None:
    """Stage the three independently produced verifier inputs."""

    _empty_directory(destination, label="release verifier bundle output")
    shutil.copytree(build_manifest.parent, destination / "build")
    shutil.copytree(runtime_report.parent, destination / "runtime")
    shutil.copytree(verification.parent, destination / "verification")


def stage_receipt_bundle(
    destination: Path,
    *,
    asset_root: Path,
    build_manifest: Path,
    verification: Path,
    receipt: Path,
) -> None:
    """Stage exact release assets and their trusted authority records."""

    _empty_directory(destination, label="release receipt bundle output")
    shutil.copytree(asset_root, destination / "assets")
    shutil.copy2(build_manifest, destination / build_manifest.name)
    shutil.copy2(verification, destination / verification.name)
    shutil.copy2(receipt, destination / "release-receipt.json")
