from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

from bcf_governance._version import __version__


REPO_ROOT = Path(__file__).resolve().parents[1]


def _is_pack_artifact(path: Path) -> bool:
    return "__pycache__" not in path.parts and path.suffix != ".pyc"


def _read_text(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_public_wrappers_are_thin_and_private_runtime_stays_in_sync() -> None:
    for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
        if path.name == "__init__.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert "bcf_governance.tooling" in text
        assert len(text.splitlines()) < 20

    runtime_files = sorted(
        path.relative_to(REPO_ROOT / "bcf_governance/tooling")
        for path in (REPO_ROOT / "bcf_governance/tooling").rglob("*.py")
        if _is_pack_artifact(path)
    )
    mismatches = [
        relative.as_posix()
        for relative in runtime_files
        if (REPO_ROOT / "bcf_governance/tooling" / relative).read_bytes()
        != (REPO_ROOT / "template-repo/scripts/_bcf_runtime" / relative).read_bytes()
    ]
    assert not mismatches, "private runtime drifted:\n" + "\n".join(mismatches)
    assert (REPO_ROOT / "bcf_governance/_version.py").read_bytes() == (
        REPO_ROOT / "template-repo/scripts/_bcf_runtime/_version.py"
    ).read_bytes()
    assert _read_text("requirements-governance.txt") == _read_text(
        "template-repo/requirements-governance.txt"
    )


def test_root_wrapper_bootstraps_an_uninstalled_source_checkout(tmp_path: Path) -> None:
    wrapper = REPO_ROOT / "scripts/install_governance_pack.py"
    site_packages = Path(yaml.__file__).resolve().parent.parent
    launcher = (
        "import runpy, sys; "
        f"sys.path.append({str(site_packages)!r}); "
        f"sys.argv = [{str(wrapper)!r}, '--help']; "
        f"runpy.run_path({str(wrapper)!r}, run_name='__main__')"
    )

    result = subprocess.run(
        [sys.executable, "-S", "-c", launcher],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


def test_packaged_template_resource_stays_in_sync() -> None:
    template_files = sorted(
        path.relative_to(REPO_ROOT / "template-repo")
        for path in (REPO_ROOT / "template-repo").rglob("*")
        if path.is_file() and _is_pack_artifact(path)
    )
    packaged_files = sorted(
        path.relative_to(REPO_ROOT / "bcf_governance/pack/template-repo")
        for path in (REPO_ROOT / "bcf_governance/pack/template-repo").rglob("*")
        if path.is_file() and _is_pack_artifact(path)
    )
    assert packaged_files == template_files

    mismatches = [
        relative_path.as_posix()
        for relative_path in template_files
        if (REPO_ROOT / "template-repo" / relative_path).read_bytes()
        != (REPO_ROOT / "bcf_governance/pack/template-repo" / relative_path).read_bytes()
    ]
    assert not mismatches, "packaged template resources drifted:\n" + "\n".join(mismatches)


def test_generated_version_surfaces_match_authoritative_version() -> None:
    manifest = yaml.safe_load(_read_text("manifest.yml"))
    assert manifest["document"]["version"] == __version__
    assert _read_text("bcf_governance/_version.py") == _read_text(
        "template-repo/scripts/_bcf_runtime/_version.py"
    )
