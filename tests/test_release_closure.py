from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile
import zipfile

import pytest
import yaml

from bcf_governance.tooling.release_closure import (
    ReleaseClosureError,
    verify_archive,
    verify_release_lock,
    verify_wheelhouse,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _closure(tmp_path: Path) -> tuple[Path, Path, Path]:
    wheels = {
        "alpha-1.0-py3-none-any.whl": b"alpha",
        "beta-2.0-py3-none-any.whl": b"beta",
    }
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    for name, raw in wheels.items():
        (wheelhouse / name).write_bytes(raw)
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "alpha==1.0 --hash=sha256:" + _sha(wheels["alpha-1.0-py3-none-any.whl"]) + "\n"
        "beta==2.0 --hash=sha256:" + _sha(wheels["beta-2.0-py3-none-any.whl"]) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": "1.0",
        "subject": {
            "python": "3.12.14",
            "implementation": "CPython",
            "operating_system": "ubuntu-24.04",
            "platform": "linux_x86_64",
            "wheel_platform": "manylinux_2_17_x86_64",
            "abi": "cp312",
        },
        "resolution": {
            "lock_path": "release/requirements-cp312-linux-x86_64.lock",
            "lock_sha256": _sha(lock.read_bytes()),
            "direct_requirements": ["alpha", "beta"],
            "network_policy": "candidate_may_download_only_manifest_admitted_wheels",
            "build_install": {"no_index": True, "require_hashes": True, "no_isolation": True},
            "verification_install": {"no_index": True, "require_hashes": True},
        },
        "wheels": {name: _sha(raw) for name, raw in wheels.items()},
    }
    manifest_path = tmp_path / "wheelhouse.yml"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return manifest_path, lock, wheelhouse


def test_repository_release_lock_is_a_complete_exact_hash_closure() -> None:
    result = verify_release_lock(
        REPO_ROOT / "release/wheelhouse-manifest.yml",
        REPO_ROOT / "release/requirements-cp312-linux-x86_64.lock",
    )
    assert result.python == "3.12.14"
    assert result.platform == "linux_x86_64"
    assert len(result.wheels) == 41


def test_wheelhouse_requires_exact_filenames_and_bytes(tmp_path: Path) -> None:
    manifest, lock, wheelhouse = _closure(tmp_path)
    assert verify_wheelhouse(manifest, lock, wheelhouse).python == "3.12.14"
    (wheelhouse / "extra.whl").write_bytes(b"extra")
    with pytest.raises(ReleaseClosureError, match="inventory"):
        verify_wheelhouse(manifest, lock, wheelhouse)
    (wheelhouse / "extra.whl").unlink()
    (wheelhouse / "alpha-1.0-py3-none-any.whl").write_bytes(b"changed")
    with pytest.raises(ReleaseClosureError, match="digest mismatch"):
        verify_wheelhouse(manifest, lock, wheelhouse)


@pytest.mark.parametrize("mutation", ["unhashed", "range", "extra-hash"])
def test_release_lock_rejects_open_or_changed_dependencies(
    tmp_path: Path, mutation: str
) -> None:
    manifest, lock, _ = _closure(tmp_path)
    text = lock.read_text(encoding="utf-8")
    if mutation == "unhashed":
        text = text.splitlines()[0].split(" --hash")[0] + "\n" + text.splitlines()[1] + "\n"
    elif mutation == "range":
        text = text.replace("alpha==1.0", "alpha>=1.0")
    else:
        text += "gamma==3.0 --hash=sha256:" + "f" * 64 + "\n"
    lock.write_text(text, encoding="utf-8")
    payload = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    payload["resolution"]["lock_sha256"] = _sha(lock.read_bytes())
    manifest.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ReleaseClosureError):
        verify_release_lock(manifest, lock)


def test_archive_verifier_accepts_regular_wheel_and_sdist(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("package/__init__.py", "")
    sdist = tmp_path / "package.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo("package/README.md")
        raw = b"readme"
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
    assert verify_archive(wheel) == ("package/__init__.py",)
    assert verify_archive(sdist) == ("package/README.md",)


@pytest.mark.parametrize("kind", ["zip-escape", "zip-link", "tar-escape", "tar-link"])
def test_archive_verifier_rejects_escapes_and_links(tmp_path: Path, kind: str) -> None:
    if kind.startswith("zip"):
        path = tmp_path / "package.whl"
        with zipfile.ZipFile(path, "w") as archive:
            if kind == "zip-escape":
                archive.writestr("../escape", "bad")
            else:
                info = zipfile.ZipInfo("package/link")
                info.external_attr = 0o120777 << 16
                archive.writestr(info, "target")
    else:
        path = tmp_path / "package.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("../escape" if kind == "tar-escape" else "package/link")
            if kind == "tar-link":
                info.type = tarfile.SYMTYPE
                info.linkname = "target"
            archive.addfile(info)
    with pytest.raises(ReleaseClosureError):
        verify_archive(path)
