"""Bind pack metadata to the same bounded wheel bytes as a maintained owner.

This query grants no release or candidate authority. Both owners must authenticate
asset identity independently before asking for this byte join.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
from pathlib import Path
from typing import Any, Never

from .architecture_policy_input import _read
from .architecture_source_components import SourceComponentError
from .governance_install.release_custody import MAXIMUM_WHEEL_BYTES
from .release_asset_inventory import release_asset_paths


def _refuse(detail: str) -> Never:
    raise SourceComponentError(f"bound pack manifest: {detail}")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _refuse("duplicate JSON field")
        result[key] = value
    return result


def bound_wheel_manifest(assets_root: Path, template_root: Path,
                         expected_sha256: str) -> dict[str, Any]:
    """Verify canonical wheel descriptor identity and exact executing metadata."""
    wheels = [path for path in release_asset_paths(assets_root) if path.suffix == ".whl"]
    if len(wheels) != 1 or wheels[0].resolve(strict=True) != wheels[0]:
        _refuse("one canonical authenticated wheel required")
    fd = os.open(wheels[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAXIMUM_WHEEL_BYTES:
            _refuse("release wheel type or size differs")
        with os.fdopen(os.dup(fd), "rb") as stream:
            wheel_raw = stream.read(MAXIMUM_WHEEL_BYTES + 1)
        after = os.fstat(fd)
        named = wheels[0].lstat()
        def fields(row: os.stat_result) -> tuple[int, ...]:
            return (row.st_dev, row.st_ino, row.st_mode, row.st_size,
                    row.st_mtime_ns, row.st_ctime_ns, row.st_nlink)
        if fields(before) != fields(after) or fields(after) != fields(named):
            _refuse("release wheel changed during descriptor read")
    finally:
        os.close(fd)
    if len(wheel_raw) > MAXIMUM_WHEEL_BYTES or _sha(wheel_raw) != expected_sha256:
        _refuse("release wheel changed after authentication")
    with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
        manifest_raw = archive.read("bcf_governance/pack/template-repo/.bcf-pack-manifest.json")
    if _read(template_root / ".bcf-pack-manifest.json") != manifest_raw:
        _refuse("executing pack manifest differs from authenticated wheel")
    manifest = json.loads(manifest_raw, object_pairs_hook=_unique_object)
    if not isinstance(manifest, dict):
        _refuse("pack manifest must be an object")
    return manifest
