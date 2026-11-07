"""Bounded canonical architecture YAML admission; no ownership authority."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

import yaml


def _read(path: Path) -> bytes:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("policy input must have a canonical absolute path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 2 * 1024**2:
            raise ValueError("policy input must be a bounded regular file")
        raw = stream.read(2 * 1024**2 + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    identity = tuple(getattr(before, field) for field in fields)
    if any(tuple(getattr(value, field) for field in fields) != identity
           for value in [after, path.lstat()]) or len(raw) != before.st_size:
        raise ValueError("policy input changed during admission")
    return raw


def _yaml_shape(node: yaml.Node, ancestors: frozenset[int], remaining: list[int]) -> None:
    remaining[0] -= 1
    if remaining[0] < 0 or len(ancestors) >= 128 or id(node) in ancestors:
        raise ValueError("cyclic or excessive YAML alias expansion")
    ancestors = ancestors | {id(node)}
    if isinstance(node, yaml.MappingNode):
        names: set[str] = set()
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                raise ValueError("YAML mappings require explicit string key values")
            if key.value in names:
                raise ValueError("duplicate YAML mapping key")
            names.add(key.value)
            _yaml_shape(value, ancestors, remaining)
    elif isinstance(node, yaml.SequenceNode):
        for value in node.value:
            _yaml_shape(value, ancestors, remaining)


def _yaml_document(raw: bytes) -> object:
    node = yaml.compose(raw, Loader=yaml.SafeLoader)
    if node is None:
        raise ValueError("empty governed YAML document")
    _yaml_shape(node, frozenset(), [100000])
    return yaml.safe_load(raw)


def load_architecture_mapping(path: Path, *, expected_sha256: str | None = None) -> dict[str, Any]:
    """Read one stable bounded input and reject ambiguity before interpretation."""
    raw = _read(path)
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("policy input does not match its admitted SHA256")
    document = _yaml_document(raw)
    if not isinstance(document, dict):
        raise ValueError("architecture input must contain a mapping")
    return document
