"""Bounded, non-executable XML admission shared by maintained evidence readers."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

_MAX_XML_BYTES = 16 * 1024**2


def parse_evidence_xml(raw: bytes) -> Element:
    """Reject DTDs, entities and external references before evidence interpretation."""
    if len(raw) > _MAX_XML_BYTES:
        raise ParseError("evidence requires bounded XML")
    try:
        return fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise ParseError("forbidden XML declaration in evidence") from exc


def read_evidence_xml(path: Path) -> Element:
    """Read one regular nonsymlink input with bounded allocation and stable identity."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_XML_BYTES:
            raise ParseError("evidence requires bounded XML regular file")
        raw = stream.read(_MAX_XML_BYTES + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
    identity = tuple(getattr(before, key) for key in fields)
    if (len(raw) != before.st_size
            or any(tuple(getattr(value, key) for key in fields) != identity
                   for value in (after, path.lstat()))):
        raise ParseError("evidence XML changed during admission")
    return parse_evidence_xml(raw)
