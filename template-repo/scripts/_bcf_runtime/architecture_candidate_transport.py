"""Closed candidate input transport; data only, never custody authority."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .architecture_candidate_membership import CandidateQualificationInputs
from .architecture_source_components import SourceComponentError

KEY = "BCF_CANDIDATE_MEMBERSHIP_INPUTS"
_FIELDS = {"source_root", "assets_root", "build_manifest", "template_root",
           "adopter_commit", "adopter_tree"}


def encode_candidate_inputs(inputs: CandidateQualificationInputs) -> str:
    if type(inputs) is not CandidateQualificationInputs:
        raise SourceComponentError("candidate transport: maintained input type required")
    value = {name: str(getattr(inputs, name)) for name in sorted(_FIELDS)}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(raw.encode()) > 8192:
        raise SourceComponentError("candidate transport: input size exceeded")
    return raw


def decode_candidate_inputs(raw: str, *, isolated_candidate: bool) -> CandidateQualificationInputs:
    if not isolated_candidate:
        raise SourceComponentError("candidate transport: released execution domain required")
    if not isinstance(raw, str) or not raw or len(raw.encode()) > 8192:
        raise SourceComponentError("candidate transport: bounded explicit input required")
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SourceComponentError("candidate transport: duplicate field")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except json.JSONDecodeError as exc:
        raise SourceComponentError("candidate transport: invalid JSON input") from exc
    if (not isinstance(value, dict) or set(value) != _FIELDS
            or any(not isinstance(item, str) or not item for item in value.values())):
        raise SourceComponentError("candidate transport: exact input fields required")
    for name in ("source_root", "assets_root", "build_manifest", "template_root"):
        path = Path(value[name])
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise SourceComponentError("candidate transport: canonical source path required")
        value[name] = path
    return CandidateQualificationInputs(**value)
