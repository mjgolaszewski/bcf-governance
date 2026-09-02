"""Canonical BCF package and GitHub release version identities."""

from __future__ import annotations

from dataclasses import dataclass
import re


_PUBLIC_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:(a|b|rc)(0|[1-9][0-9]*))?$"
)


class ReleaseVersionError(ValueError):
    """Raised when a package or tag version is outside the public policy."""


@dataclass(frozen=True)
class ReleaseVersion:
    """One canonical stable or PEP 440 pre-release version."""

    value: str
    prerelease: bool

    @property
    def tag(self) -> str:
        return f"v{self.value}"


def parse_release_version(value: str) -> ReleaseVersion:
    """Accept canonical X.Y.Z and X.Y.Z{a,b,rc}N release identities."""

    match = _PUBLIC_VERSION.fullmatch(value)
    if match is None:
        raise ReleaseVersionError(
            "release version must be canonical X.Y.Z or X.Y.Z{a,b,rc}N"
        )
    return ReleaseVersion(value=value, prerelease=match.group(4) is not None)


def parse_release_tag(tag: str) -> ReleaseVersion:
    """Parse a canonical version tag without accepting aliases."""

    if not tag.startswith("v"):
        raise ReleaseVersionError("release tag must start with v")
    parsed = parse_release_version(tag[1:])
    if parsed.tag != tag:
        raise ReleaseVersionError("release tag is not canonical")
    return parsed
