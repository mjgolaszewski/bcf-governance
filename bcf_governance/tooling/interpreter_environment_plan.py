"""Immutable selected-interpreter plan, identity and installation input contract."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement


class InterpreterEnvironmentError(ValueError):
    """Raised when the governed interpreter environment cannot be compiled."""


def _dependency_name(value: object) -> str:
    if not isinstance(value, str):
        raise InterpreterEnvironmentError("dependency declaration is not a string")
    try:
        requirement = Requirement(value)
    except InvalidRequirement as exc:
        raise InterpreterEnvironmentError(
            "dependency declaration is not a bounded package requirement"
        ) from exc
    if requirement.url or requirement.marker or requirement.extras:
        raise InterpreterEnvironmentError(
            "dependency declaration must not use URLs, markers, or extras"
        )
    return requirement.name


def _normalized_name(value: object) -> str:
    return re.sub(r"[-_.]+", "-", _dependency_name(value)).lower()


@dataclass(frozen=True)
class InterpreterEnvironmentPlan:
    """One canonical projection of every selected-interpreter requirement."""

    requirements: tuple[str, ...]
    requires_python: str | None
    projection_path: Path | None
    source_kind: str = "project_metadata_projection"
    source_path: Path | None = None
    source_sha256: str | None = None

    @property
    def distribution_names(self) -> frozenset[str]:
        return frozenset(_normalized_name(value) for value in self.requirements)

    def rendered_requirements(self) -> str:
        return "".join(f"{value}\n" for value in self.requirements)

    def identity(self, base_python: Path) -> str:
        """Bind one derived environment to its source plan and base runtime."""

        executable = base_python.resolve(strict=True)
        digest = hashlib.sha256()
        digest.update(self.rendered_requirements().encode("utf-8"))
        digest.update(b"\0")
        digest.update((self.requires_python or "").encode("utf-8"))
        digest.update(b"\0")
        digest.update(self.source_kind.encode("utf-8"))
        digest.update(b"\0")
        digest.update((self.source_sha256 or "").encode("ascii"))
        digest.update(b"\0")
        with executable.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


    @property
    def installation_path(self) -> Path | None:
        """Return the authenticated dependency input consumed by pip."""

        if self.source_kind == "project_metadata_projection":
            return self.projection_path
        return self.projection_path or self.source_path

    def pip_arguments(self) -> tuple[str, ...]:
        """Bind installation to the already-derived dependency proposition."""

        if self.source_kind in {"legacy_governance_requirements", "governed_requirements_source", "locked_project"}:
            return self.requirements
        if self.projection_path is None:
            raise InterpreterEnvironmentError(
                "interpreter dependency projection is unavailable"
            )
        return self.requirements
