"""Pure deterministic changelog projection for authenticated automation PRs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from .automation_contracts import AutomationContractError


@dataclass(frozen=True)
class ChangelogProjection:
    content: bytes
    marker: str
    entry: str
    changed: bool


def automation_marker(
    *, repository_id: int, producer_id: str, pr_number: int, source_state: str
) -> str:
    identity = f"{repository_id}:{producer_id}:{pr_number}:{source_state}".encode()
    digest = hashlib.sha256(identity).hexdigest()
    return f"<!-- bcf-automation-changelog:{repository_id}:{producer_id}:{pr_number}:{digest} -->"


def render_automation_changelog(
    current: bytes,
    *,
    repository_id: int,
    producer_id: str,
    pr_number: int,
    source_state: str,
    dependency_paths: tuple[str, ...],
) -> ChangelogProjection:
    """Replace this PR's sole marker/entry under Unreleased/Changed."""

    try:
        text = current.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AutomationContractError("CHANGELOG.md must be UTF-8") from exc
    if text.count("## [Unreleased]") != 1:
        raise AutomationContractError("CHANGELOG.md must contain one exact Unreleased heading")
    if pr_number < 1 or not producer_id or not re.fullmatch(r"[a-f0-9]{64}", source_state):
        raise AutomationContractError("automation changelog identity is incomplete")
    prefix = f"<!-- bcf-automation-changelog:{repository_id}:{producer_id}:{pr_number}:"
    marker_lines = [line for line in text.splitlines() if line.startswith(prefix)]
    if len(marker_lines) > 1:
        raise AutomationContractError("CHANGELOG.md contains duplicate automation markers")
    paths = tuple(sorted(set(dependency_paths)))
    if paths != dependency_paths or not paths:
        raise AutomationContractError("dependency paths must be nonempty, unique, and sorted")
    entry = (
        f"- Automated dependency update `{producer_id}` from PR #{pr_number}: "
        + ", ".join(f"`{path}`" for path in paths)
        + "."
    )
    marker = automation_marker(
        repository_id=repository_id,
        producer_id=producer_id,
        pr_number=pr_number,
        source_state=source_state,
    )
    lines = text.splitlines()
    if marker_lines:
        old_index = lines.index(marker_lines[0])
        if old_index + 1 >= len(lines) or not lines[old_index + 1].startswith(
            f"- Automated dependency update `{producer_id}` from PR #{pr_number}:"
        ):
            raise AutomationContractError("automation marker is not bound to its fixed entry")
        lines[old_index : old_index + 2] = [marker, entry]
    else:
        unreleased = lines.index("## [Unreleased]")
        next_release = next(
            (index for index in range(unreleased + 1, len(lines)) if lines[index].startswith("## [")),
            len(lines),
        )
        changed = next(
            (index for index in range(unreleased + 1, next_release) if lines[index] == "### Changed"),
            None,
        )
        unreleased_lines = lines[unreleased + 1 : next_release]
        if "No unreleased changes." in unreleased_lines:
            lines.remove("No unreleased changes.")
            next_release -= 1
        if changed is None:
            insert = unreleased + 1
            lines[insert:insert] = ["", "### Changed", "", marker, entry]
        else:
            insert = changed + 1
            while insert < next_release and lines[insert] == "":
                insert += 1
            if insert < next_release and lines[insert] == "No unreleased changes.":
                lines[insert : insert + 1] = [marker, entry]
            else:
                lines[insert:insert] = [marker, entry, ""]
    rendered = ("\n".join(lines).rstrip() + "\n").encode()
    return ChangelogProjection(rendered, marker, entry, rendered != current)
