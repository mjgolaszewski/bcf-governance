#!/usr/bin/env python3
"""Check BCF's README-led editorial ownership and local documentation links."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from bcf_governance._version import __version__  # noqa: E402
from bcf_governance.cli import COMMANDS  # noqa: E402


CANONICAL_DOCUMENTS = {
    "README.md": (
        "Design thesis",
        "What BCF establishes",
        "Why these defaults",
        "Verification cost and scope",
        "Documentation map",
    ),
    "docs/RELIABILITY_MODEL.md": (
        "Failure model",
        "Redundant verification, single authority",
        "Compute and attention",
        "Common objections",
        "Empirical question",
        "Limits",
    ),
    "docs/ARCHITECTURE.md": (
        "Authority model",
        "CQRS-lite",
        "Single semantic ownership",
        "Mechanical and negative testing",
        "Exact evidence and computed lifecycle",
        "Fail-fast and bounded execution",
        "CI graph as a compiled contract",
        "Profiles and scope",
    ),
    "docs/CI_AUTHORITY.md": (
        "State flow",
        "Trust table",
        "Workflow identity and admission",
        "GitHub reference topology",
        "Release construction and publication",
    ),
    "docs/USAGE.md": (
        "Profiles",
        "CI graph ownership",
        "Gate contracts and CI",
        "Supporting commands",
    ),
    "docs/MAINTAINING.md": ("Source ownership", "Verification", "Version and release"),
    "template-repo/docs/OPERATIONS.md": (
        "Release Validation",
        "Governance Helpers",
        "CI Resource Ownership",
    ),
}

BRANCH_DOCUMENTS = (
    "template-repo/governance/EXISTING_REPO_ADOPTION.md",
    "template-repo/governance/HOTFIX_LANE.md",
    "template-repo/governance/MODEL_RISK_AND_PROVENANCE.md",
    "template-repo/governance/REPO_CLEANUP.md",
)

EDITORIAL_DOCUMENTS = tuple(CANONICAL_DOCUMENTS) + BRANCH_DOCUMENTS + (
    "docs/EDITORIAL_CHECKLIST.md",
)

BANNED_TONE = (
    "manifesto",
    "revolutionary",
    "game-changing",
    "infallible",
    "guarantees correctness",
    "ai-proof",
)

LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
BCF_COMMAND = re.compile(r"^bcf\s+([a-z][a-z0-9-]*)\b", re.MULTILINE)


def _slug(heading: str) -> str:
    value = re.sub(r"[*_`~]", "", heading).strip().lower()
    value = re.sub(r"[^\w\- ]", "", value)
    return re.sub(r"[\s-]+", "-", value).strip("-")


def _anchors(path: Path) -> set[str]:
    return {_slug(match) for match in HEADING.findall(path.read_text(encoding="utf-8"))}


def _check_link(
    source: Path, raw_target: str, repo_root: Path = REPO_ROOT
) -> list[str]:
    target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
    if target.startswith(("https://", "http://", "mailto:")):
        return []
    path_text, _, anchor = unquote(target).partition("#")
    resolved = source if not path_text else (source.parent / path_text).resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return [f"{source.relative_to(repo_root)}: link escapes repository: {target}"]
    if not resolved.exists():
        return [f"{source.relative_to(repo_root)}: missing link target: {target}"]
    if anchor and resolved.is_file() and anchor not in _anchors(resolved):
        return [f"{source.relative_to(repo_root)}: missing anchor: {target}"]
    return []


def validate_editorial_contract(repo_root: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = []
    for relative, required_headings in CANONICAL_DOCUMENTS.items():
        path = repo_root / relative
        if not path.is_file():
            errors.append(f"missing canonical document: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        headings = set(HEADING.findall(text))
        for heading in required_headings:
            if heading not in headings:
                errors.append(f"{relative}: missing heading: {heading}")

    for relative in EDITORIAL_DOCUMENTS:
        path = repo_root / relative
        if not path.is_file():
            errors.append(f"missing editorial document: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for phrase in BANNED_TONE:
            if phrase in lowered:
                errors.append(f"{relative}: disallowed editorial phrase: {phrase}")
        for target in LINK.findall(text):
            errors.extend(_check_link(path, target, repo_root))
        for command in BCF_COMMAND.findall(text):
            if command not in COMMANDS:
                errors.append(f"{relative}: unknown bcf command: {command}")

    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())
    required_positions = (
        "deterministic error-correction framework",
        "probabilistic software producer",
        "Generate probabilistically → constrain structurally → challenge causally",
        "compute truth deterministically",
        "CQRS-lite",
        "Single-owner invariant principle (SOIP)",
        "Mechanical constraints",
        "Causal negative controls",
        "Exact-commit evidence",
        "Bounded modules and context",
        "Cheap preflight before expensive work",
        "an agent cannot certify its own output",
        "Mechanical invariants decide only the claims",
        "spend machine time to protect correctness and conserve human attention",
        "does not turn an incomplete or incorrect specification into a correct one",
        "cost",
        "limitations",
    )
    for phrase in required_positions:
        if phrase not in normalized_readme:
            errors.append(f"README.md: missing architectural position: {phrase}")
    if f"Development package version: `v{__version__}`" not in readme:
        errors.append("README.md: package version does not match version authority")
    if f"bcf_governance-{__version__}-py3-none-any.whl" not in readme:
        errors.append("README.md: wheel example does not match package version")
    expected_release_path = (
        f"releases/download/v{__version__}/"
        f"bcf_governance-{__version__}-py3-none-any.whl"
    )
    for relative in ("README.md", "docs/USAGE.md"):
        text = (repo_root / relative).read_text(encoding="utf-8")
        release_paths = re.findall(
            r"releases/download/v[^/\s]+/bcf_governance-[^/\s]+-py3-none-any\.whl",
            text,
        )
        if release_paths != [expected_release_path]:
            errors.append(
                f"{relative}: release URL must point exactly to the current package version"
            )
    if "--mode pull_request" in readme or "--mode pr" not in readme:
        errors.append("README.md: preflight example does not use the implemented PR mode")
    for required_graph_command in (
        "bcf ci graph validate --repo-root .",
        "bcf ci graph render --repo-root . --check",
        "bcf ci adopt github --repo-root . --check",
    ):
        if required_graph_command not in readme:
            errors.append("README.md: graph adoption example omits " + required_graph_command)

    ci_guide = (repo_root / "docs/CI_AUTHORITY.md").read_text(encoding="utf-8")
    if "```mermaid" not in ci_guide:
        errors.append("docs/CI_AUTHORITY.md: missing state-flow diagram")
    if "| Role | Executes candidate code | Credentials | Permitted effects |" not in ci_guide:
        errors.append("docs/CI_AUTHORITY.md: missing canonical trust table")

    checklist = (repo_root / "docs/EDITORIAL_CHECKLIST.md").read_text(encoding="utf-8")
    if "- [ ]" in checklist:
        errors.append("docs/EDITORIAL_CHECKLIST.md: incomplete review item")
    if "non-authoritative" not in checklist:
        errors.append("docs/EDITORIAL_CHECKLIST.md: review authority boundary is absent")
    return errors


def main() -> int:
    errors = validate_editorial_contract()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("editorial-contract-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
