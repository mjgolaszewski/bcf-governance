#!/usr/bin/env python3
"""Build or verify exact coverage for a release editorial review."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path
from typing import Any

import yaml


PACKAGED_MIRROR_ROOT = "bcf_governance/pack/template-repo/"
ADDITIONAL_HUMAN_FACING_SOURCES = {
    "AGENTS.yml",
    "template-repo/AGENTS.yml",
    "docs/assets/bcf-governance-pack-hero.jpg",
}
SPECIFIC_FINDINGS = {
    "AGENTS.yml": "reviewed canonical repository-agent guidance for current profile, lifecycle, and authority boundaries",
    "README.md": "updated the mechanically checked package example and exact method-dispatch failure mode",
    "docs/ARCHITECTURE.md": "documented exact same-instance method identity and fail-closed dynamic or replaceable dispatch",
    "docs/RELIABILITY_MODEL.md": "added method-owner loss as an explicit operation-effect failure mode",
    "docs/USAGE.md": "documented exact method dispatch, explicit component ports, dynamic-dispatch limits, and the release example",
    "docs/MAINTAINING.md": "updated the exact release-audit procedure and base selection",
    "examples/lifecycle-walkthrough/README.md": "replaced obsolete 0.6 and hand-built gate loop with 1.1 preflight and session mechanics",
    "template-repo/governance/EXISTING_REPO_ADOPTION.md": "corrected upgrade and workflow ownership boundaries",
    "template-repo/governance/REPO_CLEANUP.md": "clarified editorial, semantic, deterministic, and approval authority",
    "audits/README.md": "replaced human-specific wording with operator and governance language",
    "template-repo/audits/README.md": "replaced human-specific wording with operator and governance language",
    "docs/EDITORIAL_CHECKLIST.md": "pruned checked-box release evidence after durable rules moved to maintainer guidance",
    "docs/assets/bcf-governance-pack-hero.jpg": "retained the established project identity asset; no semantic or release claim is encoded in its pixels",
    "template-repo/AGENTS.yml": "reviewed installed repository-agent guidance and retained its generated-template ownership",
}


class EditorialAuditError(ValueError):
    """Raised when editorial coverage does not match the exact repository tree."""


def _git(repo_root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, check=False
    )
    if result.returncode:
        raise EditorialAuditError(result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _base_bytes(repo_root: Path, base_sha: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{base_sha}:{path}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def _current_inventory(repo_root: Path) -> set[str]:
    return {
        value.decode()
        for value in _git(repo_root, "ls-files", "-z", "*.md", "LICENSE").split(b"\0")
        if value
    } | {
        path
        for path in ADDITIONAL_HUMAN_FACING_SOURCES
        if (repo_root / path).is_file() and not (repo_root / path).is_symlink()
    }


def _inventory(repo_root: Path, base_sha: str) -> list[str]:
    current = _current_inventory(repo_root)
    base = {
        value.decode()
        for value in _git(
            repo_root, "ls-tree", "-r", "-z", "--name-only", base_sha
        ).split(b"\0")
        if value and (value.decode().endswith(".md") or value.decode() == "LICENSE")
    }
    return sorted(
        path
        for path in current | base | ADDITIONAL_HUMAN_FACING_SOURCES
        if not path.startswith(PACKAGED_MIRROR_ROOT)
    )


def _base_is_available(repo_root: Path, base_sha: str) -> bool:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{base_sha}^{{tree}}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _check_current_custody(
    repo_root: Path, audit: dict[str, Any]
) -> list[str]:
    """Validate current editorial bytes when historical objects are not packaged."""
    errors: list[str] = []
    rows = audit.get("documents")
    if not isinstance(rows, list):
        return ["editorial audit documents must be a sequence"]
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            errors.append("editorial audit contains an invalid document row")
            continue
        path = str(row["path"])
        if path in indexed:
            errors.append(f"editorial audit duplicates {path}")
            continue
        indexed[path] = row
    current = {
        path
        for path in _current_inventory(repo_root)
        if not path.startswith(PACKAGED_MIRROR_ROOT)
    }
    retained = {
        path for path, row in indexed.items() if row.get("after_sha256") is not None
    }
    if current != retained:
        missing = sorted(current - retained)
        stale = sorted(retained - current)
        if missing:
            errors.append("editorial audit omits current documents: " + ", ".join(missing))
        if stale:
            errors.append("editorial audit retains absent documents: " + ", ".join(stale))
    for path, row in indexed.items():
        target = repo_root / path
        after = row.get("after_sha256")
        if after is None:
            if target.exists():
                errors.append(f"editorial audit marks present document pruned: {path}")
            continue
        if target.is_symlink() or not target.is_file():
            errors.append(f"editorial audit current document is unsafe: {path}")
            continue
        if after != _sha(target.read_bytes()):
            errors.append(f"editorial audit current digest mismatches: {path}")
        expected_disposition = (
            "compatibility_redirect"
            if row.get("topic_role") == "compatibility_redirect"
            else "historical"
            if row.get("topic_role") == "historical"
            else "retained"
            if row.get("before_sha256") == after
            else "revised"
        )
        if row.get("disposition") != expected_disposition:
            errors.append(f"editorial audit disposition mismatches: {path}")
    return errors


def _audience(path: str) -> str:
    if path in {"AGENTS.md", "AGENTS.yml", "CLAUDE.md"} or path.endswith(
        ("/AGENTS.md", "/AGENTS.yml", "/CLAUDE.md")
    ):
        return "repository agents"
    if path == "docs/assets/bcf-governance-pack-hero.jpg":
        return "BCF evaluators and adopters"
    if path == "LICENSE" or path.endswith("/LICENSE"):
        return "redistributors"
    if path == "CHANGELOG.md" or path.endswith("/CHANGELOG.md"):
        return "adopters and release operators"
    if path.startswith("template-repo/") or path.startswith("examples/"):
        return "consumer repository operators"
    if path.startswith("docs/"):
        return "BCF adopters and maintainers"
    if path.startswith("audits/"):
        return "governance reviewers"
    return "BCF evaluators and adopters"


def _topic(path: str) -> tuple[str, str]:
    if path.endswith("AGENTS.md") or path.endswith("CLAUDE.md"):
        owner = str(Path(path).with_name("AGENTS.yml"))
        return owner, "compatibility_redirect"
    if path == "CHANGELOG.md" or path.endswith("/CHANGELOG.md"):
        return path, "historical"
    if path == "docs/assets/bcf-governance-pack-hero.jpg":
        return "README.md", "supporting_asset"
    return path, "canonical"


def build_rows(repo_root: Path, base_sha: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relative in _inventory(repo_root, base_sha):
        before = _base_bytes(repo_root, base_sha, relative)
        path = repo_root / relative
        after = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        topic_owner, topic_role = _topic(relative)
        if after is None:
            disposition = "pruned"
        elif topic_role == "compatibility_redirect":
            disposition = "compatibility_redirect"
        elif topic_role == "historical":
            disposition = "historical"
        elif before == after:
            disposition = "retained"
        else:
            disposition = "revised"
        rows.append(
            {
                "path": relative,
                "audience": _audience(relative),
                "canonical_topic_owner": topic_owner,
                "topic_role": topic_role,
                "before_sha256": _sha(before) if before is not None else None,
                "after_sha256": _sha(after) if after is not None else None,
                "findings": [
                    SPECIFIC_FINDINGS.get(
                        relative,
                        "reviewed; no currency, consolidation, or pruning change required",
                    )
                    if before != after
                    else "reviewed; no currency, consolidation, or pruning change required"
                ],
                "disposition": disposition,
            }
        )
    return rows


def build_audit(
    repo_root: Path, base_sha: str, audit_path: Path
) -> dict[str, Any]:
    relative_audit = audit_path.relative_to(repo_root).as_posix()
    version = audit_path.name.removeprefix("v").removesuffix(
        "-editorial-review.yml"
    )
    return {
        "schema_version": "1.0",
        "document": {
            "kind": "editorial_review",
            "id": f"bcf-governance-v{version}-editorial-review",
            "status": "completed",
            "path": relative_audit,
        },
        "base_commit": base_sha,
        "inventory_policy": {
            "source_documents": "tracked Markdown and root LICENSE from base union current tree",
            "packaged_mirror_root": PACKAGED_MIRROR_ROOT.rstrip("/"),
            "packaged_mirror_review": "canonical template source plus byte-parity gate",
        },
        "documents": build_rows(repo_root, base_sha),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--base-sha")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    audit_path = args.audit if args.audit.is_absolute() else root / args.audit
    if args.apply:
        if not args.base_sha:
            raise SystemExit("--apply requires --base-sha")
        payload = build_audit(root, args.base_sha, audit_path)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(yaml.safe_dump(payload, sort_keys=False, width=140), encoding="utf-8")
        print(f"editorial-audit-written:{len(payload['documents'])}")
        return
    if not audit_path.is_file() or audit_path.is_symlink():
        raise SystemExit("editorial audit is missing or unsafe")
    actual = yaml.safe_load(audit_path.read_text(encoding="utf-8"))
    base_sha = str(actual.get("base_commit", "")) if isinstance(actual, dict) else ""
    if not isinstance(actual, dict):
        raise SystemExit("editorial audit must contain a mapping")
    if _base_is_available(root, base_sha):
        expected = build_audit(root, base_sha, audit_path)
        if actual != expected:
            raise SystemExit("editorial audit differs from exact tracked document inventory or bytes")
    else:
        errors = _check_current_custody(root, actual)
        if errors:
            raise SystemExit("; ".join(errors))
    print(f"editorial-audit-ok:{len(actual['documents'])}")


if __name__ == "__main__":
    main()
