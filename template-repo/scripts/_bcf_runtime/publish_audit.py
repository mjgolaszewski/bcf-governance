"""Audit every reachable Git blob before making a repository public."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    rule_id: str
    object_id: str
    commit: str
    path: str
    remediation: str


RULES = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "remove and rotate the private key"),
    ("github-token", re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b"), "remove and rotate the GitHub token"),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "remove and rotate the AWS access key"),
    ("assigned-secret", re.compile(r"(?i)\b(?:password|token_secret|client_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "replace the assigned secret with environment configuration"),
    ("private-ipv4", re.compile(r"(?<![0-9])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![0-9])"), "replace the private address with a public-safe placeholder"),
    ("internal-hostname", re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:internal|local|lan|home|corp)\b"), "replace the internal hostname with a reserved example domain"),
    ("workspace-path", re.compile(r"(?<![A-Za-z0-9_])/(?:docker|home|Users)/[^\s'\"`<>)\]}]+"), "replace the local workspace path with a repository-relative path"),
)


def _git(repo_root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=check,
        capture_output=True,
    )


def _require_complete_history(repo_root: Path) -> None:
    inside = _git(repo_root, "rev-parse", "--is-inside-work-tree", check=False)
    if inside.returncode != 0:
        raise RuntimeError("publish audit requires a Git repository")
    shallow = _git(repo_root, "rev-parse", "--is-shallow-repository").stdout.strip()
    if shallow == b"true":
        raise RuntimeError("publish audit requires complete history; run git fetch --unshallow --tags")


def _historical_blobs(repo_root: Path) -> dict[str, tuple[str, str]]:
    commits = _git(repo_root, "rev-list", "--all").stdout.decode().splitlines()
    blobs: dict[str, tuple[str, str]] = {}
    for commit in commits:
        tree = _git(repo_root, "ls-tree", "-r", "-z", "--full-tree", commit).stdout
        for entry in tree.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            _mode, object_type, object_id = metadata.decode().split()
            if object_type == "blob":
                blobs.setdefault(object_id, (commit, raw_path.decode(errors="replace")))
    return blobs


def audit_history(repo_root: Path) -> list[Finding]:
    repo_root = repo_root.resolve()
    _require_complete_history(repo_root)
    findings: list[Finding] = []
    for object_id, (commit, path) in _historical_blobs(repo_root).items():
        content = _git(repo_root, "cat-file", "blob", object_id).stdout
        if b"\0" in content:
            continue
        text = content.decode("utf-8", errors="ignore")
        sanitized = re.sub(r"(?i)\b[a-z0-9.-]+\.(?:invalid|test)\b", "reserved.example", text)
        for rule_id, pattern, remediation in RULES:
            if pattern.search(sanitized):
                findings.append(Finding(rule_id, object_id, commit, path, remediation))
    return findings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit complete Git history before publication.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--history", action="store_true", help="Scan all blobs reachable from all refs.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--compact", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    if not args.history:
        raise SystemExit("publish-audit currently requires --history")
    try:
        findings = audit_history(args.repo_root)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    payload = {"status": "fail" if findings else "pass", "scope": "history", "findings": [asdict(item) for item in findings]}
    if args.format == "json":
        print(json.dumps(payload, indent=None if args.compact else 2, separators=(",", ":") if args.compact else None, sort_keys=True))
    else:
        print(f"publish-audit-{payload['status']} (history)")
        for finding in findings:
            print(f"- {finding.rule_id}: {finding.commit}:{finding.path} ({finding.object_id}) — {finding.remediation}")
    if findings:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
