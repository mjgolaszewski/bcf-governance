"""Scan governed artifacts for local paths and private infrastructure markers."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


OUTPUT_FORMATS = {"text", "json"}
ALLOW_MARKERS = ("governance-exposure: allow", "exposure-scan: allow")
TEXT_SUFFIXES = {".json", ".md", ".toml", ".txt", ".yaml", ".yml"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "artifacts",
    ".artifacts",
    "build",
    "dist",
    "node_modules",
    "venv",
}
DEFAULT_SCAN_PATHS = [
    "AGENTS.yml",
    "MEMORY.yml",
    "architecture-boundaries.yml",
    "governance-profile.yml",
    "README.md",
    "audits",
    "contracts",
    "docs",
    "governance",
    "phases",
    "plans",
]
PATTERNS = {
    "local_workspace_path": re.compile(r"(?<![A-Za-z0-9_])/(?:docker|home|Users)/[^\s'\"`<>)\]}]+"),
    "windows_user_path": re.compile(r"\b[A-Za-z]:\\Users\\[^\s'\"`<>)\]}]+"),
    "private_ipv4": re.compile(
        r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
    ),
    "private_hostname": re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:internal|corp|lan|local)\b"
    ),
}


@dataclass(frozen=True)
class ExposureFinding:
    path: str
    line: int
    pattern: str
    match: str


@dataclass(frozen=True)
class ExposureReport:
    status: str
    repo_root: str
    scanned_files: int
    findings: list[ExposureFinding]


def _repo_relative(repo_root: Path, path: Path) -> str:
    return path.relative_to(repo_root).as_posix()


def _is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {"Makefile", "Makefile.fragment"}


def _load_manifest_paths(repo_root: Path) -> list[str]:
    manifest_path = repo_root / "governance" / "artifact-manifest.yml"
    if not manifest_path.exists():
        return []
    payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return []
    roots = payload.get("artifact_roots")
    if not isinstance(roots, dict):
        return []
    paths: list[str] = []
    for root in roots.values():
        if isinstance(root, dict) and isinstance(root.get("path"), str):
            paths.append(root["path"].rstrip("/"))
    return paths


def _scan_roots(repo_root: Path, explicit_paths: list[str]) -> list[Path]:
    roots = explicit_paths or [*DEFAULT_SCAN_PATHS, *_load_manifest_paths(repo_root)]
    paths: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        candidate = (repo_root / root).resolve()
        if not candidate.exists() or candidate in seen:
            continue
        seen.add(candidate)
        paths.append(candidate)
    return paths


def _iter_files(repo_root: Path, roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            if _is_text_file(root):
                files.append(root)
            continue
        for current_root, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
            root_path = Path(current_root)
            for filename in filenames:
                path = root_path / filename
                if _is_text_file(path):
                    files.append(path)
    return sorted(set(files))


def scan_exposures(repo_root: Path, *, paths: list[str] | None = None) -> ExposureReport:
    repo_root = repo_root.resolve()
    scan_paths = _scan_roots(repo_root, paths or [])
    findings: list[ExposureFinding] = []
    files = _iter_files(repo_root, scan_paths)
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if any(marker in line for marker in ALLOW_MARKERS):
                continue
            for pattern_name, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    findings.append(
                        ExposureFinding(
                            path=_repo_relative(repo_root, path),
                            line=line_number,
                            pattern=pattern_name,
                            match=match.group(0),
                        )
                    )
    return ExposureReport(
        status="fail" if findings else "pass",
        repo_root=str(repo_root),
        scanned_files=len(files),
        findings=findings,
    )


def _report_to_dict(report: ExposureReport) -> dict[str, Any]:
    return asdict(report)


def _emit_json(report: ExposureReport, *, compact: bool) -> None:
    separators = (",", ":") if compact else None
    indent = None if compact else 2
    print(json.dumps(_report_to_dict(report), indent=indent, separators=separators, sort_keys=True))


def _emit_text(report: ExposureReport) -> None:
    if report.status == "pass":
        print("governance-exposure-scan-ok")
        return
    print("governance exposure findings:")
    for finding in report.findings:
        print(f"- {finding.path}:{finding.line} {finding.pattern}: {finding.match}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan governed artifacts for local paths and private infrastructure markers."
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--path", action="append", default=[], help="Repo-relative path to scan.")
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=sorted(OUTPUT_FORMATS),
        default="text",
    )
    parser.add_argument("--compact", action="store_true", help="Use compact JSON output.")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    report = scan_exposures(args.repo_root, paths=args.path)
    if args.output_format == "json":
        _emit_json(report, compact=args.compact)
    else:
        _emit_text(report)
    if report.status != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"governance exposure scan failed: {exc}", file=sys.stderr)
        raise
