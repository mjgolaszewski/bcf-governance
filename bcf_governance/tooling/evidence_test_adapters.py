"""Normalize pytest and JUnit evidence into portable observations."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pytest_counts(text: str) -> dict[str, int]:
    counts = {
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }
    for name in counts:
        matches = re.findall(rf"(\d+)\s+{name}", text, flags=re.IGNORECASE)
        if matches:
            counts[name] = int(matches[-1])
    collected_matches = re.findall(
        r"collected\s+(\d+)\s+items?", text, flags=re.IGNORECASE
    )
    terminal_total = sum(counts.values())
    counts["collected"] = (
        int(collected_matches[-1]) if collected_matches else terminal_total
    )
    counts["executed"] = (
        counts["passed"]
        + counts["failed"]
        + counts["errors"]
        + counts["xfailed"]
        + counts["xpassed"]
    )
    return counts


def _junit_observations(path: Path) -> tuple[dict[str, int], list[str]]:
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    node_ids: list[str] = []
    skipped = failed = errors = 0
    for case in cases:
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "")
        node_ids.append(f"{classname}::{name}" if classname else name)
        skipped += int(case.find("skipped") is not None)
        failed += int(case.find("failure") is not None)
        errors += int(case.find("error") is not None)
    collected = len(cases)
    executed = collected - skipped
    return (
        {
            "collected": collected,
            "executed": executed,
            "passed": executed - failed - errors,
            "failed": failed,
            "errors": errors,
            "skipped": skipped,
            "xfailed": 0,
            "xpassed": 0,
        },
        sorted(node_ids),
    )


def recompute_test_artifact_observations(
    receipt_path: Path, receipt: dict[str, Any]
) -> tuple[dict[str, int], list[str] | None]:
    """Reparse raw test artifacts instead of trusting normalized receipt counts."""
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list):
        return _pytest_counts(""), None
    probe_artifact_names: set[str] = set()
    probes = receipt.get("behavioral_probes")
    if isinstance(probes, list):
        for probe in probes:
            raw_artifacts = probe.get("raw_artifacts") if isinstance(probe, dict) else None
            if isinstance(raw_artifacts, dict):
                probe_artifact_names.update(
                    str(value)
                    for value in raw_artifacts.values()
                    if isinstance(value, str)
                )
    text_parts: list[str] = []
    for raw in artifacts:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            continue
        if raw["path"] in probe_artifact_names:
            continue
        relative = Path(raw["path"])
        if relative.is_absolute() or ".." in relative.parts:
            continue
        path = receipt_path.parent / relative
        if not path.is_file():
            continue
        media_type = str(raw.get("media_type", ""))
        if "junit" in media_type or path.name.endswith(".junit.xml"):
            try:
                return _junit_observations(path)
            except (ET.ParseError, OSError, ValueError):
                return _pytest_counts(""), []
        if path.name.endswith((".stdout.txt", ".stderr.txt")):
            try:
                text_parts.append(path.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                continue
    return _pytest_counts("\n".join(text_parts)), None


def test_observations(
    repo_root: Path,
    contract: dict[str, Any],
    result: subprocess.CompletedProcess[str],
    output_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    test_contract = contract.get("test_contract")
    test_contract = test_contract if isinstance(test_contract, dict) else {}
    thresholds = {
        "min_collected": int(test_contract.get("min_collected", 1)),
        "min_executed": int(test_contract.get("min_executed", 1)),
        "max_skipped": int(test_contract.get("max_skipped", 0)),
    }
    node_ids: list[str] = []
    artifacts: list[dict[str, str]] = []
    junit_path_value = test_contract.get("junit_xml")
    if isinstance(junit_path_value, str) and junit_path_value:
        source = repo_root / junit_path_value
        if not source.exists():
            counts = _pytest_counts(result.stdout + "\n" + result.stderr)
        else:
            counts, node_ids = _junit_observations(source)
            destination = output_dir / f"{contract['target']}.junit.xml"
            shutil.copy2(source, destination)
            artifacts.append(
                {
                    "path": destination.name,
                    "media_type": "application/junit+xml",
                    "sha256": _sha256(destination),
                }
            )
    else:
        counts = _pytest_counts(result.stdout + "\n" + result.stderr)
    manifest_value = test_contract.get("expected_node_manifest")
    expected_nodes: list[str] = []
    if isinstance(manifest_value, str) and manifest_value:
        manifest_path = repo_root / manifest_value
        if manifest_path.exists():
            expected_nodes = sorted(
                line.strip()
                for line in manifest_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
    return (
        {
            "test_counts": counts,
            "test_thresholds": thresholds,
            "test_node_ids": node_ids,
            "expected_test_node_ids": expected_nodes,
            "expected_nodes_mode": str(
                test_contract.get("expected_nodes_mode", "contains")
            ),
        },
        artifacts,
    )
