"""Mechanically collect and verify pytest populations owned by gate contracts."""

from __future__ import annotations

import argparse
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .evidence_execution import _selected_python


class TestManifestError(ValueError):
    """Raised when a governed test population cannot be reproduced."""


@dataclass(frozen=True)
class PytestSelectorMap:
    """An exact, collision-free mapping from JUnit identities to pytest selectors."""

    gate_id: str
    entries: tuple[tuple[str, str], ...]

    @property
    def normalized_nodes(self) -> tuple[str, ...]:
        return tuple(identity for identity, _ in self.entries)

    def selector_for(self, identity: object) -> str:
        if not isinstance(identity, str) or not identity:
            raise TestManifestError("test-node oracle is not exact")
        for normalized, selector in self.entries:
            if normalized == identity:
                return selector
        raise TestManifestError(
            f"test-node oracle {identity!r} is absent from the verified "
            f"collection mapping for {self.gate_id}"
        )


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TestManifestError(f"{path} must deserialize to a mapping")
    return payload


def _test_contract(repo_root: Path, gate_id: str) -> dict[str, Any]:
    registry = _load_yaml(repo_root / "governance/gate-contracts.yml")
    gates = registry.get("gates")
    gate = gates.get(gate_id) if isinstance(gates, dict) else None
    evidence = gate.get("evidence") if isinstance(gate, dict) else None
    contract = evidence.get("test_contract") if isinstance(evidence, dict) else None
    if not isinstance(contract, dict):
        raise TestManifestError(f"gate {gate_id} has no governed test contract")
    selectors = contract.get("selectors")
    manifest = contract.get("expected_node_manifest")
    if not isinstance(selectors, list) or not selectors:
        raise TestManifestError(f"gate {gate_id} has no governed test selectors")
    if not isinstance(manifest, str) or not manifest:
        raise TestManifestError(f"gate {gate_id} has no expected node manifest")
    return contract


def _safe_manifest_path(repo_root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise TestManifestError("expected node manifest path is invalid")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise TestManifestError("expected node manifest must stay inside the repository")
    path = repo_root / relative
    parent = path.parent.resolve()
    if not parent.is_relative_to(repo_root.resolve()):
        raise TestManifestError("expected node manifest escapes the repository")
    return path


def _selectors(repo_root: Path, values: object) -> list[str]:
    if not isinstance(values, list) or not values:
        raise TestManifestError("test selectors must be a non-empty list")
    resolved: list[str] = []
    for raw in values:
        if raw == "@test_roots":
            agents = _load_yaml(repo_root / "AGENTS.yml")
            testing = agents.get("testing_governance")
            roots = testing.get("test_roots") if isinstance(testing, dict) else None
            if not isinstance(roots, list) or not roots:
                raise TestManifestError("AGENTS.yml declares no test roots")
            resolved.extend(str(value) for value in roots)
        elif (
            isinstance(raw, str)
            and raw
            and not Path(raw).is_absolute()
            and ".." not in Path(raw).parts
        ):
            resolved.append(raw)
        else:
            raise TestManifestError("test selector must be a safe repository-relative value")
    return resolved


def _junit_node_id(pytest_node_id: str) -> str:
    if "::" not in pytest_node_id:
        module = Path(pytest_node_id).with_suffix("").as_posix().replace("/", ".")
        return module
    source, remainder = pytest_node_id.split("::", 1)
    parameter_at = remainder.find("[")
    structural = remainder if parameter_at < 0 else remainder[:parameter_at]
    parameter = "" if parameter_at < 0 else remainder[parameter_at:]
    names = structural.split("::")
    module = Path(source).with_suffix("").as_posix().replace("/", ".")
    if len(names) > 1:
        module = ".".join([module, *names[:-1]])
    return f"{module}::{names[-1]}{parameter}"


def _safe_pytest_node(value: str) -> str:
    if value.count("::") < 1 or any(character in value for character in "\x00\r\n"):
        raise TestManifestError(f"pytest collection returned an unsafe node {value!r}")
    source = value.split("::", 1)[0]
    relative = Path(source)
    if (
        not source.endswith(".py")
        or source.startswith("-")
        or relative.is_absolute()
        or ".." in relative.parts
    ):
        raise TestManifestError(f"pytest collection returned an unsafe node {value!r}")
    return value


def _selector_map_from_nodes(
    gate_id: str, raw_nodes: list[str]
) -> VerifiedTestSelectorMap:
    by_identity: dict[str, str] = {}
    for raw_node in raw_nodes:
        selector = _safe_pytest_node(raw_node)
        identity = _junit_node_id(selector)
        previous = by_identity.get(identity)
        if previous is not None and previous != selector:
            raise TestManifestError(
                f"ambiguous JUnit node identity for {gate_id}: {identity!r} maps to "
                f"both {previous!r} and {selector!r}"
            )
        by_identity[identity] = selector
    if not by_identity:
        raise TestManifestError(f"pytest collection returned zero nodes for {gate_id}")
    return PytestSelectorMap(gate_id, tuple(sorted(by_identity.items())))


def collect_selector_map(
    repo_root: Path,
    gate_id: str,
    *,
    python_executable: str | Path | None = None,
) -> PytestSelectorMap:
    """Collect the lossless pytest/JUnit identity mapping for one test gate."""
    repo_root = repo_root.resolve()
    contract = _test_contract(repo_root, gate_id)
    python = _selected_python(python_executable)
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [
            str(python),
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            *_selectors(repo_root, contract.get("selectors")),
        ],
        cwd=repo_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise TestManifestError(
            f"pytest collection infrastructure failure for {gate_id}: {diagnostic}"
        )
    return _selector_map_from_nodes(
        gate_id,
        [
            line.strip()
            for line in result.stdout.splitlines()
            if ".py::" in line and not line.startswith((" ", "="))
        ],
    )


def collect_nodes(
    repo_root: Path,
    gate_id: str,
    *,
    python_executable: str | Path | None = None,
) -> list[str]:
    """Collect the exact JUnit-normalized nodes selected by one gate contract."""
    return list(
        collect_selector_map(
            repo_root, gate_id, python_executable=python_executable
        ).normalized_nodes
    )


def declared_test_gates(repo_root: Path) -> list[str]:
    registry = _load_yaml(repo_root / "governance/gate-contracts.yml")
    gates = registry.get("gates")
    if not isinstance(gates, dict):
        return []
    return sorted(
        str(gate_id)
        for gate_id, gate in gates.items()
        if isinstance(gate, dict)
        and isinstance(gate.get("evidence"), dict)
        and isinstance(gate["evidence"].get("test_contract"), dict)
        and gate["evidence"]["test_contract"].get("expected_node_manifest")
    )


def check_gate_selectors(
    repo_root: Path,
    gate_id: str,
    *,
    python_executable: str | Path | None = None,
) -> PytestSelectorMap:
    """Return the verified lossless mapping or raise on manifest drift."""
    contract = _test_contract(repo_root, gate_id)
    path = _safe_manifest_path(repo_root, contract.get("expected_node_manifest"))
    if not path.is_file() or path.is_symlink():
        raise TestManifestError(f"expected node manifest is missing for {gate_id}")
    expected = sorted(
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    mapping = collect_selector_map(
        repo_root, gate_id, python_executable=python_executable
    )
    actual = list(mapping.normalized_nodes)
    if expected != actual:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise TestManifestError(
            f"test node manifest drift for {gate_id}; missing={missing}; extra={extra}"
        )
    return mapping


def check_gate(
    repo_root: Path,
    gate_id: str,
    *,
    python_executable: str | Path | None = None,
) -> list[str]:
    """Return collected nodes or raise when the committed manifest drifts."""
    return list(
        check_gate_selectors(
            repo_root, gate_id, python_executable=python_executable
        ).normalized_nodes
    )


def update_gate(
    repo_root: Path,
    gate_id: str,
    *,
    python_executable: str | Path | None = None,
) -> Path:
    """Regenerate one manifest from its governed selector query."""
    contract = _test_contract(repo_root, gate_id)
    path = _safe_manifest_path(repo_root, contract.get("expected_node_manifest"))
    nodes = collect_nodes(repo_root, gate_id, python_executable=python_executable)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(nodes) + "\n", encoding="utf-8")
    return path


def check_all(
    repo_root: Path, *, python_executable: str | Path | None = None
) -> dict[str, int]:
    return {
        gate_id: len(
            check_gate(repo_root, gate_id, python_executable=python_executable)
        )
        for gate_id in declared_test_gates(repo_root)
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Check or update exact pytest manifests.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("operation", choices=("check", "update"))
    parser.add_argument("--gate", required=True)
    parser.add_argument("--python", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == "check":
            nodes = check_gate(
                args.repo_root.resolve(), args.gate, python_executable=args.python
            )
            print(f"test-manifest-ok gate={args.gate} nodes={len(nodes)}")
        else:
            path = update_gate(
                args.repo_root.resolve(), args.gate, python_executable=args.python
            )
            print(path)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
