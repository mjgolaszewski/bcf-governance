"""Cheap structural applicability checks for governed negative controls."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml  # type: ignore[import-untyped]

from ..yaml_mutations import YAMLMutationPathError, resolve_yaml_target, typed_mutation_value


class NegativeControlPreflightError(ValueError):
    """A declared mutation or oracle no longer targets canonical source."""


def inspect_negative_control_targets(
    repo_root: Path, *, git: Callable[..., str],
) -> int:
    """Reject stale mutation targets and undeclared oracle nodes before evidence."""
    registry = yaml.safe_load(
        (repo_root / "governance/gate-contracts.yml").read_text(encoding="utf-8")
    )
    gates = registry.get("gates") if isinstance(registry, dict) else None
    if not isinstance(gates, dict):
        raise NegativeControlPreflightError("gate contract registry has no gate mappings")
    stale_oracles: list[str] = []
    for gate_id, gate in gates.items():
        evidence = gate.get("evidence") if isinstance(gate, dict) else None
        test_contract = evidence.get("test_contract") if isinstance(evidence, dict) else None
        manifest_value = test_contract.get("expected_node_manifest") if isinstance(test_contract, dict) else None
        manifest_path = repo_root / manifest_value if isinstance(manifest_value, str) else None
        governed_nodes = (
            {
                line.strip()
                for line in manifest_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            if manifest_path is not None and manifest_path.is_file()
            else set()
        )
        controls = gate.get("negative_controls") if isinstance(gate, dict) else None
        for control in controls if isinstance(controls, list) else ():
            oracle = control.get("oracle") if isinstance(control, dict) else None
            nodes = oracle.get("node_ids") if isinstance(oracle, dict) else None
            if oracle and oracle.get("kind") == "test_node_failure" and (
                not isinstance(nodes, list) or not nodes or any(node not in governed_nodes for node in nodes)
            ):
                stale_oracles.append(str(control.get("id", gate_id)))
    if stale_oracles:
        raise NegativeControlPreflightError(
            "negative control oracle nodes are stale: " + ", ".join(sorted(stale_oracles))
        )
    ledger: dict[str, Any] | None = None
    checked = 0
    root = repo_root.resolve()
    for gate_id, gate in gates.items():
        controls = gate.get("negative_controls") if isinstance(gate, dict) else None
        if not isinstance(controls, list):
            continue
        for control in controls:
            if not isinstance(control, dict) or not isinstance(control.get("mutation"), dict):
                raise NegativeControlPreflightError(f"negative control is invalid: {gate_id}")
            control_id = str(control.get("id", gate_id))
            mutation = control["mutation"]
            relative_value = mutation.get("path")
            if relative_value == "@active_phase_log":
                if ledger is None:
                    ledger_value = yaml.safe_load(
                        (repo_root / "plans/phase-ledger.yml").read_text(encoding="utf-8")
                    )
                    ledger = ledger_value if isinstance(ledger_value, dict) else {}
                active = ledger.get("active_phase")
                relative_value = active.get("log") if isinstance(active, dict) else None
            if not isinstance(relative_value, str):
                raise NegativeControlPreflightError(f"negative control target is missing: {control_id}")
            relative = Path(relative_value)
            if relative.is_absolute() or ".." in relative.parts:
                raise NegativeControlPreflightError(f"negative control target is unsafe: {control_id}")
            target = repo_root / relative
            if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
                raise NegativeControlPreflightError(f"negative control target is absent: {control_id}")
            if git(repo_root, "ls-files", "--error-unmatch", relative.as_posix()) != relative.as_posix():
                raise NegativeControlPreflightError(f"negative control target is untracked: {control_id}")
            search = mutation.get("search")
            if isinstance(search, str):
                occurrences = target.read_text(encoding="utf-8").count(search)
                if occurrences == 0:
                    raise NegativeControlPreflightError(
                        f"negative control target is stale: {control_id}"
                    )
            else:
                yaml_path = mutation.get("yaml_path")
                if not isinstance(yaml_path, str):
                    raise NegativeControlPreflightError(f"negative control mutation is unsupported: {control_id}")
                current: Any = yaml.safe_load(target.read_text(encoding="utf-8"))
                try:
                    value = typed_mutation_value(mutation)
                    current = resolve_yaml_target(current, yaml_path).value
                except YAMLMutationPathError as exc:
                    raise NegativeControlPreflightError(
                        f"negative control YAML target is stale: {control_id}"
                    ) from exc
                if current == value:
                    raise NegativeControlPreflightError(
                        f"negative control YAML target is already mutated: {control_id}"
                    )
            checked += 1
    return checked
