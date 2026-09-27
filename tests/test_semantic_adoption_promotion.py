"""Dependency custody remains valid through every managed adoption write."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import semantic_authority_commands as commands
from bcf_governance.tooling.governance_install import transaction
from bcf_governance.tooling.semantic_adoption_dependencies import SemanticDependencyError
from semantic_typescript_fixture import repository


def test_adoption_compacts_semantic_registries_without_changing_values(
    tmp_path: Path,
) -> None:
    payload = repository(tmp_path)
    registry = payload["contracts"]["canonical_representations"]
    prototype = registry["representations"][0]
    registry["representations"] = []
    shared_symbols = ["model.py::Value"]
    for index in range(7):
        row = copy.deepcopy(prototype)
        row["semantic_id"] = f"example.value-{index}.v1"
        row["authorized_constructors_and_factories"] = shared_symbols
        row["authorized_pure_delegates"] = shared_symbols
        registry["representations"].append(row)

    first = commands._contract_bytes(payload, "canonical_representations")
    second = commands._contract_bytes(payload, "canonical_representations")

    assert first == second
    assert yaml.safe_load(first) == registry
    assert len(first.splitlines()) <= 200


def test_dependency_change_during_first_promotion_rolls_back_all_managed_bytes_and_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository(tmp_path)
    commands._lock(tmp_path, apply=True)
    for index, relative in enumerate(commands.MANAGED_PATHS):
        (tmp_path / relative).chmod(0o600 if index % 2 else 0o640)
    before = {
        relative: ((tmp_path / relative).read_bytes(), (tmp_path / relative).stat().st_mode)
        for relative in commands.MANAGED_PATHS
    }
    dependency = tmp_path / "node_modules/@bcf-test/declared-types/index.d.ts"
    original_dependency = dependency.read_bytes()
    real_write = transaction._atomic_write
    written: list[Path] = []

    def mutate_dependency_during_write(path: Path, data: bytes, mode: int) -> None:
        real_write(path, data, mode)
        written.append(path)
        if len(written) == 1:
            assert path.relative_to(tmp_path).as_posix() in commands.MANAGED_PATHS
            dependency.write_bytes(original_dependency + b"\n// concurrent dependency change\n")

    monkeypatch.setattr(transaction, "_atomic_write", mutate_dependency_during_write)
    with pytest.raises(SemanticDependencyError, match="changed during adoption"):
        commands._adopt(tmp_path, tmp_path / "adopt.yml", apply=True)
    assert written, "The failure must follow an actual managed promotion write"
    assert written[0] in written[1:], "The partial managed write must be rolled back"
    assert before == {
        relative: ((tmp_path / relative).read_bytes(), (tmp_path / relative).stat().st_mode)
        for relative in commands.MANAGED_PATHS
    }
    assert dependency.read_bytes() != original_dependency
