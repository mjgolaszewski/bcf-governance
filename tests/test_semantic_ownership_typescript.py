from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from bcf_governance.tooling.semantic_ownership_cross_language import (
    build_endpoint_traces,
)
from bcf_governance.tooling.semantic_ownership_reference import ReferenceProofError
from bcf_governance.tooling.semantic_ownership_typescript import (
    TypeScriptDiscoveryError,
    contract_from_mapping,
    discover_typescript_source,
    tracked_typescript_files,
)


def _contract() -> dict[str, object]:
    return {
        "node_executable": "node",
        "tsconfig": "tsconfig.json",
        "package_lock": "package-lock.json",
        "source_roots": ["src"],
        "browser_contract_roots": ["server"],
    }


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=repo, check=True, capture_output=True)


def test_typescript_contract_is_closed_and_repository_relative() -> None:
    payload = _contract()
    payload["unexpected"] = True
    with pytest.raises(TypeScriptDiscoveryError, match="unknown or missing"):
        contract_from_mapping(payload)

    payload = _contract()
    payload["tsconfig"] = "../tsconfig.json"
    with pytest.raises(TypeScriptDiscoveryError, match="inside the repository"):
        contract_from_mapping(payload)


def test_typescript_inventory_is_tracked_and_source_first(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src/owned.ts").write_text("export const owned = true;\n", encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "soip@example.test")
    _git(repo, "config", "user.name", "SOIP Test")
    _git(repo, "add", "src/owned.ts")
    _git(repo, "commit", "-m", "tracked TypeScript")
    (repo / "src/untracked.ts").write_text("export const hidden = true;\n", encoding="utf-8")

    assert [value.relative_to(repo).as_posix() for value in tracked_typescript_files(repo)] == [
        "src/owned.ts"
    ]


def test_typescript_discovery_uses_locked_local_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    source = repo / "src/owned.ts"
    package = repo / "node_modules/typescript/package.json"
    source.parent.mkdir(parents=True)
    package.parent.mkdir(parents=True)
    source.write_text("export const owned = true;\n", encoding="utf-8")
    (repo / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    (repo / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/typescript": {"version": "6.0.3"}}}),
        encoding="utf-8",
    )
    package.write_text(json.dumps({"version": "6.0.3"}), encoding="utf-8")
    node = tmp_path / "node"
    node.write_bytes(b"declared-node")
    monkeypatch.setattr(
        "bcf_governance.tooling.semantic_ownership_typescript.shutil.which",
        lambda _: str(node),
    )
    payload = {
        "language": "typescript",
        "node_version": "v24.20.0",
        "compiler_version": "6.0.3",
        "files": ["src/owned.ts"],
        "functions": [],
        "constructors": [],
        "normalizations": [],
        "unresolved": [],
        "fetches": [],
        "decoder_calls": [],
        "endpoint_contracts": [],
        "diagnostics": [],
    }
    monkeypatch.setattr(
        "bcf_governance.tooling.semantic_ownership_typescript.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )

    result = discover_typescript_source(
        repo, contract_from_mapping(_contract()), [source]
    )

    assert result["compiler_version"] == "6.0.3"
    assert result["files"][0]["path"] == "src/owned.ts"
    assert result["toolchain"]["typescript_version"] == "6.0.3"
    assert result["toolchain"]["node_version"] == "v24.20.0"


def test_typescript_discovery_rejects_installed_version_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    source = repo / "src/owned.ts"
    package = repo / "node_modules/typescript/package.json"
    source.parent.mkdir(parents=True)
    package.parent.mkdir(parents=True)
    source.write_text("export const owned = true;\n", encoding="utf-8")
    (repo / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    (repo / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/typescript": {"version": "6.0.3"}}}),
        encoding="utf-8",
    )
    package.write_text(json.dumps({"version": "6.0.2"}), encoding="utf-8")
    node = tmp_path / "node"
    node.write_bytes(b"declared-node")
    monkeypatch.setattr(
        "bcf_governance.tooling.semantic_ownership_typescript.shutil.which",
        lambda _: str(node),
    )

    with pytest.raises(TypeScriptDiscoveryError, match="does not match"):
        discover_typescript_source(repo, contract_from_mapping(_contract()), [source])


def test_typescript_compiler_failure_is_infrastructure_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    source = repo / "src/owned.ts"
    source.parent.mkdir(parents=True)
    source.write_text("export const owned = true;\n", encoding="utf-8")
    (repo / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    node = tmp_path / "node"
    node.write_bytes(b"declared-node")
    monkeypatch.setattr(
        "bcf_governance.tooling.semantic_ownership_typescript.shutil.which",
        lambda _: str(node),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.semantic_ownership_typescript._compiler_version",
        lambda *_: "6.0.3",
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.semantic_ownership_typescript.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=2, stdout="", stderr="tsconfig compiler diagnostic"
        ),
    )

    with pytest.raises(TypeScriptDiscoveryError, match="tsconfig compiler diagnostic"):
        discover_typescript_source(repo, contract_from_mapping(_contract()), [source])


def test_cross_language_trace_requires_generated_contract_and_decoder() -> None:
    python = {
        "endpoints": [
            {
                "path": "/api/items",
                "method": "GET",
                "response_model": "Items",
                "symbol": "server/routes.py::items",
            }
        ]
    }
    typescript = {
        "endpoint_contracts": [
            {"method": "GET", "endpoint": "/api/items", "response_type": "Items"}
        ],
        "fetches": [
            {
                "endpoint": "/api/items",
                "caller": "src/items.ts::loadItems",
                "transport_symbol": "src/http.ts::fetchFn",
            }
        ],
        "decoder_calls": [
            {
                "caller": "src/items.ts::loadItems",
                "symbol": "src/contracts.ts::responseDecoderForEndpoint",
            }
        ],
    }

    traces = build_endpoint_traces(
        python, typescript, browser_contract_roots=("server",)
    )

    assert traces[0]["browser_contract_required"] is True
    assert traces[0]["decoder_coverage"] is True


def test_reference_proof_error_is_typed() -> None:
    assert issubclass(ReferenceProofError, RuntimeError)
