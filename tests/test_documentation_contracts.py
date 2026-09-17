from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO_ROOT / ".github/scripts/check_editorial_contract.py"


def _checker():
    spec = importlib.util.spec_from_file_location("editorial_contract", CHECKER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_editorial_contract_is_current_and_complete() -> None:
    assert _checker().validate_editorial_contract(REPO_ROOT) == []


def test_editorial_contract_command_runs_from_outside_repository(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(CHECKER_PATH)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "editorial-contract-ok"

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("# Fixture\n", encoding="utf-8")
    for args in (
        ("init",),
        ("config", "user.email", "editorial@example.test"),
        ("config", "user.name", "Editorial Test"),
        ("add", "."),
        ("commit", "-m", "fixture"),
    ):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    audit = repo / "audit.yml"
    command = [
        sys.executable,
        str(REPO_ROOT / ".github/scripts/build_editorial_audit.py"),
        "--repo-root",
        str(repo),
        "--audit",
        str(audit),
    ]
    subprocess.run(command + ["--base-sha", "HEAD", "--apply"], check=True)
    value = yaml.safe_load(audit.read_text(encoding="utf-8"))
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert value["base_commit"] == head

    value["base_commit"] = "HEAD"
    audit.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    rejected = subprocess.run(command + ["--check"], capture_output=True, text=True)
    assert rejected.returncode != 0
    assert "base_commit must be an immutable commit SHA" in rejected.stderr


def test_editorial_tone_and_topic_owner_mutants_are_rejected(tmp_path: Path) -> None:
    module = _checker()
    copied = tmp_path / "repo"
    # Copy the checker-owned topic inventory. The exact release audit owns the
    # complete human-facing population; this focused mutant needs only the
    # canonical and branch documents whose content it changes.
    for relative in (*module.CANONICAL_DOCUMENTS, *module.BRANCH_DOCUMENTS):
        source = REPO_ROOT / relative
        target = copied / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    version_source = copied / "bcf_governance/_version.py"
    version_source.parent.mkdir(parents=True, exist_ok=True)
    version_source.write_text('__version__ = "0.7.0"\n', encoding="utf-8")

    readme = copied / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            "## Design thesis", "## A revolutionary manifesto"
        ),
        encoding="utf-8",
    )
    errors = module.validate_editorial_contract(copied)
    assert any("missing heading: Design thesis" in error for error in errors)
    assert any("disallowed editorial phrase: manifesto" in error for error in errors)
    assert any("disallowed editorial phrase: revolutionary" in error for error in errors)

    readme.write_bytes((REPO_ROOT / "README.md").read_bytes())
    readme.write_text(
        readme.read_text(encoding="utf-8")
        .replace(
            "## What BCF establishes",
            "## Delivery comparison",
        )
        .replace(
            "cannot certify",
            "may certify",
            1,
        ),
        encoding="utf-8",
    )
    errors = module.validate_editorial_contract(copied)
    assert any("missing heading: What BCF establishes" in error for error in errors)
    assert any(
        "missing architectural position: an agent cannot certify its own output"
        in error
        for error in errors
    )

    readme.write_bytes((REPO_ROOT / "README.md").read_bytes())
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            f"releases/download/v{module.__version__}/bcf_governance-{module.__version__}-py3-none-any.whl",
            f"releases/download/v0.0.0/bcf_governance-{module.__version__}-py3-none-any.whl",
        ),
        encoding="utf-8",
    )
    errors = module.validate_editorial_contract(copied)
    assert any("release URL must point exactly" in error for error in errors)


def test_broken_local_documentation_link_is_rejected(tmp_path: Path) -> None:
    module = _checker()
    source = tmp_path / "README.md"
    source.write_text("# Demo\n\n[missing](docs/absent.md)\n", encoding="utf-8")
    errors = module._check_link(source, "docs/absent.md", tmp_path)
    assert errors and "missing link target" in errors[0]
