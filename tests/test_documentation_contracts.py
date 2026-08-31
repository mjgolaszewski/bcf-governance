from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


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


def test_editorial_tone_and_topic_owner_mutants_are_rejected(tmp_path: Path) -> None:
    module = _checker()
    copied = tmp_path / "repo"
    for relative in module.EDITORIAL_DOCUMENTS:
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
            "## Why these defaults", "## A revolutionary manifesto"
        ),
        encoding="utf-8",
    )
    errors = module.validate_editorial_contract(copied)
    assert any("missing heading: Why these defaults" in error for error in errors)
    assert any("disallowed editorial phrase: manifesto" in error for error in errors)
    assert any("disallowed editorial phrase: revolutionary" in error for error in errors)


def test_broken_local_documentation_link_is_rejected(tmp_path: Path) -> None:
    module = _checker()
    source = tmp_path / "README.md"
    source.write_text("# Demo\n\n[missing](docs/absent.md)\n", encoding="utf-8")
    errors = module._check_link(source, "docs/absent.md", tmp_path)
    assert errors and "missing link target" in errors[0]
