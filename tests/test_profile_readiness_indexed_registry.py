"""Profile readiness consumes the same closed registry as native ownership."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.profile_contract_v2 import (
    ProfileV2Error,
    validate_profile_v2_readiness,
)
from bcf_governance.tooling.semantic_ownership_deconstruct import deconstruct
from bcf_governance.tooling.semantic_ownership_registry import load_registry
from tests.test_profile_contract_v2 import _git, _profile_repo


def _indexed_consumer(tmp_path: Path) -> tuple[Path, Path]:
    repo = _profile_repo(tmp_path)
    before = load_registry(repo)
    flat = validate_profile_v2_readiness(repo, profile="standard")
    deconstruct(repo, apply=True)
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "deconstruct registry without changing declarations")
    indexed = load_registry(repo)
    assert indexed.raw == before.raw
    assert validate_profile_v2_readiness(repo, profile="standard") == flat
    assert flat.semantic_representations == len(indexed.entries) > 0
    root = yaml.safe_load((repo / "governance/canonical-representations.yml").read_text())
    assert "representations" not in root
    return repo, repo / root["representation_sources"][0]


def test_indexed_and_flat_readiness_have_identical_declared_population(tmp_path: Path) -> None:
    repo, _ = _indexed_consumer(tmp_path)
    probe = (
        "import sys; from pathlib import Path; "
        "root = Path(sys.argv[1]); sys.path.insert(0, str(root / 'scripts')); "
        "from _bcf_runtime.profile_contract_v2 import validate_profile_v2_readiness; "
        "report = validate_profile_v2_readiness(root, profile='standard'); "
        "assert report.semantic_representations == int(sys.argv[2]); "
        "assert 'bcf_governance' not in sys.modules"
    )
    subprocess.run(
        [sys.executable, "-I", "-c", probe, str(repo), str(len(load_registry(repo).entries))],
        cwd=tmp_path, check=True, capture_output=True, text=True,
    )


@pytest.mark.parametrize("fault", ["missing", "orphan", "duplicate", "empty"])
def test_profile_readiness_rejects_invalid_indexed_sources(tmp_path: Path, fault: str) -> None:
    repo, source = _indexed_consumer(tmp_path)
    if fault == "missing":
        source.unlink()
    elif fault == "orphan":
        source.with_name("undeclared.yml").write_bytes(source.read_bytes())
    elif fault == "duplicate":
        source.write_bytes(source.read_bytes() + b"document: {}\n")
    else:
        root = yaml.safe_load((repo / "governance/canonical-representations.yml").read_text())
        for relative in root["representation_sources"]:
            path = repo / relative
            document = yaml.safe_load(path.read_text())
            document["representations"] = []
            path.write_text(yaml.safe_dump(document, sort_keys=False))
    with pytest.raises(ProfileV2Error, match="semantic authority:"):
        validate_profile_v2_readiness(repo, profile="standard")
