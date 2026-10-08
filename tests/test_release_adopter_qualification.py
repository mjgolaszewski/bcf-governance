from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import venv

import pytest

from bcf_governance.tooling.ci_github_values import GitHubValueError, remote_repository
from bcf_governance.tooling.release_adopter_qualification import (
    ReleaseQualificationError,
    _release_assets,
    _isolated_project_python,
    load_contract,
    qualify_release,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _assets(root: Path) -> dict[str, str]:
    names = {
        "bcf_governance-2.2.1-py3-none-any.whl": b"wheel",
        "bcf_governance-2.2.1.tar.gz": b"sdist",
    }
    for name, data in names.items():
        (root / name).write_bytes(data)
    digests = {name: hashlib.sha256(data).hexdigest() for name, data in names.items()}
    (root / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items())),
        encoding="utf-8",
    )
    return digests


def test_release_qualification_contract_is_closed_and_unique() -> None:
    contract = load_contract(REPO_ROOT)

    assert [item["id"] for item in contract["required_adopters"]] == [
        "tradeflow-lite",
        "racecar-standard-v3",
        "agentbus-standard-v3",
    ]
    assert contract["qualification"] == {
        "source": "exact_clean_local_checkout",
        "mutation_scope": "disposable_clone_only",
        "fixed_point": "required",
        "evaluation_scope": "canonical_graph_derived",
        "authority": "local_non_authoritative",
        "product_failure": "blocks_custody_until_attributed",
        "release_asset_identity": "exact_sha256sums",
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("git@github.com:mjgolaszewski/racecar.git", "mjgolaszewski/racecar"),
        ("https://github.com/moranwm/tradeflow.git", "moranwm/tradeflow"),
        ("ssh://git@ssh.github.com/mjgolaszewski/AgentBus.git", "mjgolaszewski/AgentBus"),
    ],
)
def test_github_remote_identity_is_shared_by_submit_and_qualification(
    value: str, expected: str
) -> None:
    assert remote_repository(value) == expected


def test_non_github_or_ambiguous_remote_is_rejected() -> None:
    with pytest.raises(GitHubValueError):
        remote_repository("/docker/racecar")


def test_release_assets_require_exact_wheel_sdist_and_digests(tmp_path: Path) -> None:
    expected = _assets(tmp_path)

    assert _release_assets(tmp_path) == ("2.2.1", dict(sorted(expected.items())))
    (tmp_path / "bcf_governance-2.2.1.tar.gz").write_bytes(b"changed")
    with pytest.raises(ReleaseQualificationError, match="digest mismatch"):
        _release_assets(tmp_path)


def test_missing_adopter_matrix_fails_before_environment_or_mutation(
    tmp_path: Path,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    _assets(assets)

    with pytest.raises(
        ReleaseQualificationError,
        match="roots/interpreters do not exactly match",
    ):
        qualify_release(
            REPO_ROOT,
            release_assets=assets,
            adopter_roots=(),
            adopter_pythons={},
            output=tmp_path / "receipt.json",
        )
    assert not (tmp_path / "receipt.json").exists()


def test_repository_environment_is_copied_and_own_editable_path_is_rebound(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "candidate"
    source.mkdir()
    destination.mkdir()
    environment = source / ".venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    hook = environment / "lib" / version / "site-packages" / "project.pth"
    hook.write_text(str(source / "src") + "\n", encoding="utf-8")

    projected = _isolated_project_python(
        source, environment / "bin/python", destination
    )

    assert projected == destination / ".bcf-qualification-venv/bin/python"
    projected_hook = (
        destination / ".bcf-qualification-venv/lib" / version
        / "site-packages/project.pth"
    )
    assert projected_hook.read_text(encoding="utf-8") == str(destination / "src") + "\n"
