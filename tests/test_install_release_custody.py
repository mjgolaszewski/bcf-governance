from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from types import SimpleNamespace
from urllib.request import Request
import zipfile

import pytest
import yaml

from bcf_governance import __version__
from bcf_governance.tooling.governance_install import release_custody
from bcf_governance.tooling.governance_install.runtime_custody import (
    RuntimeCustodyState,
    inspect_runtime_custody,
)
from bcf_governance.tooling.governance_install import cli as install_cli
from bcf_governance.tooling.governance_install.upgrade import (
    _upgrade_direct_comparison_input,
)
from bcf_governance.tooling.release_asset_inventory import exact_assets


REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = REPO_ROOT / "bcf_governance/pack/template-repo"
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
PREDECESSOR_COMMIT = "deedeced7a30858eba720eaaee0160a2383fc807"


def _install_exact_predecessor(target: Path, source_root: Path) -> None:
    archive = subprocess.run(
        ["git", "archive", "--format=tar", PREDECESSOR_COMMIT],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    ).stdout
    source_root.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as packaged:
        packaged.extractall(source_root, filter="data")
    target.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=target, check=True)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(source_root)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "bcf_governance.cli",
            "install",
            "--target",
            str(target),
            "--profile",
            "lite",
            "--project-id",
            "predecessor-fixture",
            "--project-name",
            "Predecessor Fixture",
            "--date",
            "2026-09-29",
            "--skip-validation",
        ],
        cwd=source_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(["git", "add", "-A"], cwd=target, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=BCF Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "install exact BCF 2.1.3 predecessor",
        ],
        cwd=target,
        check=True,
    )


def _release_assets(root: Path) -> tuple[Path, dict[str, str]]:
    root.mkdir()
    wheel = root / f"bcf_governance-{__version__}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in sorted(TEMPLATE_ROOT.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                relative = path.relative_to(TEMPLATE_ROOT).as_posix()
                archive.writestr(
                    f"bcf_governance/pack/template-repo/{relative}", path.read_bytes()
                )
    sdist = root / f"bcf_governance-{__version__}.tar.gz"
    sdist.write_bytes(b"exact source archive fixture")
    sums = root / "SHA256SUMS"
    sums.write_text(
        "\n".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
            for path in (wheel, sdist)
        )
        + "\n",
        encoding="utf-8",
    )
    return root, exact_assets(root.iterdir())


class _Provider:
    def __init__(self, assets: dict[str, str]) -> None:
        self.assets = assets

    def repository(self, repository: str) -> dict[str, object]:
        return {"id": 1207503211, "full_name": repository}

    def immutable_releases(self, _repository: str) -> dict[str, object]:
        return {"enabled": True}

    def reference(self, _repository: str, ref: str) -> dict[str, object]:
        assert ref == f"tags/v{__version__}"
        return {"object": {"type": "tag", "sha": TAG_OBJECT}}

    def tag_object(self, _repository: str, sha: str) -> dict[str, object]:
        assert sha == TAG_OBJECT
        return {
            "tag": f"v{__version__}",
            "object": {"type": "commit", "sha": COMMIT},
            "verification": {"verified": False, "reason": "unsigned"},
        }

    def release_by_tag(self, repository: str, tag: str) -> dict[str, object]:
        return {
            "id": 99,
            "tag_name": tag,
            "immutable": True,
            "draft": False,
            "prerelease": False,
            "html_url": f"https://github.com/{repository}/releases/tag/{tag}",
            "assets": [
                {
                    "name": name,
                    "state": "uploaded",
                    "digest": f"sha256:{digest}",
                }
                for name, digest in self.assets.items()
            ],
        }

    def attestations(self, _repository: str, digest: str) -> tuple[dict[str, object], ...]:
        assert digest.startswith("sha256:")
        return ({"bundle": {}},)


def test_release_custody_authenticates_exact_assets_provider_and_pack(tmp_path: Path) -> None:
    assets_root, assets = _release_assets(tmp_path / "assets")

    custody = release_custody.prepare_release_custody(
        assets_root,
        installed_version=__version__,
        template_root=TEMPLATE_ROOT,
        token="",
        api=_Provider(assets),
    )

    assert custody.version == __version__
    assert custody.source_commit == COMMIT
    assert custody.release_id == 99
    assert custody.wheel_sha256 == assets[
        f"bcf_governance-{__version__}-py3-none-any.whl"
    ]
    assert "scripts/_bcf_runtime/install_governance_pack.py" in custody.released_template_files


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("asset", "local assets differ"),
        ("tag", "tag identity"),
        ("attestation", "lacks attestation"),
    ],
)
def test_release_custody_rejects_wrong_provider_bindings(
    tmp_path: Path, mutation: str, error: str
) -> None:
    assets_root, assets = _release_assets(tmp_path / "assets")
    provider = _Provider(assets)
    if mutation == "asset":
        provider.assets = {**assets, "SHA256SUMS": "f" * 64}
    elif mutation == "tag":
        provider.tag_object = lambda _repository, _sha: {  # type: ignore[method-assign]
            "tag": f"v{__version__}",
            "object": {"type": "commit", "sha": "invalid"},
            "verification": {"verified": False, "reason": "unsigned"},
        }
    else:
        provider.attestations = lambda _repository, _digest: ()  # type: ignore[method-assign]

    with pytest.raises(release_custody.ReleaseCustodyError, match=error):
        release_custody.prepare_release_custody(
            assets_root,
            installed_version=__version__,
            template_root=TEMPLATE_ROOT,
            token="",
            api=provider,
        )


def test_release_provider_exposes_get_only_exact_official_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[Request] = []

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"id":1207503211,"full_name":"mjgolaszewski/bcf-governance"}'

    def opened(request: Request, *, timeout: int) -> _Response:
        assert timeout == 30
        requests.append(request)
        return _Response()

    monkeypatch.setattr(release_custody, "open_download", opened)
    provider = release_custody.ReadOnlyReleaseProvider("token")

    assert provider.repository(release_custody.OFFICIAL_RELEASE_REPOSITORY)["id"] == 1207503211
    assert requests[0].method == "GET"
    assert requests[0].full_url == (
        "https://api.github.com/repos/mjgolaszewski/bcf-governance"
    )
    assert not any(
        hasattr(provider, name)
        for name in ("create_release", "publish_release", "upload_release_asset", "dispatch")
    )
    with pytest.raises(release_custody.ReleaseCustodyError, match="not official BCF"):
        provider.repository("other/repository")


def test_runtime_lock_is_derived_from_projected_bytes_and_validated(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    source = b"version = '{{PROJECT_ID}}'\n"
    installed = b"version = 'demo'\n"
    relative = "scripts/_bcf_runtime/example.py"
    path = target / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(installed)
    preserved_path = target / "schemas/consumer.schema.json"
    preserved_path.parent.mkdir(parents=True)
    preserved_path.write_text("{}\n", encoding="utf-8")
    preserved_digest = hashlib.sha256(preserved_path.read_bytes()).hexdigest()
    custody = release_custody.ReleaseCustody(
        version=__version__,
        source_commit=COMMIT,
        repository_id=1207503211,
        release_id=99,
        release_url=(
            f"https://github.com/mjgolaszewski/bcf-governance/releases/tag/v{__version__}"
        ),
        wheel_sha256="1" * 64,
        source_archive_sha256="2" * 64,
        checksum_manifest_sha256="3" * 64,
        released_template_files={relative: source},
    )

    release_custody.write_runtime_lock(
        target,
        custody=custody,
        manifest_entries={relative: {"installation_scope": "ordinary_adopter"}},
        upgrade_paths=("scripts/_bcf_runtime",),
        preserved={"schemas/consumer.schema.json": preserved_digest},
        placeholder_values={"PROJECT_ID": "demo"},
    )
    payload = release_custody.validate_installed_runtime_lock(
        target,
        expected_version=__version__,
        schema_path=REPO_ROOT / "schemas/bcf-runtime-lock.schema.json",
    )
    snapshot = inspect_runtime_custody(
        target,
        schema_path=REPO_ROOT / "schemas/bcf-runtime-lock.schema.json",
    )

    assert payload["files"] == {relative: hashlib.sha256(installed).hexdigest()}
    assert payload["preserved_consumer_files"] == {
        "schemas/consumer.schema.json": preserved_digest
    }
    assert snapshot.state is RuntimeCustodyState.NORMALIZED_EXACT
    assert snapshot.runtime_owned == payload["files"]
    assert snapshot.consumer_preserved == payload["preserved_consumer_files"]
    assert snapshot.deletion_authorized is False
    assert payload["official_installer_adaptations"][relative] == {
        "released_sha256": hashlib.sha256(source).hexdigest(),
        "installed_sha256": hashlib.sha256(installed).hexdigest(),
        "reason": "Canonical installer substitutes declared template values in the installed consumer runtime.",
    }

    path.write_text("drift\n", encoding="utf-8")
    with pytest.raises(release_custody.ReleaseCustodyError, match="byte mismatch"):
        release_custody.validate_installed_runtime_lock(
            target,
            expected_version=__version__,
            schema_path=REPO_ROOT / "schemas/bcf-runtime-lock.schema.json",
        )


def test_release_bound_upgrade_cannot_silently_preserve_stale_custody(
    tmp_path: Path,
) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=target, check=True)
    runtime = target / "scripts/_bcf_runtime/example.py"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("installed\n", encoding="utf-8")
    lock = target / "governance/bcf-runtime-lock.json"
    lock.parent.mkdir()
    lock.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "version": "2.1.3",
                "source_commit": PREDECESSOR_COMMIT,
                "release_id": 1,
                "release_url": "https://github.com/mjgolaszewski/bcf-governance/releases/tag/v2.1.3",
                "wheel_sha256": "a" * 64,
                "source_archive_sha256": "b" * 64,
                "checksum_manifest_sha256": "c" * 64,
                "official_installer_adaptations": {},
                "files": {
                    "scripts/_bcf_runtime/example.py": hashlib.sha256(
                        runtime.read_bytes()
                    ).hexdigest()
                },
                "preserved_consumer_files": {},
            }
        )
    )
    args = SimpleNamespace(
        target=target,
        release_assets=None,
        upgrade=True,
        reset_options=False,
    )

    from bcf_governance.tooling import install_governance_pack

    with pytest.raises(RuntimeError, match="reject_release_assets_required"):
        install_governance_pack.install(args)


def test_release_bound_adopter_can_enter_exact_nonauthoritative_candidate_qualification(
    tmp_path: Path,
) -> None:
    source = tmp_path / "candidate-source"
    source_manifest = source / "bcf_governance/pack/template-repo/.bcf-pack-manifest.json"
    source_manifest.parent.mkdir(parents=True)
    source_manifest.write_bytes((TEMPLATE_ROOT / ".bcf-pack-manifest.json").read_bytes())
    subprocess.run(["git", "init", "--quiet"], cwd=source, check=True)
    subprocess.run(["git", "add", "-A"], cwd=source, check=True)
    subprocess.run(
        ["git", "-c", "user.name=BCF Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "candidate"],
        cwd=source,
        check=True,
    )

    target = tmp_path / "adopter"
    target.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=target, check=True)
    relative = "scripts/_bcf_runtime/example.py"
    runtime = target / relative
    runtime.parent.mkdir(parents=True)
    runtime.write_text("candidate runtime\n", encoding="utf-8")
    _lock_payload = {
        "schema_version": "1.0",
        "version": __version__,
        "source_commit": "a" * 40,
        "release_id": 1,
        "release_url": f"https://github.com/mjgolaszewski/bcf-governance/releases/tag/v{__version__}",
        "wheel_sha256": "b" * 64,
        "source_archive_sha256": "c" * 64,
        "checksum_manifest_sha256": "d" * 64,
        "official_installer_adaptations": {},
        "files": {relative: hashlib.sha256(runtime.read_bytes()).hexdigest()},
        "preserved_consumer_files": {},
    }
    lock = target / "governance/bcf-runtime-lock.json"
    lock.parent.mkdir(parents=True)
    lock.write_text(json.dumps(_lock_payload) + "\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=target, check=True)
    subprocess.run(
        ["git", "-c", "user.name=BCF Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "adopter"],
        cwd=target,
        check=True,
    )

    prepared = release_custody.prepare_upgrade_release_custody(
        target,
        None,
        True,
        TEMPLATE_ROOT,
        candidate_qualification_source=source,
    )
    prepared.project(
        target,
        manifest_entries={relative: {"installation_scope": "ordinary_adopter"}},
        upgrade_paths=("scripts/_bcf_runtime",),
        placeholder_values={},
    )

    snapshot = inspect_runtime_custody(target, schema_path=REPO_ROOT / "schemas/bcf-runtime-lock.schema.json")
    assert snapshot.state is RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT
    assert snapshot.provenance_claim["non_authoritative"] is True
    assert not lock.exists()
    with pytest.raises(
        release_custody.ReleaseCustodyError,
        match="no immutable release authority",
    ):
        release_custody.validate_installed_runtime_lock(
            target,
            expected_version=__version__,
            schema_path=REPO_ROOT / "schemas/bcf-runtime-lock.schema.json",
        )


def test_upgrade_atomically_projects_release_custody_with_runtime_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "repo"
    _install_exact_predecessor(target, tmp_path / "bcf-2.1.3")
    lock_path = target / "governance/bcf-runtime-lock.json"
    assert not lock_path.exists()
    predecessor_runtime = target / "scripts/_bcf_runtime/_version.py"
    assert '"2.1.3"' in predecessor_runtime.read_text(encoding="utf-8")
    released = {
        path.relative_to(TEMPLATE_ROOT).as_posix(): path.read_bytes()
        for path in TEMPLATE_ROOT.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
        and path.name != ".bcf-pack-manifest.json"
    }
    custody = release_custody.ReleaseCustody(
        version=__version__,
        source_commit=COMMIT,
        repository_id=1207503211,
        release_id=99,
        release_url=(
            f"https://github.com/mjgolaszewski/bcf-governance/releases/tag/v{__version__}"
        ),
        wheel_sha256="1" * 64,
        source_archive_sha256="2" * 64,
        checksum_manifest_sha256="3" * 64,
        released_template_files=released,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.install_governance_pack.prepare_upgrade_release_custody",
        lambda *_args, **_kwargs: release_custody.UpgradeReleaseCustody(
            custody, {}
        ),
    )
    assets = tmp_path / "assets"
    assets.mkdir()

    install_cli.main(
        [
            "--target",
            str(target),
            "--upgrade",
            "--release-assets",
            str(assets),
            "--require-strict-validation",
        ]
    )

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock["version"] == __version__
    assert lock["source_commit"] == COMMIT
    assert lock["source_repository"] == release_custody.OFFICIAL_RELEASE_REPOSITORY
    runtime = "scripts/_bcf_runtime/install_governance_pack.py"
    assert lock["files"][runtime] == hashlib.sha256((target / runtime).read_bytes()).hexdigest()
    graph = yaml.safe_load((target / "governance/ci-graph.yml").read_text(encoding="utf-8"))
    call = next(
        event
        for event in graph["workflows"][0]["events"]
        if event["type"] == "workflow_call"
    )
    assert call["inputs"]["comparison_base_sha"] == {
        "description": "Exact repository comparison base for explicit calls",
        "required": True,
        "type": "string",
    }


def test_upgrade_rejects_malformed_existing_comparison_input(tmp_path: Path) -> None:
    graph = tmp_path / "governance/ci-graph.yml"
    graph.parent.mkdir(parents=True)
    graph.write_text(
        yaml.safe_dump(
            {
                "workflows": [
                    {
                        "id": "governance",
                        "role": "exact-main",
                        "events": [
                            {"type": "pull_request"},
                            {
                                "type": "workflow_call",
                                "inputs": {"comparison_base_sha": {"required": False}},
                            },
                            {"type": "push"},
                        ],
                    }
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="comparison-base input is malformed"):
        _upgrade_direct_comparison_input(tmp_path)


def test_authenticated_upgrade_normalizes_exact_legacy_overlap(
    tmp_path: Path,
) -> None:
    target = tmp_path / "repo"
    relative = "schemas/architecture-boundaries.schema.json"
    runtime_relative = "scripts/_bcf_runtime/_version.py"
    path = target / relative
    path.parent.mkdir(parents=True)
    path.write_bytes((TEMPLATE_ROOT / relative).read_bytes())
    runtime_path = target / runtime_relative
    runtime_path.parent.mkdir(parents=True)
    runtime_path.write_bytes((TEMPLATE_ROOT / runtime_relative).read_bytes())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lock = target / "governance/bcf-runtime-lock.json"
    lock.parent.mkdir(parents=True)
    lock.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "version": "2.1.4",
                "source_commit": "e" * 40,
                "release_id": 1,
                "release_url": "https://github.com/mjgolaszewski/bcf-governance/releases/tag/v2.1.4",
                "wheel_sha256": "1" * 64,
                "source_archive_sha256": "2" * 64,
                "checksum_manifest_sha256": "3" * 64,
                "official_installer_adaptations": {},
                "files": {relative: digest},
                "preserved_consumer_files": {relative: digest},
            }
        ),
        encoding="utf-8",
    )
    assets_root, assets = _release_assets(tmp_path / "assets")

    prepared = release_custody.prepare_upgrade_release_custody(
        target,
        assets_root,
        True,
        TEMPLATE_ROOT,
        api=_Provider(assets),
    )

    assert prepared.preserved == {relative: digest}
    prepared.project(
        target,
        manifest_entries={
            relative: {"installation_scope": "ordinary_adopter"},
            runtime_relative: {"installation_scope": "ordinary_adopter"},
        },
        upgrade_paths=("schemas", "scripts/_bcf_runtime"),
        placeholder_values={},
    )
    successor = inspect_runtime_custody(
        target,
        schema_path=REPO_ROOT / "schemas/bcf-runtime-lock.schema.json",
    )
    assert successor.state is RuntimeCustodyState.NORMALIZED_EXACT
    assert successor.runtime_owned == {
        runtime_relative: hashlib.sha256(runtime_path.read_bytes()).hexdigest()
    }
    assert successor.consumer_preserved == {relative: digest}


def test_upgrade_rolls_back_runtime_and_lock_when_custody_projection_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=target, check=True)
    install_cli.main(
        ["--target", str(target), "--profile", "lite", "--skip-validation"]
    )
    lock_path = target / "governance/bcf-runtime-lock.json"
    lock_path.write_text(
        json.dumps({"version": "2.1.3", "preserved_consumer_files": {}}),
        encoding="utf-8",
    )
    runtime_path = target / "scripts/_bcf_runtime/install_governance_pack.py"
    runtime_path.write_text("old runtime\n", encoding="utf-8")
    before = (runtime_path.read_bytes(), lock_path.read_bytes())
    custody = release_custody.UpgradeReleaseCustody(None, {})
    monkeypatch.setattr(
        "bcf_governance.tooling.install_governance_pack.prepare_upgrade_release_custody",
        lambda *_args, **_kwargs: custody,
    )

    def reject_projection(*_args: object, **_kwargs: object) -> None:
        raise release_custody.ReleaseCustodyError("projection rejected")

    monkeypatch.setattr(release_custody.UpgradeReleaseCustody, "project", reject_projection)
    assets = tmp_path / "assets"
    assets.mkdir()

    with pytest.raises(SystemExit):
        install_cli.main(
            [
                "--target",
                str(target),
                "--upgrade",
                "--release-assets",
                str(assets),
                "--skip-validation",
            ]
        )

    assert (runtime_path.read_bytes(), lock_path.read_bytes()) == before
