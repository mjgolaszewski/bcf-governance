from __future__ import annotations

import hashlib
import copy
import json
from pathlib import Path
import subprocess
import sys
import venv
import zipfile
import yaml

import pytest

from bcf_governance.tooling import local_pr
from bcf_governance.tooling import ci_commands
from bcf_governance.tooling import release_adopter_qualification as qualification
from bcf_governance.tooling.ci_github_values import GitHubValueError, remote_repository
from bcf_governance.tooling.local_pr_context import LocalValidationLane
from bcf_governance.tooling.release_adopter_qualification import (
    ReleaseQualificationError,
    _exact_release_runtime,
    _release_assets,
    _isolated_project_python,
    load_contract,
    qualify_release,
    validate_qualification_receipt,
)
from bcf_governance.tooling.release_adopter_sources import (
    AdopterSourceError,
    AdopterSourceIdentity,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCER = {
    "kind": "local",
    "id": "bcf-release-compatibility",
}


@pytest.fixture
def qualification_provider(monkeypatch):
    from bcf_governance.tooling.ci_github_api import GitHubAPI
    from bcf_governance.tooling.ci_github_errors import GitHubAPIError

    required = load_contract(REPO_ROOT)['required_adopters']
    population = {item['repository']: index for index, item in enumerate(required, 1)}
    observed = {'calls': [], 'move': None, 'repositories': {}}

    def request(_self, method, path, **_kwargs):
        assert method == 'GET'
        observed['calls'].append(path)
        repository = '/'.join(path.split('/')[2:4])
        index = population[repository]
        if '/git/' not in path:
            observed['repositories'][repository] = observed['repositories'].get(repository, 0) + 1
        moved = observed['repositories'].get(repository, 0) > 1
        mutation = observed['move'] if moved else None
        if mutation == 'unavailable':
            raise GitHubAPIError('provider unavailable at collection')
        sha = 'f' * 40 if mutation == 'commit' else str(index) * 40
        branch = 'other' if mutation == 'branch' else 'main'
        if '/git/ref/' in path:
            return {'ref': 'refs/heads/' + branch, 'object': {'type': 'commit', 'sha': sha}}
        if '/git/commits/' in path:
            return {'sha': sha, 'tree': {'sha': 'e' * 40 if mutation == 'tree' else str(index) * 40}}
        return {'id': index + 1000 if mutation == 'id' else index, 'default_branch': branch}

    monkeypatch.setenv('GITHUB_TOKEN', 'test-only')
    monkeypatch.setattr(GitHubAPI, '_request', request)
    return observed


def test_qualification_cli_derives_local_nonauthoritative_producer_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def qualify(*_args: object, **kwargs: object) -> dict[str, str]:
        observed.update(kwargs)
        return {"status": "pass"}

    monkeypatch.setattr(ci_commands, "qualify_release", qualify)
    ci_commands.main([
        "qualify-release", "--repo-root", str(tmp_path),
        "--repository", "owner/repo",
        "--release-assets", str(tmp_path / "assets"),
        "--release-build-manifest", str(tmp_path / "build.json"),
        "--output", str(tmp_path / "receipt.json"),
    ])
    assert observed["producer"] == PRODUCER


def test_qualification_cli_ignores_ambient_provider_workflow_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "attacker/workflow.yml@main")
    monkeypatch.setattr(
        ci_commands, "qualify_release",
        lambda *_args, **kwargs: observed.update(kwargs) or {"status": "pass"},
    )
    ci_commands.main([
        "qualify-release", "--repo-root", str(tmp_path),
        "--repository", "owner/repo",
        "--release-assets", str(tmp_path / "assets"),
        "--release-build-manifest", str(tmp_path / "build.json"),
        "--output", str(tmp_path / "receipt.json"),
    ])
    assert observed["producer"] == PRODUCER


def _installed_distribution(name, version, root, *, requires=(), extras=(), metadata_name=None):
    from email.message import Message
    from types import SimpleNamespace
    info=Message(); info['Metadata-Version']='2.1'; info['Name']=name if metadata_name is None else metadata_name; info['Version']=version
    for extra in extras:info['Provides-Extra']=extra
    for required in requires:info['Requires-Dist']=required
    return SimpleNamespace(version=version,requires=requires,metadata=info,locate_file=lambda _:root)


def _metadata_wheel(path: Path) -> None:
    version = path.name.split('-')[1]
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(f'bcf_governance-{version}.dist-info/METADATA',
            f'Metadata-Version: 2.1\nName: bcf-governance\nVersion: {version}\n')


def _assets(root: Path) -> dict[str, str]:
    names = {
        "bcf_governance-2.2.1-py3-none-any.whl": b"wheel",
        "bcf_governance-2.2.1.tar.gz": b"sdist",
    }
    for name, data in names.items():
        _metadata_wheel(root / name) if name.endswith(".whl") else (root / name).write_bytes(data)
    digests = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
    (root / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items())),
        encoding="utf-8",
    )
    return digests


def _build_assets(root: Path, archives: dict[str, str]) -> dict[str, str]:
    return {
        **archives,
        "SHA256SUMS": hashlib.sha256((root / "SHA256SUMS").read_bytes()).hexdigest(),
    }


def _build_manifest(
    path: Path, assets: dict[str, str], *, commit: str, tree: str
) -> Path:
    path.write_text(
        json.dumps(
            {
                "subject": {"commit_sha": commit, "tree_sha": tree},
                "assets": assets,
            }
        ),
        encoding="utf-8",
    )
    return path


def _receipt(contract: dict[str, object], assets: dict[str, str]) -> dict[str, object]:
    adopters = []
    for index, item in enumerate(contract["required_adopters"]):  # type: ignore[index]
        identity = str(index + 1) * 40
        adopters.append(
            {
                "id": item["id"],
                "repository": item["repository"],
                "repository_id": str(index + 100),
                "profile": item["profile"],
                "source_branch": "main",
                "source_commit": identity,
                "source_tree": identity,
                "candidate_commit": identity,
                "candidate_tree": identity,
                "evaluation": {"intent": "pr", "target": None},
                "status": "pass",
            }
        )
    return {
        "schema_version": "1.1",
        "kind": "release_adopter_qualification",
        "authority": False,
        "subject": {
            "repository": "owner/repo",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
        },
        "release": {"version": "2.2.1", "assets": dict(sorted(assets.items()))},
        "contract_sha256": "c" * 64,
        "source_inventory_sha256": qualification.source_inventory_sha256(
            [
                AdopterSourceIdentity(
                    id=item["id"],
                    repository=item["repository"],
                    repository_id=str(index + 100),
                    profile=item["profile"],
                    default_branch="main",
                    commit_sha=str(index + 1) * 40,
                    tree_sha=str(index + 1) * 40,
                )
                for index, item in enumerate(
                    contract["required_adopters"]  # type: ignore[index]
                )
            ]
        ),
        "producer": PRODUCER,
        "adopters": adopters,
        "status": "pass",
        "publication_authority": False,
    }


def test_release_qualification_contract_is_closed_and_unique() -> None:
    contract = load_contract(REPO_ROOT)

    assert [item["id"] for item in contract["required_adopters"]] == [
        "tradeflow-lite",
        "racecar-standard-v3",
        "agentbus-standard-v3",
    ]
    assert "provider_credentials" not in contract
    assert all("provider_credential" not in item for item in contract["required_adopters"])
    assert contract["qualification"] == {
        "source": "provider_default_branch_transaction",
        "caller_checkout_role": "materialization_resource_only",
        "mutation_scope": "disposable_clone_only",
        "fixed_point": "required",
        "evaluation_scope": "canonical_graph_derived",
        "authority": "local_non_authoritative",
        "execution_provenance": "local_observation_receipt",
        "continuation": "compatibility_report_only",
        "source_freshness": "provider_exact_at_capture_and_collection",
        "product_failure": "typed_remediation_input_no_publication_effect",
        "release_asset_identity": "exact_sha256sums",
    }


def test_historical_source_policy_decodes_but_cannot_authorize_new_execution():
    contract = copy.deepcopy(load_contract(REPO_ROOT))
    contract['schema_version'] = '1.3'
    contract['document']['version'] = '1.3.0'
    contract['qualification'].update(
        source='explicit_pinned_local_clone_transaction',
        caller_checkout_role='exact_source_identity',
        source_freshness='exact_at_observation',
    )
    decoded = qualification.parse_contract(
        yaml.safe_dump(contract).encode(),
        (REPO_ROOT / 'schemas/release-qualification.schema.json').read_bytes(),
    )
    assert decoded == contract
    with pytest.raises(AdopterSourceError, match='source policy'):
        qualification.require_provider_source_policy(decoded)


@pytest.mark.parametrize('field', ['source', 'caller_checkout_role', 'source_freshness'])
def test_provider_source_policy_cannot_mix_legacy_selection_fields(field):
    contract = copy.deepcopy(load_contract(REPO_ROOT))
    legacy = {'source': 'explicit_pinned_local_clone_transaction',
              'caller_checkout_role': 'exact_source_identity',
              'source_freshness': 'exact_at_observation'}
    contract['qualification'][field] = legacy[field]
    with pytest.raises(ReleaseQualificationError, match='contract is invalid'):
        qualification.parse_contract(
            yaml.safe_dump(contract).encode(),
            (REPO_ROOT / 'schemas/release-qualification.schema.json').read_bytes(),
        )


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

    assert _release_assets(tmp_path) == (
        "2.2.1",
        dict(sorted(_build_assets(tmp_path, expected).items())),
        dict(sorted(expected.items())),
    )
    (tmp_path / "bcf_governance-2.2.1.tar.gz").write_bytes(b"changed")
    with pytest.raises(ReleaseQualificationError, match="checksum inventory is not exact"):
        _release_assets(tmp_path)


def test_archive_projection_cannot_replace_complete_build_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('GITHUB_TOKEN', 'test-only')
    assets = tmp_path / "assets"
    assets.mkdir()
    archive_digests = _assets(assets)
    release_commit = "a" * 40
    release_tree = "b" * 40
    manifest = _build_manifest(
        tmp_path / "release-build-manifest.json",
        archive_digests,
        commit=release_commit,
        tree=release_tree,
    )

    with pytest.raises(
        ReleaseQualificationError,
        match="release assets are not bound to the current exact build manifest",
    ):
        qualify_release(
            REPO_ROOT,
            repository="mjgolaszewski/bcf-governance",
            release_assets=assets,
            release_build_manifest=manifest,
            adopter_roots=(),
            adopter_pythons={},
            producer=PRODUCER,
            output=tmp_path / "receipt.json",
        )


def test_exact_release_runtime_projects_wheel_over_admitted_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "bcf_governance-2.2.1-py3-none-any.whl"
    _metadata_wheel(wheel)
    controller = tmp_path / "controller"
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def run(
        argv: list[str] | tuple[str, ...], *, cwd: Path,
        env: dict[str, str] | None = None,
    ) -> str:
        del cwd
        calls.append((list(argv), env))
        if len(argv) == 4 and list(argv)[1:3] == ["-P", "-c"]:
            return json.dumps({
                "distribution_root": str(controller),
                "executable": str(controller / "bin/python"),
                "module_file": str(controller / "bcf_governance/__init__.py"),
                "requirements": [
                    {
                        "installed": "6.0.2",
                        "name": "PyYAML",
                        "required": ">=6.0,<7",
                        "satisfied": True,
                    }
                ],
                "version": "2.2.1",
            })
        return ""

    monkeypatch.setattr(qualification, "_run", run)
    command, environment = _exact_release_runtime(
        wheel,
        controller,
        version="2.2.1",
        cwd=tmp_path,
        environment={"GITHUB_TOKEN": "observation-only", "PYTHONPATH": "ambient"},
    )

    assert calls[0][0] == [
        sys.executable, "-m", "venv", str(controller),
    ]
    assert calls[1][0] == [
        str(controller / "bin/python"), "-m", "pip", "install",
        "--disable-pip-version-check", "--no-deps", "--force-reinstall", str(wheel),
    ]
    assert command == (
        str(controller / "bin/python"), "-P", "-c",
        "from bcf_governance.cli import main; main()",
    )
    assert "PYTHONPATH" not in environment
    admitted = (
        controller / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages/bcf-admitted-runtime.pth"
    ).read_text(encoding="utf-8").splitlines()
    assert admitted
    assert all(Path(value).is_absolute() for value in admitted)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"module_file": "/ambient/bcf_governance/__init__.py"}, "shadowed"),
        ({"requirements": [{"installed": None, "name": "PyYAML", "required": ">=6", "satisfied": False}]}, "dependencies"),
        ({"version": "2.2.0"}, "dependencies"),
    ],
)
def test_exact_release_runtime_rejects_shadowing_or_incompatible_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: dict[str, object],
    message: str,
) -> None:
    wheel = tmp_path / "bcf_governance-2.2.1-py3-none-any.whl"
    _metadata_wheel(wheel)
    controller = tmp_path / "controller"
    observation: dict[str, object] = {
        "distribution_root": str(controller),
        "executable": str(controller / "bin/python"),
        "module_file": str(controller / "bcf_governance/__init__.py"),
        "requirements": [],
        "version": "2.2.1",
    }
    observation.update(mutation)

    monkeypatch.setattr(
        qualification,
        "_run",
        lambda argv, **_kwargs: json.dumps(observation)
        if len(argv) == 4 and list(argv)[1:3] == ["-P", "-c"] else "",
    )

    with pytest.raises(ReleaseQualificationError, match=message):
        _exact_release_runtime(
            wheel,
            controller,
            version="2.2.1",
            cwd=tmp_path,
            environment={},
        )


def test_missing_adopter_matrix_fails_before_environment_or_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    digests = _assets(assets)
    release_commit = "a" * 40
    release_tree = "b" * 40
    manifest = _build_manifest(
        tmp_path / "release-build-manifest.json",
        _build_assets(assets, digests),
        commit=release_commit,
        tree=release_tree,
    )
    monkeypatch.setenv("GITHUB_TOKEN", "observation-only")
    monkeypatch.setattr(
        qualification,
        "_source_identity",
        lambda _root: ("mjgolaszewski/bcf-governance", release_commit, release_tree),
    )
    with pytest.raises(
        ReleaseQualificationError,
        match="exact pinned adopter clone inventory differs from the contract",
    ):
        qualify_release(
            REPO_ROOT,
            repository="mjgolaszewski/bcf-governance",
            release_assets=assets,
            release_build_manifest=manifest,
            adopter_roots=(),
            adopter_pythons={},
            producer=PRODUCER,
            output=tmp_path / "receipt.json",
        )
    assert not (tmp_path / "receipt.json").exists()


@pytest.mark.parametrize('defect', ['profile', 'missing-profile', 'missing-python', 'nonexecutable-python', None])
def test_all_pinned_adopter_inputs_are_admitted_before_first_allocation(tmp_path, monkeypatch, defect, qualification_provider):
    contract = load_contract(REPO_ROOT)
    assets = tmp_path / 'assets'
    assets.mkdir()
    digests = _assets(assets)
    release = ('mjgolaszewski/bcf-governance', 'a' * 40, 'b' * 40)
    manifest = _build_manifest(tmp_path / 'build.json', _build_assets(assets, digests),
                               commit=release[1], tree=release[2])
    identities = {REPO_ROOT.resolve(): release}
    roots = []
    for index, item in enumerate(contract['required_adopters'], 1):
        root = tmp_path / item['id']
        root.mkdir()
        (root / 'governance-profile.yml').write_text(
            f"profile:\n  selected: {item['profile']}\n", encoding='utf-8',
        )
        identities[root.resolve()] = (item['repository'], str(index) * 40, str(index) * 40)
        roots.append(root)
    last = roots[-1]
    python = last / 'python'
    python.write_text('#!/bin/sh\n', encoding='utf-8')
    python.chmod(0o755)
    if defect == 'profile':
        (last / 'governance-profile.yml').write_text('profile: {selected: wrong}\n')
    elif defect == 'missing-profile':
        (last / 'governance-profile.yml').unlink()
    elif defect == 'missing-python':
        python.unlink()
    elif defect == 'nonexecutable-python':
        python.chmod(0o644)
    effects = []
    def allocation(**kwargs):
        effects.append('allocation')
        raise AssertionError('first allocation reached')
    monkeypatch.setattr(qualification, '_source_identity', lambda root: identities[root.resolve()])
    monkeypatch.setattr(qualification.tempfile, 'TemporaryDirectory', allocation)
    if defect is None:
        expected, message = AssertionError, 'first allocation reached'
    else:
        expected = ReleaseQualificationError
        message = 'profile' if 'profile' in defect else 'interpreter is unavailable'
    with pytest.raises(expected, match=message):
        qualify_release(REPO_ROOT, repository=release[0], release_assets=assets,
                        release_build_manifest=manifest, adopter_roots=roots,
                        adopter_pythons={contract['required_adopters'][-1]['repository']: python},
                        producer=PRODUCER, output=tmp_path / 'receipt.json')
    assert effects == (['allocation'] if defect is None else [])
    assert not (tmp_path / 'receipt.json').exists()


@pytest.mark.parametrize('defect', ['stale-commit', 'stale-tree', 'legacy-policy', 'missing-token',
                                  'wrong-repository', 'duplicate-resource', 'missing-resource'])
def test_provider_selection_rejects_resources_before_first_allocation(tmp_path, monkeypatch, defect):
    from bcf_governance.tooling.ci_github_api import GitHubAPI

    contract = copy.deepcopy(load_contract(REPO_ROOT))
    contract['schema_version'] = '1.4'
    contract['qualification'].update(
        source='provider_default_branch_transaction',
        caller_checkout_role='materialization_resource_only',
        source_freshness='provider_exact_at_capture_and_collection',
    )
    assets = tmp_path / 'assets'
    assets.mkdir()
    digests = _assets(assets)
    release = ('mjgolaszewski/bcf-governance', 'a' * 40, 'b' * 40)
    manifest = _build_manifest(tmp_path / 'build.json', _build_assets(assets, digests),
                               commit=release[1], tree=release[2])
    identities = {REPO_ROOT.resolve(): release}
    provider = {}
    roots = []
    for index, item in enumerate(contract['required_adopters'], 1):
        root = tmp_path / item['id']
        root.mkdir()
        (root / 'governance-profile.yml').write_text(f"profile: {{selected: {item['profile']}}}\n")
        identities[root.resolve()] = (item['repository'], str(index) * 40, str(index) * 40)
        provider[item['repository']] = (index, str(index) * 40)
        roots.append(root)
    effects = []
    reads = []

    def request(_self, method, path, **_kwargs):
        assert method == 'GET'
        reads.append(path)
        repository = '/'.join(path.split('/')[2:4])
        number, sha = provider[repository]
        if '/git/ref/' in path:
            return {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': sha}}
        if '/git/commits/' in path:
            return {'sha': sha, 'tree': {'sha': sha}}
        return {'id': number, 'default_branch': 'main'}

    def allocation(**_kwargs):
        effects.append('allocation')
        raise AssertionError('invalid source reached allocation')

    if defect == 'legacy-policy':
        contract['schema_version'] = '1.3'
    else:
        repo, commit, tree = identities[roots[-1].resolve()]
        identities[roots[-1].resolve()] = ('owner/unrelated' if defect == 'wrong-repository' else repo,
                                          'f' * 40 if defect == 'stale-commit' else commit,
                                          'e' * 40 if defect == 'stale-tree' else tree)
        if defect == 'duplicate-resource':
            roots.append(roots[0])
        elif defect == 'missing-resource':
            roots.pop()
    monkeypatch.setenv('GITHUB_TOKEN', 'test-only')
    if defect == 'missing-token':
        monkeypatch.delenv('GITHUB_TOKEN')
        def forbidden_asset_read(*_args):
            raise AssertionError('missing credential reached asset reads')
        monkeypatch.setattr(qualification, '_release_assets', forbidden_asset_read)
    monkeypatch.setattr(GitHubAPI, '_request', request)
    monkeypatch.setattr(qualification, 'load_contract', lambda _root: contract)
    monkeypatch.setattr(qualification, '_source_identity', lambda root: identities[root.resolve()])
    monkeypatch.setattr(qualification.tempfile, 'TemporaryDirectory', allocation)
    with pytest.raises(ReleaseQualificationError, match='source policy|provider source|token is required|inventory|duplicate'):
        qualify_release(REPO_ROOT, repository=release[0], release_assets=assets,
                        release_build_manifest=manifest, adopter_roots=roots,
                        adopter_pythons={}, producer=PRODUCER, output=tmp_path / 'receipt.json')
    assert effects == []
    assert not (tmp_path / 'receipt.json').exists()
    if defect in {'legacy-policy', 'missing-token', 'wrong-repository', 'duplicate-resource', 'missing-resource'}:
        assert reads == []


@pytest.mark.parametrize('source_movement', [None, 'id', 'branch', 'commit', 'tree', 'unavailable'])
def test_release_subject_identity_cannot_be_replaced_by_adopter_iteration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, qualification_provider, source_movement,
) -> None:
    contract = load_contract(REPO_ROOT)
    assets = tmp_path / "assets"
    assets.mkdir()
    digests = _assets(assets)
    release_identity = ("mjgolaszewski/bcf-governance", "a" * 40, "b" * 40)
    manifest = _build_manifest(
        tmp_path / "release-build-manifest.json",
        _build_assets(assets, digests),
        commit=release_identity[1],
        tree=release_identity[2],
    )
    identities = {REPO_ROOT.resolve(): release_identity}
    adopter_roots: list[Path] = []
    adopter_pythons: dict[str, Path] = {}
    profiles: dict[str, str] = {}
    source_trees: dict[str, str] = {}
    calls: list[list[str]] = []
    profile_checks: list[tuple[Path, str]] = []
    original_profile_check = qualification.require_adopter_profile
    environment_requests: list[Path | None] = []
    for index, item in enumerate(contract["required_adopters"], start=1):
        root = tmp_path / item["id"]
        root.mkdir()
        (root / 'governance-profile.yml').write_text(
            f"profile:\n  selected: {item['profile']}\n", encoding='utf-8',
        )
        python = root / ".venv/bin/python"
        python.parent.mkdir(parents=True)
        python.write_text("#!/bin/sh\n", encoding="utf-8")
        python.chmod(0o755)
        identity = str(index) * 40
        identities[root.resolve()] = (item["repository"], identity, identity)
        adopter_roots.append(root)
        if index != 2:
            adopter_pythons[item["repository"]] = python
        profiles[item["id"]] = item["profile"]
        source_trees[item["id"]] = identity

    def source_identity(root: Path) -> tuple[str, str, str]:
        return identities[root.resolve()]

    def run(
        argv: list[str], *, cwd: Path, env: object | None = None,
    ) -> str:
        calls.append(list(argv))
        if len(argv) == 4 and argv[1:3] == ["-P", "-c"]:
            controller = Path(argv[0]).parents[1]
            return json.dumps({
                "distribution_root": str(controller),
                "executable": str(controller / "bin/python"),
                "module_file": str(controller / "bcf_governance/__init__.py"),
                "requirements": [],
                "version": "2.2.1",
            })
        if len(argv) == 6 and argv[1:3] == ["-P", "-c"]:
            return json.dumps({
                "status": "prospectively_admissible_provider_proof_required",
                "subject": {"commit_sha": "c" * 40, "tree_sha": "d" * 40},
                "post_merge_evaluation": {"intent": "pr", "target": None},
            })
        if argv[:2] == ["git", "clone"]:
            destination = Path(argv[-1])
            destination.mkdir()
            (destination / "governance-profile.yml").write_text(
                f"profile:\n  selected: {profiles[destination.name]}\n",
                encoding="utf-8",
            )
            (destination / 'governance').mkdir()
            (destination / 'governance/gate-contracts.yml').write_text(
                "profile_contract_version: '2.0'\ngates:\n"
                "  test:\n    invocation: {argv: [python3, gate.py]}\n",
                encoding='utf-8',
            )
            (destination / 'requirements-governance.txt').write_text('pytest>=8\n', encoding='utf-8')
            (destination / 'governance/ci-graph.yml').write_text(
                "resource_classes: {candidate: {python_version: '3.12'}}\n", encoding='utf-8',
            )
        if argv[4:5] == ['install']:
            from bcf_governance.tooling.governance_install.upgrade import _upgrade_interpreter_contract
            from bcf_governance.tooling.interpreter_environment import derive_interpreter_environment
            assert derive_interpreter_environment(cwd) is None
            assert _upgrade_interpreter_contract(cwd) == [cwd / 'governance/gate-contracts.yml']
        if argv[:3] == ["git", "remote", "get-url"]:
            repository = identities[cwd.resolve()][0]
            return f"https://github.com/{repository}.git"
        if argv[:3] == ["git", "rev-parse", "HEAD^{tree}"]:
            return source_trees[cwd.name]
        if "prospective-train" in argv:
            return json.dumps({
                "status": "prospectively_admissible_provider_proof_required",
                "subject": {"commit_sha": "c" * 40, "tree_sha": "d" * 40},
                "post_merge_evaluation": {"intent": "pr", "target": None},
            })
        return ""

    monkeypatch.setenv("GITHUB_TOKEN", "observation-only")
    def check_profile(root, source):
        original_profile_check(root, source)
        profile_checks.append((root, source.id))
    monkeypatch.setattr(qualification, "require_adopter_profile", check_profile)
    monkeypatch.setattr(qualification, "_source_identity", source_identity)
    monkeypatch.setattr(qualification, "_run", run)
    monkeypatch.setattr(
        qualification, "_isolated_project_python",
        lambda _source, source_python, _destination, _environment: source_python,
    )
    def ensure_project_python(root, controller, requested=None):
        from bcf_governance.tooling.interpreter_environment import derive_interpreter_environment
        assert derive_interpreter_environment(root) is not None, 'canonical install must precede environment derivation'
        environment_requests.append(requested)
        return requested or root / '.venv/bin/python'
    monkeypatch.setattr(qualification, "ensure_local_project_python", ensure_project_python)
    monkeypatch.setattr(qualification, "_commit", lambda *_args, **_kwargs: None)

    qualification_provider['move'] = source_movement
    def execute():
        return qualify_release(
            REPO_ROOT,
            repository=release_identity[0],
            release_assets=assets,
            release_build_manifest=manifest,
            adopter_roots=tuple(reversed(adopter_roots)),
            adopter_pythons=adopter_pythons,
            producer=PRODUCER,
            output=tmp_path / "receipt.json",
        )
    if source_movement is not None:
        with pytest.raises(ReleaseQualificationError, match='stale|unavailable'):
            execute()
        assert not (tmp_path / 'receipt.json').exists()
        assert len(environment_requests) == len(contract['required_adopters'])
        return
    receipt = execute()
    assert len(qualification_provider['calls']) == 6 * len(contract['required_adopters'])
    assert all(item['repository_id'] == str(index) and item['source_branch'] == 'main'
               for index, item in enumerate(receipt['adopters'], 1))

    ids = [item['id'] for item in contract['required_adopters']]
    assert [identifier for _, identifier in profile_checks] == ids + ids
    assert len(environment_requests) == len(ids)
    assert sum(value is None for value in environment_requests) == 1
    assert all(root == tmp_path / identifier for root, identifier in profile_checks[:len(ids)])
    assert all(root != tmp_path / identifier for root, identifier in profile_checks[len(ids):])
    assert receipt["subject"] == {
        "repository": release_identity[0],
        "commit_sha": release_identity[1],
        "tree_sha": release_identity[2],
    }
    assert {
        item["repository"]: (item["source_commit"], item["source_tree"])
        for item in receipt["adopters"]
    } == {
        str(item["repository"]): identities[
            (tmp_path / str(item["id"])).resolve()
        ][1:]
        for item in contract["required_adopters"]
    }
    install_calls = [call for call in calls if call[4:5] == ["install"]]
    assert len(install_calls) == len(contract["required_adopters"])
    assert all(
        "--candidate-qualification-source" in call
        and call[call.index("--candidate-qualification-source") + 1]
        == str(REPO_ROOT.resolve())
        and "--release-assets" not in call
        for call in install_calls
    )
    qualification_calls = [
        call for call in calls if len(call) == 6 and call[1:3] == ["-P", "-c"]
    ]
    assert len(qualification_calls) == len(contract["required_adopters"])
    assert all("prospective-train" not in call for call in calls)


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
        source,
        environment / "bin/python",
        destination,
        tmp_path / "qualification-environment",
    )

    assert projected == tmp_path / "qualification-environment/bin/python"
    assert not (destination / ".bcf-qualification-venv").exists()
    projected_hook = (
        tmp_path / "qualification-environment/lib" / version
        / "site-packages/project.pth"
    )
    assert projected_hook.read_text(encoding="utf-8") == str(destination / "src") + "\n"


def test_nested_repository_environment_is_copied_from_its_interpreter_root(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "candidate"
    source.mkdir()
    destination.mkdir()
    environment = source / ".artifacts/runtime/execution-state/session/project-environments/exact/venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    hook = environment / "lib" / version / "site-packages" / "project.pth"
    hook.write_text(str(source / "src") + "\n", encoding="utf-8")

    projected = _isolated_project_python(
        source,
        environment / "bin/python",
        destination,
        tmp_path / "qualification-environment",
    )

    assert projected == tmp_path / "qualification-environment/bin/python"
    assert projected.is_file()
    projected_hook = (
        tmp_path / "qualification-environment/lib" / version
        / "site-packages/project.pth"
    )
    assert projected_hook.read_text(encoding="utf-8") == str(destination / "src") + "\n"
    assert not (tmp_path / "qualification-environment/runtime").exists()


def test_external_virtual_environment_preserves_lexical_package_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    external = tmp_path / "external/.venv/bin/python"
    source.mkdir()
    destination.mkdir()
    external.parent.mkdir(parents=True)
    external.symlink_to(sys.executable)
    observed: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.append(argv)
        return subprocess.CompletedProcess(argv, 0, '["/isolated/site-packages"]\n', "")

    monkeypatch.setattr(qualification.subprocess, "run", run)

    selected = _isolated_project_python(
        source, external, destination, tmp_path / "unused-copy"
    )

    assert selected == external.absolute()
    assert observed[0][0] == str(external.absolute())


def test_candidate_qualification_derives_the_closed_observation_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bcf_governance.tooling import prospective_candidate_identity

    captured: dict[str, object] = {}
    monkeypatch.setattr(
        prospective_candidate_identity,
        "canonical_prospective_inputs",
        lambda _root, **_kwargs: {
            "semantic_intent": "pr",
            "evaluation_target": None,
            "subject_commit": "a" * 40,
            "subject_tree": "b" * 40,
        },
    )

    def run(_root: Path, **kwargs: object) -> dict[str, str]:
        captured.update(kwargs)
        return {"status": "prospectively_admissible_provider_proof_required"}

    monkeypatch.setattr(local_pr, "run_prospective_train", run)

    result = qualification.run_candidate_qualification_train(
        tmp_path, Path(sys.executable)
    )

    assert result["status"] == "prospectively_admissible_provider_proof_required"
    assert (
        captured["validation_lane"]
        is LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION
    )
    assert captured["semantic_intent"] == "pr"
    assert captured["evaluation_target"] is None
    assert captured["remote"] == "bcf-qualification-base"


def test_qualification_base_remote_is_immutable_at_captured_adopter_subject(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=candidate, check=True)
    subprocess.run(["git", "config", "user.name", "BCF Fixture"], cwd=candidate, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=candidate, check=True)
    (candidate / "README.md").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=candidate, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "base"], cwd=candidate, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=candidate, capture_output=True,
        text=True, check=True,
    ).stdout.strip()

    qualification._project_qualification_base_remote(
        candidate, tmp_path / "qualification-base.git", commit
    )
    observed = subprocess.run(
        ["git", "ls-remote", "bcf-qualification-base", "HEAD"],
        cwd=candidate, capture_output=True, text=True, check=True,
    ).stdout.split()[0]

    assert observed == commit


@pytest.mark.parametrize('source_policy', ['1.3', '1.4'])
def test_qualification_receipt_requires_exact_subject_assets_and_adopters(
    tmp_path: Path, source_policy,
) -> None:
    contract = load_contract(REPO_ROOT)
    if source_policy == '1.3':
        contract = copy.deepcopy(contract)
        contract['schema_version'] = '1.3'
        contract['document']['version'] = '1.3.0'
        contract['qualification'].update(
            source='explicit_pinned_local_clone_transaction',
            caller_checkout_role='exact_source_identity',
            source_freshness='exact_at_observation',
        )
    assets = _assets(tmp_path)
    receipt = _receipt(contract, assets)
    kwargs = {
        "contract": contract,
        "contract_sha256": "c" * 64,
        "repository": "owner/repo",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "version": "2.2.1",
        "assets": assets,
        "producer": PRODUCER,
    }

    assert validate_qualification_receipt(receipt, **kwargs) == receipt
    mutations = []
    for key, value in (
        ("authority", True),
        ("publication_authority", True),
        ("status", "failed"),
    ):
        mutation = copy.deepcopy(receipt)
        mutation[key] = value
        mutations.append(mutation)
    missing = copy.deepcopy(receipt)
    missing["adopters"].pop()  # type: ignore[union-attr]
    mutations.append(missing)
    wrong = copy.deepcopy(receipt)
    wrong["adopters"][0]["repository"] = "owner/unrelated"  # type: ignore[index]
    mutations.append(wrong)
    for mutation in mutations:
        with pytest.raises(ReleaseQualificationError):
            validate_qualification_receipt(mutation, **kwargs)


@pytest.mark.parametrize('needed_version',['1.0','1.0-post1'])
@pytest.mark.parametrize('dependency_source',['headers','legacy'])
def test_nested_runtime_projects_actual_required_distribution_origins_before_allocation(tmp_path, monkeypatch, needed_version, dependency_source):
    import importlib.metadata as metadata
    from types import SimpleNamespace
    import zipfile
    wheel = tmp_path/'bcf_governance-2.5.0-py3-none-any.whl'
    with zipfile.ZipFile(wheel,'w') as archive:
        archive.writestr('bcf_governance-2.5.0.dist-info/METADATA',
            'Metadata-Version: 2.1\nName: bcf-governance\nVersion: 2.5.0\nRequires-Dist: needed[feature]>=1\n')
    immediate=tmp_path/'immediate'; immediate.mkdir()
    needed=tmp_path/'needed'; needed.mkdir()
    transitive=tmp_path/'transitive'; transitive.mkdir()
    monkeypatch.setattr(qualification.sysconfig,'get_paths',lambda:{'purelib':str(immediate)})
    def distribution(name):
        if name=='needed':
            result=_installed_distribution(name,needed_version,needed,requires=['child>=2; extra == "feature"','unrelated; python_version < "0"'],extras=['feature'])
            if dependency_source=='legacy':del result.metadata['Requires-Dist']
            return result
        if name=='child':return _installed_distribution(name,'2.0',transitive,requires=['needed[feature]>=1'])
        if name=='packaging':return _installed_distribution(name,'26.0',immediate)
        pytest.fail('unrelated distribution queried: '+name)
    monkeypatch.setattr(metadata,'distribution',distribution)
    controller=tmp_path/'controller'; calls=[]
    def run(argv, **_kwargs):
        calls.append(list(argv))
        if list(argv)[1:3]==['-P','-c']:
            return json.dumps({'distribution_root':str(controller),'executable':str(controller/'bin/python'),
                'module_file':str(controller/'bcf_governance/__init__.py'),'requirements':[],'version':'2.5.0'})
        return ''
    monkeypatch.setattr(qualification,'_run',run)
    _exact_release_runtime(wheel,controller,version='2.5.0',cwd=tmp_path,environment={})
    projected=(controller/'lib'/f'python{sys.version_info.major}.{sys.version_info.minor}'/'site-packages/bcf-admitted-runtime.pth').read_text().splitlines()
    assert projected==sorted(map(str,[immediate,needed,transitive]))


@pytest.mark.parametrize('defect',['missing','version','unsafe-root','direct-url','identity','ambiguous','invalid-requirement','unknown-extra','distribution-identity','malformed-headers','wheel-python','dependency-python'])
def test_required_dependency_origins_reject_before_runtime_allocation(tmp_path,monkeypatch,defect):
    from types import SimpleNamespace
    wheel=tmp_path/'bcf_governance-2.5.0-py3-none-any.whl'
    required='needed>=1'
    if defect=='unknown-extra':required='needed[unknown]>=1'
    if defect=='direct-url':required='needed @ https://example.invalid/needed.whl'
    if defect=='invalid-requirement':required='not a requirement @@@'
    with zipfile.ZipFile(wheel,'w') as archive:
        archive.writestr('bcf_governance-2.5.0.dist-info/METADATA',
            'Metadata-Version: 2.1\nName: '+('other' if defect=='identity' else 'bcf-governance')+
            '\nVersion: 2.5.0\n'+('Requires-Python: >=1000\n' if defect=='wheel-python' else '')+('bad header\n' if defect=='malformed-headers' else '')+'Requires-Dist: '+required+'\n')
        if defect=='ambiguous':archive.writestr('other.dist-info/METADATA','Name: other\nVersion: 2.5.0\n')
    origin=tmp_path/('unsafe\nroot' if defect=='unsafe-root' else 'dependencies');origin.mkdir()
    def distribution(name):
        if defect=='missing' and name=='needed':raise qualification.metadata.PackageNotFoundError(name)
        observed = _installed_distribution(name,'0.5' if defect=='version' and name=='needed' else '26.0',origin,
            metadata_name='other' if defect=='distribution-identity' else name)
        if defect=='dependency-python':observed.metadata['Requires-Python']='>=1000'
        return observed
    monkeypatch.setattr(qualification.metadata,'distribution',distribution)
    monkeypatch.setattr(qualification,'_run',lambda *_a,**_k:pytest.fail('invalid origins allocated runtime'))
    with pytest.raises(ReleaseQualificationError,match='dependency origins are invalid'):
        _exact_release_runtime(wheel,tmp_path/'controller',version='2.5.0',cwd=tmp_path,environment={})
    assert not (tmp_path/'controller').exists()
