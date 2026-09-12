from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import shutil
import stat
from typing import Any
import zipfile

import pytest
import yaml

from bcf_governance.tooling.ci_graph_contracts import CIGraphError, validate_ci_graph
from bcf_governance.tooling.ci_graph_defaults import build_reference_ci_graph
from bcf_governance.tooling.ci_graph_render import render_ci_graph
from bcf_governance.tooling.ci_graph_yaml import render_yaml
from bcf_governance.tooling.ci_github_api import GitHubAPIError, GitHubContent
from bcf_governance.tooling.evidence_storage_archives import InputSpec
from bcf_governance.tooling.evidence_storage_contracts import (
    EvidenceStorageError,
    load_input_manifest,
    load_input_reference,
)
from bcf_governance.tooling.evidence_storage_github import (
    extract_handoff_zip,
    publish_input_bundle,
    provider_storage_usage,
    resolve_input_reference,
)
from bcf_governance.tooling.evidence_storage_manifests import (
    build_input_bundle,
    verify_input_bundle,
)
from bcf_governance.tooling.evidence_storage_retention import (
    apply_actions_retention,
    plan_retention,
)
from bcf_governance.tooling.governance_evidence import _install_durable_inputs


REPO_ROOT = Path(__file__).resolve().parents[1]
COMMIT = "1" * 40
TREE = "2" * 40


def _storage_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    (root / "governance").mkdir(parents=True)
    (root / "schemas").mkdir()
    for name in (
        "evidence-storage.schema.json",
        "evidence-input-manifest.schema.json",
        "evidence-input-reference.schema.json",
        "evidence-retention-snapshot.schema.json",
    ):
        shutil.copy2(REPO_ROOT / "schemas" / name, root / "schemas" / name)
    contract = yaml.safe_load((REPO_ROOT / "governance/evidence-storage.yml").read_text())
    contract["provider"]["repository"] = "owner/project"
    contract["provider"]["repository_id"] = 42
    (root / "governance/evidence-storage.yml").write_text(
        yaml.safe_dump(contract, sort_keys=False), encoding="utf-8"
    )
    workflow = root / ".github/workflows/source.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: source\non: workflow_dispatch\n", encoding="utf-8")
    return root


def _producer(root: Path, run_id: int) -> dict[str, Any]:
    workflow = root / ".github/workflows/source.yml"
    return {
        "kind": "workflow",
        "workflow_path": ".github/workflows/source.yml",
        "workflow_sha256": hashlib.sha256(workflow.read_bytes()).hexdigest(),
        "job_id": "prepare",
        "job_name": "Prepare durable inputs",
        "run_id": str(run_id),
        "run_attempt": 1,
    }


def _bundle(
    root: Path,
    output: Path,
    run_id: int,
    *,
    commit: str = COMMIT,
    tree: str = TREE,
) -> Path:
    return build_input_bundle(
        root,
        namespace="security-inputs",
        specs=[
            InputSpec(
                id="scanner",
                source_path="prepared/scanner.bin",
                target_path="resolved/scanner.bin",
                freshness_class="immutable",
                observed_at_utc=None,
            ),
            InputSpec(
                id="scanner-copy",
                source_path="prepared/scanner-copy.bin",
                target_path="resolved/scanner-copy.bin",
                freshness_class="immutable",
                observed_at_utc=None,
            ),
        ],
        output_dir=output,
        subject={"repository_id": 42, "commit_sha": commit, "tree_sha": tree},
        producer=_producer(root, run_id),
        created_at=datetime(2026, 9, 11, tzinfo=UTC),
    )


def _published_reference(
    root: Path, tmp_path: Path
) -> tuple[FakeEvidenceAPI, Path, Path]:
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"exact scanner bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"exact scanner bytes")
    api = FakeEvidenceAPI(root)
    manifest_path = _bundle(root, tmp_path / "bundle", 1)
    reference_path = root / ".artifacts/reference.json"
    publish_input_bundle(
        api,  # type: ignore[arg-type]
        schema_root=root,
        bundle_dir=manifest_path.parent,
        handoff={
            "artifact_id": 501,
            "artifact_name": "bcf-source-1-1",
            "provider_digest": "sha256:" + "0" * 64,
            "run_id": "1",
            "run_attempt": 1,
        },
        output_path=reference_path,
    )
    return api, manifest_path, reference_path


class FakeEvidenceAPI:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.releases: dict[str, dict[str, Any]] = {}
        self.assets: dict[int, bytes] = {}
        self.tags: dict[str, str] = {}
        self.next_release = 100
        self.next_asset = 1000
        self.current_commit = COMMIT
        self.current_tree = TREE

    def repository(self, repository: str) -> dict[str, Any]:
        assert repository == "owner/project"
        return {"id": 42}

    def run(self, repository: str, run_id: object) -> dict[str, Any]:
        return {
            "id": int(str(run_id)),
            "run_attempt": 1,
            "head_sha": self.current_commit,
            "workflow_id": 9,
            "repository": {"id": 42},
        }

    def workflow(self, repository: str, workflow_id: object) -> dict[str, Any]:
        assert workflow_id == 9
        return {"path": ".github/workflows/source.yml"}

    def commit(self, repository: str, sha: str) -> dict[str, Any]:
        return {"sha": self.current_commit, "tree": {"sha": self.current_tree}}

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        source = self.root / path
        return GitHubContent(path=path, blob_oid="3" * 40, content=source.read_bytes())

    def jobs(self, repository: str, run_id: int, *, attempt: int) -> tuple[dict[str, Any], ...]:
        return ({"name": "Prepare durable inputs", "conclusion": "success"},)

    def artifacts(self, repository: str, run_id: object) -> tuple[dict[str, Any], ...]:
        numeric = int(str(run_id))
        return (
            {
                "id": 500 + numeric,
                "name": f"bcf-source-{numeric}-1",
                "expired": False,
                "digest": "sha256:" + "0" * 64,
                "workflow_run": {"id": numeric},
            },
        )

    def immutable_releases(self, repository: str) -> dict[str, Any]:
        return {"enabled": True}

    def evidence_release_by_tag(self, repository: str, tag: str) -> dict[str, Any]:
        if tag not in self.releases:
            raise GitHubAPIError("GitHub API GET release returned 404")
        return self.releases[tag]

    def evidence_releases(self, repository: str) -> tuple[dict[str, Any], ...]:
        return tuple(self.releases.values())

    def create_evidence_draft_release(
        self, repository: str, *, tag: str, target_commit: str, body: str
    ) -> dict[str, Any]:
        release_id = self.next_release
        self.next_release += 1
        release = {
            "id": release_id,
            "tag_name": tag,
            "draft": True,
            "immutable": False,
            "prerelease": True,
            "upload_url": f"https://uploads.github.com/repos/owner/project/releases/{release_id}/assets{{?name,label}}",
            "assets": [],
            "published_at": None,
        }
        self.releases[tag] = release
        self.tags[tag] = target_commit
        return release

    def upload_evidence_asset(
        self,
        *,
        upload_url: str,
        repository: str,
        release_id: object,
        name: str,
        path: Path,
        maximum_bytes: int,
    ) -> dict[str, Any]:
        data = path.read_bytes()
        assert len(data) <= maximum_bytes
        asset_id = self.next_asset
        self.next_asset += 1
        item = {
            "id": asset_id,
            "name": name,
            "size": len(data),
            "state": "uploaded",
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        }
        release = next(item for item in self.releases.values() if item["id"] == release_id)
        release["assets"].append(item)
        self.assets[asset_id] = data
        return item

    def publish_release(self, repository: str, release_id: object) -> dict[str, Any]:
        release = next(item for item in self.releases.values() if item["id"] == release_id)
        release.update(
            draft=False,
            immutable=True,
            published_at="2026-09-11T00:00:00Z",
        )
        return release

    def reference(self, repository: str, reference: str) -> dict[str, Any]:
        return {"object": {"type": "commit", "sha": self.tags[reference[5:]]}}

    def tag_object(self, repository: str, tag_sha: str) -> dict[str, Any]:
        raise AssertionError("fixtures use lightweight evidence tags")

    def attestations(self, repository: str, digest: str) -> tuple[dict[str, Any], ...]:
        return ({"subject_digest": digest},)

    def download_evidence_asset(
        self,
        repository: str,
        asset_id: object,
        *,
        destination: Path,
        maximum_bytes: int,
    ) -> None:
        data = self.assets[int(str(asset_id))]
        assert len(data) <= maximum_bytes
        destination.write_bytes(data)


class ConcurrentCreateEvidenceAPI(FakeEvidenceAPI):
    """Simulate another trusted publisher winning each unique tag creation."""

    def create_evidence_draft_release(
        self, repository: str, *, tag: str, target_commit: str, body: str
    ) -> dict[str, Any]:
        super().create_evidence_draft_release(
            repository, tag=tag, target_commit=target_commit, body=body
        )
        raise GitHubAPIError("GitHub API POST release returned 422")


class ScopedEvidenceAPI:
    """Record and constrain the provider operations available to one token."""

    def __init__(
        self,
        delegate: FakeEvidenceAPI,
        *,
        forbidden: frozenset[str],
    ) -> None:
        self.delegate = delegate
        self.forbidden = forbidden
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        if name in self.forbidden:
            raise AssertionError(f"token crossed its declared authority boundary: {name}")
        target = getattr(self.delegate, name)

        def call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(name)
            return target(*args, **kwargs)

        return call


def test_archives_are_deterministic_and_deduplicate_equal_bytes(tmp_path: Path) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"exact scanner bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"exact scanner bytes")

    manifest_path = _bundle(root, tmp_path / "bundle", 1)
    manifest = load_input_manifest(root, manifest_path)

    assert manifest["objects"][0]["asset_name"] == manifest["objects"][1]["asset_name"]
    assert len(tuple((manifest_path.parent / "objects").iterdir())) == 1
    assert manifest["total_archive_bytes"] < manifest["total_expanded_bytes"] + 1024


def test_publication_uses_workflow_token_for_reads_and_app_token_only_for_writes(
    tmp_path: Path,
) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"exact scanner bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"exact scanner bytes")
    backing = FakeEvidenceAPI(root)
    writer_methods = frozenset(
        {"create_evidence_draft_release", "upload_evidence_asset", "publish_release"}
    )
    reader = ScopedEvidenceAPI(backing, forbidden=writer_methods)
    writer = ScopedEvidenceAPI(
        backing,
        forbidden=frozenset(
            {
                "artifacts",
                "attestations",
                "commit",
                "content",
                "evidence_release_by_tag",
                "evidence_releases",
                "immutable_releases",
                "jobs",
                "repository",
                "run",
                "workflow",
            }
        ),
    )
    manifest_path = _bundle(root, tmp_path / "bundle", 1)

    publish_input_bundle(
        reader,  # type: ignore[arg-type]
        publication_api=writer,  # type: ignore[arg-type]
        schema_root=root,
        bundle_dir=manifest_path.parent,
        handoff={
            "artifact_id": 501,
            "artifact_name": "bcf-source-1-1",
            "provider_digest": "sha256:" + "0" * 64,
            "run_id": "1",
            "run_attempt": 1,
        },
        output_path=root / ".artifacts/split-authority-reference.json",
    )

    assert set(writer.calls) == writer_methods
    assert "attestations" in reader.calls
    assert "evidence_release_by_tag" in reader.calls


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    [
        (
            lambda manifest: manifest["objects"][1].update(
                target_path="resolved"
            ),
            "target paths must not overlap",
        ),
        (
            lambda manifest: manifest["objects"][0].update(
                asset_name=f"sha256-{'f' * 64}.tar.gz"
            ),
            "filename must encode its SHA-256 digest",
        ),
        (
            lambda manifest: manifest["objects"][1].update(
                archive_size=manifest["objects"][1]["archive_size"] + 1
            ),
            "archive identity has contradictory metadata",
        ),
        (
            lambda manifest: manifest["objects"][0].update(
                target_path="resolved//scanner.bin"
            ),
            "target path must be a canonical relative path",
        ),
        (
            lambda manifest: manifest["objects"][0].update(
                expanded_size=manifest["objects"][0]["expanded_size"] + 1
            ),
            "expanded size differs from its members",
        ),
        (
            lambda manifest: manifest.update(created_at_utc="not-a-date"),
            "created_at_utc must be a UTC timestamp",
        ),
    ],
)
def test_manifest_cross_field_identity_fails_closed(
    tmp_path: Path, mutation: Any, diagnostic: str
) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"same bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"same bytes")
    manifest_path = _bundle(root, tmp_path / "bundle", 1)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutation(payload)
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(EvidenceStorageError, match=diagnostic):
        load_input_manifest(root, manifest_path)


def test_bundle_verification_reconstructs_members_before_publication(
    tmp_path: Path,
) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"same bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"other bytes")
    manifest_path = _bundle(root, tmp_path / "bundle", 1)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["objects"][0]["members"][0]["sha256"] = "f" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(EvidenceStorageError, match="member digest mismatch"):
        verify_input_bundle(root, manifest_path.parent)


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    [
        (
            lambda reference: reference["provider"].update(repository_id=43),
            "provider and subject repository identities differ",
        ),
        (
            lambda reference: reference["provider"].update(
                target_commit="4" * 40
            ),
            "provider target and subject commit differ",
        ),
        (
            lambda reference: reference["source_handoff"].update(run_id="2"),
            "handoff and producer execution identities differ",
        ),
        (
            lambda reference: reference["assets"][1].update(
                name=f"sha256-{'f' * 64}.tar.gz"
            ),
            "asset filename must encode its SHA-256 digest",
        ),
    ],
)
def test_reference_cross_field_identity_fails_closed(
    tmp_path: Path, mutation: Any, diagnostic: str
) -> None:
    root = _storage_repo(tmp_path)
    _, _, reference_path = _published_reference(root, tmp_path)
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    mutation(reference)
    reference_path.write_text(json.dumps(reference), encoding="utf-8")

    with pytest.raises(EvidenceStorageError, match=diagnostic):
        load_input_reference(root, reference_path)


def test_resolver_rejects_noncanonical_content_addressed_tags(tmp_path: Path) -> None:
    root = _storage_repo(tmp_path)
    api, _, reference_path = _published_reference(root, tmp_path)
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    forged = f"bcf-evidence-inputs-manifest-{'f' * 64}"
    reference["provider"]["tag"] = forged
    manifest_asset = next(
        item
        for item in reference["assets"]
        if item["name"] == "evidence-input-manifest.json"
    )
    manifest_asset["tag"] = forged
    reference_path.write_text(json.dumps(reference), encoding="utf-8")

    with pytest.raises(EvidenceStorageError, match="manifest tag is not canonical"):
        resolve_input_reference(
            api,  # type: ignore[arg-type]
            repo_root=root,
            reference_path=reference_path,
            output_root=root / ".artifacts/noncanonical-output",
        )


def test_symlinked_source_and_expired_freshness_fail_closed(tmp_path: Path) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"bytes")
    prepared.joinpath("scanner-copy.bin").symlink_to("scanner.bin")
    with pytest.raises(EvidenceStorageError, match="symlinked"):
        _bundle(root, tmp_path / "bundle", 1)

    prepared.joinpath("scanner-copy.bin").unlink()
    prepared.joinpath("scanner-copy.bin").write_bytes(b"bytes")
    with pytest.raises(EvidenceStorageError, match="freshness has expired"):
        build_input_bundle(
            root,
            namespace="database-inputs",
            specs=[
                InputSpec(
                    id="database",
                    source_path="prepared/scanner.bin",
                    target_path="security/database",
                    freshness_class="advisory_database",
                    observed_at_utc="2025-01-01T00:00:00Z",
                )
            ],
            output_dir=tmp_path / "expired-bundle",
            subject={"repository_id": 42, "commit_sha": COMMIT, "tree_sha": TREE},
            producer=_producer(root, 1),
        )


def test_content_objects_publish_once_and_cold_resolution_recovers_bytes(
    tmp_path: Path,
) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"exact scanner bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"exact scanner bytes")
    api = FakeEvidenceAPI(root)
    references: list[Path] = []
    for run_id in (1, 2):
        manifest_path = _bundle(root, tmp_path / f"bundle-{run_id}", run_id)
        reference_path = root / f".artifacts/reference-{run_id}.json"
        publish_input_bundle(
            api,  # type: ignore[arg-type]
            schema_root=root,
            bundle_dir=manifest_path.parent,
            handoff={
                "artifact_id": 500 + run_id,
                "artifact_name": f"bcf-source-{run_id}-1",
                "provider_digest": "sha256:" + "0" * 64,
                "run_id": str(run_id),
                "run_attempt": 1,
            },
            output_path=reference_path,
        )
        references.append(reference_path)

    assert len([tag for tag in api.releases if "-object-" in tag]) == 1
    assert len([tag for tag in api.releases if "-manifest-" in tag]) == 2
    reference = load_input_reference(root, references[1])
    assert len(reference["assets"]) == 2
    output = root / ".artifacts/resolved"
    resolve_input_reference(
        api,  # type: ignore[arg-type]
        repo_root=root,
        reference_path=references[1],
        output_root=output,
    )
    assert (output / "resolved/scanner.bin").read_bytes() == b"exact scanner bytes"
    assert (output / "resolved/scanner-copy.bin").read_bytes() == b"exact scanner bytes"


def test_reusable_object_release_may_predate_the_current_subject(tmp_path: Path) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"reusable bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"reusable bytes")
    api = FakeEvidenceAPI(root)
    first_manifest = _bundle(root, tmp_path / "bundle-1", 1)
    first_reference = root / ".artifacts/reference-1.json"
    publish_input_bundle(
        api,  # type: ignore[arg-type]
        schema_root=root,
        bundle_dir=first_manifest.parent,
        handoff={
            "artifact_id": 501,
            "artifact_name": "bcf-source-1-1",
            "provider_digest": "sha256:" + "0" * 64,
            "run_id": "1",
            "run_attempt": 1,
        },
        output_path=first_reference,
    )
    first = load_input_reference(root, first_reference)
    first_object = next(
        item for item in first["assets"] if item["name"] != "evidence-input-manifest.json"
    )

    second_commit = "4" * 40
    second_tree = "5" * 40
    api.current_commit = second_commit
    api.current_tree = second_tree
    second_manifest = _bundle(
        root,
        tmp_path / "bundle-2",
        2,
        commit=second_commit,
        tree=second_tree,
    )
    second_reference = root / ".artifacts/reference-2.json"
    publish_input_bundle(
        api,  # type: ignore[arg-type]
        schema_root=root,
        bundle_dir=second_manifest.parent,
        handoff={
            "artifact_id": 502,
            "artifact_name": "bcf-source-2-1",
            "provider_digest": "sha256:" + "0" * 64,
            "run_id": "2",
            "run_attempt": 1,
        },
        output_path=second_reference,
    )
    second = load_input_reference(root, second_reference)
    second_object = next(
        item for item in second["assets"] if item["name"] != "evidence-input-manifest.json"
    )

    assert second["subject"]["commit_sha"] == second_commit
    assert second_object["release_id"] == first_object["release_id"]
    assert second_object["target_commit"] == COMMIT
    resolve_input_reference(
        api,  # type: ignore[arg-type]
        repo_root=root,
        reference_path=second_reference,
        output_root=root / ".artifacts/reused-output",
    )


def test_interrupted_and_concurrent_publication_is_idempotent(tmp_path: Path) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"same reusable bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"same reusable bytes")
    api = ConcurrentCreateEvidenceAPI(root)
    manifest_path = _bundle(root, tmp_path / "bundle", 1)
    reference_path = root / ".artifacts/concurrent-reference.json"

    publish_input_bundle(
        api,  # type: ignore[arg-type]
        schema_root=root,
        bundle_dir=manifest_path.parent,
        handoff={
            "artifact_id": 501,
            "artifact_name": "bcf-source-1-1",
            "provider_digest": "sha256:" + "0" * 64,
            "run_id": "1",
            "run_attempt": 1,
        },
        output_path=reference_path,
    )

    assert all(release["immutable"] for release in api.releases.values())
    assert load_input_reference(root, reference_path)["manifest_sha256"]


@pytest.mark.parametrize("unsafe_name", ["../escape", "/absolute", "."])
def test_actions_handoff_rejects_unsafe_zip_paths(
    tmp_path: Path, unsafe_name: str
) -> None:
    archive = tmp_path / "handoff.zip"
    with zipfile.ZipFile(archive, mode="w") as output:
        output.writestr(unsafe_name, b"unsafe")

    with pytest.raises(EvidenceStorageError, match="unsafe member"):
        extract_handoff_zip(
            archive,
            tmp_path / "output",
            maximum_members=10,
            maximum_bytes=1024,
            maximum_expansion_ratio=100,
        )


def test_actions_handoff_rejects_symlinks_and_decompression_abuse(
    tmp_path: Path,
) -> None:
    symlink_archive = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(symlink_archive, mode="w") as output:
        output.writestr(link, b"target")
    with pytest.raises(EvidenceStorageError, match="unsafe member"):
        extract_handoff_zip(
            symlink_archive,
            tmp_path / "symlink-output",
            maximum_members=10,
            maximum_bytes=1024,
            maximum_expansion_ratio=100,
        )

    compressed = tmp_path / "compressed.zip"
    with zipfile.ZipFile(compressed, mode="w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("large", b"0" * 100_000)
    with pytest.raises(EvidenceStorageError, match="expansion ratio"):
        extract_handoff_zip(
            compressed,
            tmp_path / "compressed-output",
            maximum_members=10,
            maximum_bytes=200_000,
            maximum_expansion_ratio=10,
        )


def test_cold_resolution_rejects_provider_asset_and_attestation_tampering(
    tmp_path: Path,
) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"exact scanner bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"exact scanner bytes")
    api = FakeEvidenceAPI(root)
    manifest_path = _bundle(root, tmp_path / "bundle", 1)
    reference_path = root / ".artifacts/reference.json"
    publish_input_bundle(
        api,  # type: ignore[arg-type]
        schema_root=root,
        bundle_dir=manifest_path.parent,
        handoff={
            "artifact_id": 501,
            "artifact_name": "bcf-source-1-1",
            "provider_digest": "sha256:" + "0" * 64,
            "run_id": "1",
            "run_attempt": 1,
        },
        output_path=reference_path,
    )
    reference = load_input_reference(root, reference_path)
    object_asset = next(
        item for item in reference["assets"] if item["name"] != "evidence-input-manifest.json"
    )
    release = next(
        item for item in api.releases.values() if item["id"] == object_asset["release_id"]
    )
    release["assets"][0]["digest"] = "sha256:" + "f" * 64
    with pytest.raises(EvidenceStorageError, match="asset identity mismatch"):
        resolve_input_reference(
            api,  # type: ignore[arg-type]
            repo_root=root,
            reference_path=reference_path,
            output_root=root / ".artifacts/tampered-output",
        )
    release["assets"][0]["digest"] = "sha256:" + object_asset["sha256"]
    api.attestations = lambda repository, digest: ()  # type: ignore[method-assign]
    with pytest.raises(EvidenceStorageError, match="lacks attestation"):
        resolve_input_reference(
            api,  # type: ignore[arg-type]
            repo_root=root,
            reference_path=reference_path,
            output_root=root / ".artifacts/unattested-output",
        )


def test_detached_gate_projection_recomputes_inputs_and_preserves_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _storage_repo(tmp_path)
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"exact scanner bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"exact scanner bytes")
    api = FakeEvidenceAPI(root)
    manifest_path = _bundle(root, tmp_path / "bundle", 1)
    reference = root / ".artifacts/reference/evidence-input-reference.json"
    publish_input_bundle(
        api,  # type: ignore[arg-type]
        schema_root=root,
        bundle_dir=manifest_path.parent,
        handoff={
            "artifact_id": 501,
            "artifact_name": "bcf-source-1-1",
            "provider_digest": "sha256:" + "0" * 64,
            "run_id": "1",
            "run_attempt": 1,
        },
        output_path=reference,
    )
    materialized = root / ".artifacts/materialized"
    resolve_input_reference(
        api,  # type: ignore[arg-type]
        repo_root=root,
        reference_path=reference,
        output_root=materialized,
    )
    worktree = tmp_path / "detached"
    worktree.mkdir()
    shutil.copytree(root / "schemas", worktree / "schemas")
    shutil.copytree(root / "governance", worktree / "governance")
    output = tmp_path / "receipt"
    output.mkdir()
    monkeypatch.setenv(
        "BCF_EVIDENCE_INPUT_BINDINGS",
        ".artifacts/reference/evidence-input-reference.json|.artifacts/materialized",
    )

    observations, artifacts = _install_durable_inputs(root, worktree, output)

    assert observations[0]["subject_commit"] == COMMIT
    assert artifacts[0]["sha256"] == hashlib.sha256(reference.read_bytes()).hexdigest()
    assert (
        worktree / ".artifacts/materialized/resolved/scanner.bin"
    ).read_bytes() == b"exact scanner bytes"
    materialized.joinpath("resolved/scanner.bin").write_bytes(b"tampered")
    with pytest.raises(EvidenceStorageError, match="differs from manifest"):
        _install_durable_inputs(root, tmp_path / "another-detached")


def test_retention_requires_retrieval_before_deleting_handoff(tmp_path: Path) -> None:
    root = _storage_repo(tmp_path)
    api, _, reference_path = _published_reference(root, tmp_path)
    reference = load_input_reference(root, reference_path)
    live_artifacts = {
        501: {
            "id": 501,
            "name": "bcf-source-1-1",
            "size_in_bytes": 100,
            "expired": False,
            "digest": "sha256:" + "0" * 64,
            "workflow_run": {"id": 1},
        }
    }
    api.repository_artifacts = lambda repository: tuple(  # type: ignore[attr-defined]
        live_artifacts.values()
    )
    api.delete_action_artifact = (  # type: ignore[attr-defined]
        lambda repository, artifact_id: live_artifacts.pop(int(artifact_id), None)
    )
    digest = reference["manifest_sha256"]
    snapshot = {
        "schema_version": "1.0",
        "kind": "governance.evidence-retention-snapshot.v1",
        "repository": "owner/project",
        "repository_id": 42,
        "observed_at_utc": "2026-09-11T00:00:00Z",
        "actions_handoffs": [
            {
                "artifact_id": 501,
                "artifact_name": "bcf-source-1-1",
                "provider_digest": "sha256:" + "0" * 64,
                "run_id": "1",
                "run_attempt": 1,
                "size": 100,
                "published_manifest_sha256": None,
            }
        ],
        "durable_references": [
            {
                "manifest_sha256": digest,
                "release_id": reference["provider"]["release_id"],
                "tag": reference["provider"]["tag"],
                "reference_path": reference_path.relative_to(root).as_posix(),
                "reference_sha256": hashlib.sha256(
                    reference_path.read_bytes()
                ).hexdigest(),
                "protected_roots": ["live_runs:1"],
            }
        ],
        "leases": [],
    }
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    first = plan_retention(
        root,
        path,
        api=api,  # type: ignore[arg-type]
        now=datetime(2026, 9, 11, tzinfo=UTC),
    )
    assert first["actions_handoff_retain_ids"] == [501]
    snapshot["actions_handoffs"][0]["published_manifest_sha256"] = digest
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    second = plan_retention(
        root,
        path,
        api=api,  # type: ignore[arg-type]
        now=datetime(2026, 9, 11, tzinfo=UTC),
    )
    assert second["actions_handoff_delete_ids"] == [501]
    assert second["durable_release_review_ids"] == []

    snapshot["leases"] = [
        {"manifest_sha256": digest, "expires_at_utc": "2026-09-12T00:00:00Z"}
    ]
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    leased = plan_retention(
        root,
        path,
        api=api,  # type: ignore[arg-type]
        now=datetime(2026, 9, 11, tzinfo=UTC),
    )
    assert leased["actions_handoff_retain_ids"] == [501]

    snapshot["leases"] = []
    snapshot["durable_references"][0]["protected_roots"] = []
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    unreachable = plan_retention(
        root,
        path,
        api=api,  # type: ignore[arg-type]
        now=datetime(2026, 9, 11, tzinfo=UTC),
    )
    api_releases = [release["id"] for release in api.releases.values()]
    assert unreachable["durable_release_review_ids"] == sorted(api_releases)
    assert unreachable["automatic_durable_deletion"] is False

    assert len(api_releases) == 2
    snapshot["actions_handoffs"][0]["provider_digest"] = "sha256:" + "f" * 64
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(EvidenceStorageError, match="differs from provider state"):
        plan_retention(
            root,
            path,
            api=api,  # type: ignore[arg-type]
            now=datetime(2026, 9, 11, tzinfo=UTC),
        )

    snapshot["actions_handoffs"][0]["provider_digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    applied = apply_actions_retention(
        root,
        path,
        api=api,  # type: ignore[arg-type]
        now=datetime(2026, 9, 11, tzinfo=UTC),
    )
    assert applied["deleted_artifact_ids"] == [501]
    assert applied["durable_release_deletion_attempted"] is False
    repeated = apply_actions_retention(
        root,
        path,
        api=api,  # type: ignore[arg-type]
        now=datetime(2026, 9, 11, tzinfo=UTC),
    )
    assert repeated["deleted_artifact_ids"] == []
    assert repeated["already_absent_artifact_ids"] == [501]


def test_provider_budget_is_derived_from_complete_authenticated_inventory(
    tmp_path: Path,
) -> None:
    root = _storage_repo(tmp_path)
    contract = yaml.safe_load((root / "governance/evidence-storage.yml").read_text())
    api = FakeEvidenceAPI(root)
    api.repository_artifacts = lambda repository: (  # type: ignore[attr-defined]
        {
            "id": 501,
            "name": "bcf-source-1-1",
            "size_in_bytes": 128,
            "expired": False,
            "workflow_run": {"id": 1},
        },
        {
            "id": 502,
            "name": "ordinary-receipts",
            "size_in_bytes": 256,
            "expired": False,
            "workflow_run": {"id": 1},
        },
    )
    api.evidence_releases = lambda repository: ()  # type: ignore[attr-defined]

    usage = provider_storage_usage(  # type: ignore[arg-type]
        api,
        contract=contract,
        repository="owner/project",
        run_id="1",
        artifact_name="bcf-source-1-1",
    )
    assert usage.actions_bytes == 384
    assert usage.new_bytes == 128

    contract["budgets"]["maximum_actions_bytes"] = 383
    with pytest.raises(EvidenceStorageError, match="budget exceeded"):
        provider_storage_usage(  # type: ignore[arg-type]
            api,
            contract=contract,
            repository="owner/project",
            run_id="1",
            artifact_name="bcf-source-1-1",
        )


def test_provider_budget_counts_manifests_objects_and_resumable_drafts(
    tmp_path: Path,
) -> None:
    root = _storage_repo(tmp_path)
    api, _, _ = _published_reference(root, tmp_path)
    contract = yaml.safe_load((root / "governance/evidence-storage.yml").read_text())
    api.repository_artifacts = lambda repository: (  # type: ignore[attr-defined]
        {
            "id": 501,
            "name": "bcf-source-1-1",
            "size_in_bytes": 128,
            "expired": False,
            "workflow_run": {"id": 1},
        },
    )
    expected_bytes = sum(
        int(asset["size"])
        for release in api.releases.values()
        for asset in release["assets"]
    )
    interrupted_tag = f"bcf-evidence-inputs-object-{'f' * 64}"
    api.create_evidence_draft_release(
        "owner/project",
        tag=interrupted_tag,
        target_commit=COMMIT,
        body="interrupted",
    )

    usage = provider_storage_usage(  # type: ignore[arg-type]
        api,
        contract=contract,
        repository="owner/project",
        run_id="1",
        artifact_name="bcf-source-1-1",
    )

    assert usage.durable_unique_bytes == expected_bytes
    assert usage.object_count == 3


def test_projected_durable_budget_fails_before_publication(tmp_path: Path) -> None:
    root = _storage_repo(tmp_path)
    contract_path = root / "governance/evidence-storage.yml"
    contract = yaml.safe_load(contract_path.read_text())
    contract["budgets"]["maximum_durable_unique_bytes"] = 1
    contract_path.write_text(yaml.safe_dump(contract, sort_keys=False), encoding="utf-8")
    prepared = root / "prepared"
    prepared.mkdir()
    prepared.joinpath("scanner.bin").write_bytes(b"new bytes")
    prepared.joinpath("scanner-copy.bin").write_bytes(b"new bytes")
    api = FakeEvidenceAPI(root)
    manifest_path = _bundle(root, tmp_path / "bundle", 1)

    with pytest.raises(EvidenceStorageError, match="durable unique bytes"):
        publish_input_bundle(
            api,  # type: ignore[arg-type]
            schema_root=root,
            bundle_dir=manifest_path.parent,
            handoff={
                "artifact_id": 501,
                "artifact_name": "bcf-source-1-1",
                "provider_digest": "sha256:" + "0" * 64,
                "run_id": "1",
                "run_attempt": 1,
            },
            output_path=root / ".artifacts/budget-reference.json",
        )
    assert api.releases == {}


def _durable_graph_repo(tmp_path: Path) -> Path:
    root = _storage_repo(tmp_path)
    for name in ("ci-graph.schema.json", "ci-graph-extension.schema.json"):
        shutil.copy2(REPO_ROOT / "schemas" / name, root / "schemas" / name)
    (root / "governance/ci-extensions").mkdir()
    graph = build_reference_ci_graph(
        project_id="fixture",
        profile="standard",
        profile_contract_version="2.0",
        gates=["test"],
        candidate_labels=["ubuntu-24.04"],
        trusted_labels=["self-hosted", "fixture-trusted"],
        candidate_hosted=True,
        trusted_hosted=False,
    )
    contract_path = root / "governance/evidence-storage.yml"
    graph["evidence_storage"] = {
        "path": "governance/evidence-storage.yml",
        "sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
    }
    graph["artifacts"].update(
        {
            "prepared-inputs": {
                "path": ".artifacts/bcf/prepared-inputs",
                "kind": "durable-source",
                "scope": "run-attempt",
                "retention_days": 1,
                "durable_input": {
                    "namespace": "fixture-inputs",
                    "objects": [
                        {
                            "id": "scanner",
                            "source_path": ".artifacts/prepared/scanner",
                            "target_path": "security/scanner",
                            "freshness_class": "immutable",
                        }
                    ],
                },
            },
            "prepared-input-reference": {
                "path": ".artifacts/bcf/prepared-input-reference",
                "kind": "durable-reference",
                "scope": "run-attempt",
                "retention_days": 30,
                "durable_source": "prepared-inputs",
                "materialization_root": ".artifacts/resolved-inputs",
            },
        }
    )
    workflow = next(item for item in graph["workflows"] if item["id"] == "governance")
    preflight = next(item for item in workflow["jobs"] if item["id"] == "cheap-preflight")
    preflight["produces"].append("prepared-inputs")
    publisher = {
        "id": "publish-inputs",
        "display_name": "Publish authenticated durable inputs",
        "semantic_role": "durable-input-publisher",
        "resource_class": "trusted-control",
        "trust": "trusted",
        "needs": [],
        "condition": "success",
        "timeout_minutes": 5,
        "permissions": {
            "actions": "read",
            "attestations": "read",
            "contents": "read",
        },
        "checkout": False,
        "components": [],
        "executor": {
            "kind": "durable_publish",
            "source": "prepared-inputs",
            "reference": "prepared-input-reference",
        },
        "produces": ["prepared-input-reference"],
        "consumes": ["prepared-inputs"],
        "protected_environment": "bcf-trusted-evidence",
        "required": True,
    }
    graph["commands"]["verify-durable-inputs"] = {
        "argv": [
            "{python}",
            "scripts/evidence_storage.py",
            "validate",
            "--repo-root",
            ".",
        ],
        "cwd": ".",
        "environment": {},
    }
    evidence = {
        "id": "verify-inputs",
        "display_name": "Verify authenticated durable inputs",
        "semantic_role": "durable-input-consumer",
        "resource_class": "candidate-python",
        "trust": "candidate",
        "needs": ["publish-inputs"],
        "condition": "success",
        "timeout_minutes": 10,
        "permissions": {
            "actions": "read",
            "attestations": "read",
            "contents": "read",
        },
        "checkout": True,
        "components": ["python", "governance-dependencies"],
        "executor": {"kind": "command", "command": "verify-durable-inputs"},
        "produces": [],
        "consumes": ["prepared-input-reference"],
        "required": True,
    }
    publisher_workflow = {
        "id": "durable-input-flow",
        "path": ".github/workflows/durable-input-flow.yml",
        "display_name": "Fixture durable input flow",
        "role": "trusted-control",
        "events": [
            {
                "type": "workflow_run",
                "workflows": [workflow["display_name"]],
                "types": ["completed"],
            }
        ],
        "permissions": {"contents": "read"},
        "jobs": [publisher, evidence],
    }
    graph["workflows"].append(publisher_workflow)
    evidence["permissions"] = {
        "actions": "read",
        "attestations": "read",
        "contents": "read",
    }
    (root / "governance/ci-graph.yml").write_bytes(render_yaml(graph))
    return root


def test_graph_renders_short_handoff_trusted_publish_and_cold_resolve(
    tmp_path: Path,
) -> None:
    root = _durable_graph_repo(tmp_path)
    compiled = validate_ci_graph(root)
    rendered = render_ci_graph(root)[
        ".github/workflows/durable-input-flow.yml"
    ].decode()
    workflow = yaml.safe_load("\n".join(rendered.splitlines()[4:]))

    assert dict(compiled.input_sha256)["governance/evidence-storage.yml"]
    source_rendered = yaml.safe_load(
        "\n".join(
            render_ci_graph(root)[".github/workflows/governance.yml"]
            .decode()
            .splitlines()[4:]
        )
    )
    preflight_steps = source_rendered["jobs"]["cheap-preflight"]["steps"]
    publisher = workflow["jobs"]["publish-inputs"]
    evidence = workflow["jobs"]["verify-inputs"]
    assert any("prepare --repo-root" in step.get("run", "") for step in preflight_steps)
    assert publisher["runs-on"] == ["self-hosted", "fixture-trusted"]
    assert publisher["environment"] == "bcf-trusted-evidence"
    token_step = publisher["steps"][0]
    assert token_step["with"] == {
        "app-id": "${{ vars.BCF_EVIDENCE_APP_ID }}",
        "private-key": "${{ secrets.BCF_EVIDENCE_APP_PRIVATE_KEY }}",
        "permission-contents": "write",
    }
    publish_step = next(step for step in publisher["steps"] if "publish-github" in step.get("run", ""))
    assert publish_step["env"] == {
        "GITHUB_TOKEN": "${{ github.token }}",
        "BCF_EVIDENCE_WRITE_TOKEN": "${{ steps.evidence-app-token.outputs.token }}",
    }
    assert any("publish-github" in step.get("run", "") for step in publisher["steps"])
    assert not any("download-artifact" in step.get("uses", "") for step in publisher["steps"])
    assert any("resolve-github" in step.get("run", "") for step in evidence["steps"])
    assert evidence["permissions"] == {
        "actions": "read",
        "attestations": "read",
        "contents": "read",
    }
    checkout = next(
        step for step in evidence["steps"] if "actions/checkout" in step.get("uses", "")
    )
    assert checkout["with"]["ref"] == "${{ github.event.workflow_run.head_sha }}"
    assert all(
        token not in step.get("run", "").lower().split()
        for job in workflow["jobs"].values()
        if job.get("runs-on") == "ubuntu-24.04"
        for step in job.get("steps", [])
        for token in ("sleep", "poll", "wait", "wait-for-runner", "lease-runner")
    )


@pytest.mark.parametrize(
    "case",
    [
        ("retention", "source prepared-inputs retention differs"),
        ("candidate-publisher", "publish-inputs must be trusted control"),
        ("publisher-write-token", "workflow token must remain read-only"),
        ("source-bypass", "verify-inputs bypasses the durable evidence reference"),
        ("missing-contract", "durable evidence topology lacks a storage contract"),
        ("contract-digest", "evidence storage contract digest mismatch"),
        ("overlap", "durable evidence materialization roots overlap"),
        ("matrix-source", "prepared-inputs requires one non-matrix producer"),
        ("consumer-permissions", "verify-inputs lacks read authority"),
        ("optional-publisher", "publish-inputs must be required after source success"),
        ("orphan-reference", "prepared-input-reference has no verifying consumer"),
        ("same-workflow-publisher", "must run in a separate trusted workflow"),
        ("manual-publisher", "must authenticate the exact completed source workflow"),
    ],
    ids=lambda case: case[0],
)
def test_graph_rejects_durable_transport_authority_bypasses(
    tmp_path: Path, case: tuple[str, str]
) -> None:
    mutation, diagnostic = case
    root = _durable_graph_repo(tmp_path)
    path = root / "governance/ci-graph.yml"
    graph = yaml.safe_load(path.read_text())
    source_workflow = next(
        item for item in graph["workflows"] if item["id"] == "governance"
    )
    workflow = next(
        item for item in graph["workflows"] if item["id"] == "durable-input-flow"
    )
    publisher = next(item for item in workflow["jobs"] if item["id"] == "publish-inputs")
    if mutation == "retention":
        graph["artifacts"]["prepared-inputs"]["retention_days"] = 30
    elif mutation == "candidate-publisher":
        publisher["trust"] = "candidate"
        publisher["resource_class"] = "candidate-python"
    elif mutation == "publisher-write-token":
        publisher["permissions"]["contents"] = "write"
    elif mutation == "missing-contract":
        del graph["evidence_storage"]
    elif mutation == "contract-digest":
        graph["evidence_storage"]["sha256"] = "0" * 64
    elif mutation == "overlap":
        graph["artifacts"]["prepared-input-reference"]["materialization_root"] = (
            ".artifacts/bcf/prepared-inputs/nested"
        )
    elif mutation == "matrix-source":
        preflight = next(
            item for item in source_workflow["jobs"] if item["id"] == "cheap-preflight"
        )
        preflight["matrix"] = {"shard": ["one"]}
    elif mutation == "consumer-permissions":
        evidence = next(item for item in workflow["jobs"] if item["id"] == "verify-inputs")
        evidence["permissions"].pop("attestations")
    elif mutation == "optional-publisher":
        publisher["required"] = False
    elif mutation == "orphan-reference":
        evidence = next(item for item in workflow["jobs"] if item["id"] == "verify-inputs")
        evidence["consumes"].remove("prepared-input-reference")
    elif mutation == "same-workflow-publisher":
        evidence = next(item for item in workflow["jobs"] if item["id"] == "verify-inputs")
        workflow["jobs"].remove(publisher)
        source_workflow["jobs"].append(publisher)
        publisher["needs"] = ["cheap-preflight"]
        evidence["needs"] = []
        source_workflow["events"] = [
            {
                "type": "workflow_run",
                "workflows": [source_workflow["display_name"]],
                "types": ["completed"],
            }
        ]
    elif mutation == "manual-publisher":
        workflow["events"] = [{"type": "workflow_dispatch"}]
    else:
        evidence = next(item for item in workflow["jobs"] if item["id"] == "verify-inputs")
        evidence["consumes"].append("prepared-inputs")
    path.write_bytes(render_yaml(graph))

    with pytest.raises(CIGraphError, match=diagnostic):
        validate_ci_graph(root)
