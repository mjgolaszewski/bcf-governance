from __future__ import annotations

import hashlib
import json

import pytest

from bcf_governance.tooling.automation_contracts import (
    AutomationContractError,
    ProducerMatch,
)
from bcf_governance.tooling.automation_projections import project_automation_outputs
from bcf_governance.tooling.ci_github_api import GitHubContent


REPOSITORY = "owner/repository"
MAIN = "a" * 40
CANDIDATE = "b" * 40
SOURCE = "template-repo/requirements-governance.txt"
TARGET = "package/template-repo/requirements-governance.txt"
MANIFEST_A = "template-repo/.bcf-pack-manifest.json"
MANIFEST_B = "package/template-repo/.bcf-pack-manifest.json"
ENTRY = "requirements-governance.txt"
OLD = b"pytest==9.0.3\n"
NEW = b"pytest==9.1.1\n"


def _manifest(content: bytes) -> bytes:
    return (
        json.dumps(
            {
                "files": {
                    ENTRY: {
                        "operation": "copy",
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                },
                "generated": [],
                "schema_version": "1.0",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


class ProjectionAPI:
    def __init__(self) -> None:
        self.values = {
            (MAIN, SOURCE): OLD,
            (MAIN, TARGET): OLD,
            (MAIN, MANIFEST_A): _manifest(OLD),
            (MAIN, MANIFEST_B): _manifest(OLD),
            (CANDIDATE, SOURCE): NEW,
            (CANDIDATE, TARGET): OLD,
            (CANDIDATE, MANIFEST_A): _manifest(OLD),
            (CANDIDATE, MANIFEST_B): _manifest(OLD),
        }

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        assert repository == REPOSITORY
        content = self.values[(ref, path)]
        return GitHubContent(path, hashlib.sha1(content).hexdigest(), content)  # noqa: S324


def _match(
    *,
    dependency_paths: tuple[str, ...] = (SOURCE,),
    output_paths: tuple[str, ...] = (),
) -> ProducerMatch:
    return ProducerMatch(
        producer={
            "mechanical_projections": [
                {
                    "id": "template-copy",
                    "kind": "exact_copy_with_sha256_manifests",
                    "source_path": SOURCE,
                    "exact_copy_targets": [TARGET],
                    "sha256_manifest_entries": [
                        {"manifest_path": MANIFEST_A, "entry_path": ENTRY},
                        {"manifest_path": MANIFEST_B, "entry_path": ENTRY},
                    ],
                }
            ]
        },
        dependency_paths=dependency_paths,
        projection_output_paths=output_paths,
    )


def test_projection_repairs_exact_copy_and_both_manifests() -> None:
    result = project_automation_outputs(
        ProjectionAPI(),
        repository=REPOSITORY,
        main_sha=MAIN,
        candidate_sha=CANDIDATE,
        match=_match(),
    )
    assert result == {
        MANIFEST_B: _manifest(NEW),
        TARGET: NEW,
        MANIFEST_A: _manifest(NEW),
    }


def test_projection_is_idempotent_when_outputs_are_exact() -> None:
    api = ProjectionAPI()
    for path, content in {
        TARGET: NEW,
        MANIFEST_A: _manifest(NEW),
        MANIFEST_B: _manifest(NEW),
    }.items():
        api.values[(CANDIDATE, path)] = content
    assert project_automation_outputs(
        api,
        repository=REPOSITORY,
        main_sha=MAIN,
        candidate_sha=CANDIDATE,
        match=_match(output_paths=(MANIFEST_A, MANIFEST_B, TARGET)),
    ) == {}


def test_projection_rejects_independent_or_source_less_outputs() -> None:
    api = ProjectionAPI()
    api.values[(CANDIDATE, TARGET)] = b"forged\n"
    with pytest.raises(AutomationContractError, match="independently modified"):
        project_automation_outputs(
            api,
            repository=REPOSITORY,
            main_sha=MAIN,
            candidate_sha=CANDIDATE,
            match=_match(output_paths=(TARGET,)),
        )
    with pytest.raises(AutomationContractError, match="without its source"):
        project_automation_outputs(
            ProjectionAPI(),
            repository=REPOSITORY,
            main_sha=MAIN,
            candidate_sha=CANDIDATE,
            match=_match(dependency_paths=(), output_paths=(TARGET,)),
        )


def test_projection_rejects_stale_baseline_or_unrelated_manifest_change() -> None:
    api = ProjectionAPI()
    api.values[(MAIN, TARGET)] = b"stale\n"
    with pytest.raises(AutomationContractError, match="baseline copy is stale"):
        project_automation_outputs(
            api,
            repository=REPOSITORY,
            main_sha=MAIN,
            candidate_sha=CANDIDATE,
            match=_match(),
        )
    api = ProjectionAPI()
    changed = json.loads(_manifest(OLD))
    changed["unrelated"] = True
    api.values[(CANDIDATE, MANIFEST_A)] = (
        json.dumps(changed, indent=2, sort_keys=True) + "\n"
    ).encode()
    with pytest.raises(AutomationContractError, match="independently modified"):
        project_automation_outputs(
            api,
            repository=REPOSITORY,
            main_sha=MAIN,
            candidate_sha=CANDIDATE,
            match=_match(output_paths=(MANIFEST_A,)),
        )
