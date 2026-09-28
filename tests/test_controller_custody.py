from __future__ import annotations

import copy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sys
import zipfile

import pytest

from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.ci_github_identity import MainIdentity
from bcf_governance.tooling.ci_github_artifacts import ProviderArtifact
from bcf_governance.tooling import ci_controller_custody_auth as custody_auth
from bcf_governance.tooling.controller_custody import (
    authority_identity,
    compile_controller_custody,
    validate_controller_custody,
)
from bcf_governance.tooling.controller_custody_prospective import (
    validate_controller_custody_chain,
)
from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph


COMMIT = "a" * 40
TREE = "b" * 40
WHEEL = "c" * 64
TRANSITION = "d" * 64
PIN = {
    "BCF_BOOTSTRAP_ARTIFACT_ID": "11",
    "BCF_BOOTSTRAP_ARTIFACT_NAME": f"bcf-trusted-control-{COMMIT}-1",
    "BCF_BOOTSTRAP_ARTIFACT_DIGEST": "sha256:" + "e" * 64,
    "BCF_BOOTSTRAP_RUN_ID": "12",
    "BCF_BOOTSTRAP_RUN_ATTEMPT": "1",
    "BCF_BOOTSTRAP_COMMIT_SHA": COMMIT,
    "BCF_BOOTSTRAP_TREE_SHA": TREE,
    "BCF_BOOTSTRAP_REPOSITORY_ID": "13",
    "BCF_BOOTSTRAP_WHEEL_SHA256": WHEEL,
}


def _custody() -> dict:
    return compile_controller_custody(
        {
            "source": "provider_transition",
            "subject": {"commit_sha": COMMIT, "tree_sha": TREE},
            "pin": PIN,
            "transition_ids": [TRANSITION],
        },
        repository="owner/repo",
    )


def test_effective_controller_custody_preserves_complete_provider_identity() -> None:
    custody = _custody()
    assert custody["controller"] == {
        "commit_sha": COMMIT,
        "tree_sha": TREE,
        "wheel_sha256": WHEEL,
        "artifact_id": "11",
        "artifact_name": f"bcf-trusted-control-{COMMIT}-1",
        "provider_digest": "sha256:" + "e" * 64,
        "run_id": "12",
        "run_attempt": "1",
    }
    assert authority_identity(custody) == {
        "controller_commit_sha": COMMIT,
        "controller_bundle_sha256": WHEEL,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["controller"].update(commit_sha="f" * 40),
        lambda value: value["controller"].update(wheel_sha256="malformed"),
        lambda value: value["controller"].update(run_attempt="0"),
        lambda value: value["controller"].update(artifact_name="unbound"),
        lambda value: value.update(transition_ids=[TRANSITION, TRANSITION]),
        lambda value: value["subject"].update(tree_sha="malformed"),
        lambda value: value["repository"].update(full_name="wrong"),
    ],
)
def test_controller_custody_rejects_substitution_or_ambiguity(mutation) -> None:
    value = copy.deepcopy(_custody())
    mutation(value)
    with pytest.raises(GitHubControllerError):
        validate_controller_custody(value)


def test_prospective_chain_executes_every_producer_shape_and_consumer_route() -> None:
    root = Path(__file__).resolve().parents[1]
    result = validate_controller_custody_chain(
        validate_ci_graph(root).graph,
        python_executable=Path(sys.executable),
    )
    assert result["status"] == "proved"
    assert result["producer_shapes"] == [
        "active_transition",
        "admission_custody",
        "certification",
        "legacy_noncertifying_finalizer",
        "no_transition",
        "release_receipt",
    ]


def test_prospective_chain_rejects_publisher_without_exact_finalizer_custody() -> None:
    root = Path(__file__).resolve().parents[1]
    graph = copy.deepcopy(validate_ci_graph(root).graph)
    publisher = next(
        value for value in graph["workflows"]
        if value["id"] == "exact-main-publisher"
    )["jobs"][0]
    publisher["consumes"] = ["exact-main-certification"]
    with pytest.raises(GitHubControllerError, match="publisher controller-custody"):
        validate_controller_custody_chain(
            graph,
            python_executable=Path(sys.executable),
        )


def test_prospective_chain_rejects_unbound_finalizer_custody_transport() -> None:
    root = Path(__file__).resolve().parents[1]
    graph = copy.deepcopy(validate_ci_graph(root).graph)
    graph["step_components"]["download-finalizer-controller-custody"]["with"][
        "run-id"
    ] = "${{ github.run_id }}"
    with pytest.raises(GitHubControllerError, match="transport is not attempt-exact"):
        validate_controller_custody_chain(
            graph,
            python_executable=Path(sys.executable),
        )


def test_prospective_chain_rejects_an_unowned_downstream_permutation() -> None:
    root = Path(__file__).resolve().parents[1]
    graph = copy.deepcopy(validate_ci_graph(root).graph)
    workflow = next(
        value for value in graph["workflows"] if value["id"] == "controller-rotation"
    )
    next(value for value in workflow["jobs"] if value["id"] == "outcome")[
        "produces"
    ] = []
    with pytest.raises(GitHubControllerError, match="outcome producer contract"):
        validate_controller_custody_chain(
            graph,
            python_executable=Path(sys.executable),
        )


def test_prospective_chain_rejects_mixed_automation_and_rotation_triggers() -> None:
    root = Path(__file__).resolve().parents[1]
    graph = copy.deepcopy(validate_ci_graph(root).graph)
    automation = next(
        value for value in graph["workflows"]
        if value["id"] == "automation-reconcile"
    )
    automation["events"][0]["workflows"].append("bcf/exact-main-admission")
    with pytest.raises(GitHubControllerError, match="not trigger-isolated"):
        validate_controller_custody_chain(
            graph,
            python_executable=Path(sys.executable),
        )


def _custody_archive(*, extra: bool = False) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(
            "controller-custody.json",
            json.dumps(_custody(), sort_keys=True, separators=(",", ":")),
        )
        if extra:
            archive.writestr("unowned.json", "{}")
    return stream.getvalue()


def _custody_provider(monkeypatch: pytest.MonkeyPatch, raw: bytes, *, digest: str = ""):
    artifact = ProviderArtifact(
        run_id="12", run_attempt=1, artifact_id="11",
        artifact_name="bcf-controller-custody-12-1",
        provider_digest=digest or "sha256:" + hashlib.sha256(raw).hexdigest(),
        workflow={},
    )
    calls = []
    monkeypatch.setattr(
        custody_auth, "resolve_role_artifact",
        lambda _api, **kwargs: calls.append(kwargs) or artifact,
    )

    class API:
        def artifact_bytes(self, repository, artifact_id, *, maximum_bytes):
            assert (repository, artifact_id, maximum_bytes) == (
                "owner/repo", "11", 1_048_576,
            )
            return raw

    return API(), calls


def test_standalone_custody_authenticates_exact_provider_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _custody_archive()
    api, calls = _custody_provider(monkeypatch, raw)
    main = MainIdentity(
        repository_id="13", default_branch="main",
        checkout_sha=COMMIT, tree_sha=TREE,
    )
    assert custody_auth.authenticate_controller_custody(
        api, repository="owner/repo", main=main, authority={},
        run_id="12", run_attempt=1,
    ) == _custody()
    assert calls == [{
        "repository": "owner/repo", "main": main, "authority": {},
        "role": "admission", "run_id": "12", "run_attempt": 1,
        "artifact_name": "bcf-controller-custody-12-1",
        "require_success": False,
    }]


@pytest.mark.parametrize("defect", ["digest", "inventory", "subject"])
def test_standalone_custody_rejects_substituted_provider_contract(
    monkeypatch: pytest.MonkeyPatch, defect: str,
) -> None:
    raw = _custody_archive(extra=defect == "inventory")
    api, _ = _custody_provider(
        monkeypatch, raw,
        digest="sha256:" + "0" * 64 if defect == "digest" else "",
    )
    main = MainIdentity(
        repository_id="13", default_branch="main",
        checkout_sha="f" * 40 if defect == "subject" else COMMIT,
        tree_sha=TREE,
    )
    with pytest.raises(GitHubControllerError):
        custody_auth.authenticate_controller_custody(
            api, repository="owner/repo", main=main, authority={},
            run_id="12", run_attempt=1,
        )
