"""Ambiguous protected documents reject before downstream authority work."""

from pathlib import Path
from types import SimpleNamespace
import hashlib

import pytest
import yaml

from bcf_governance.tooling import (
    ci_authority_pins, ci_controller_policy, ci_github_authority,
    ci_github_release_inputs, ci_self_controller, github_protection,
    prior_evidence_transport, routine_controller_rotation, semantic_yaml,
)
from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import GitHubControllerError, MainIdentity


ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
TREE = "b" * 40
WORKFLOW = b"name: fixture\non: workflow_dispatch\njobs:\n  gate:\n    name: Gate\n    runs-on: ubuntu-latest\n    steps: [{run: 'echo fixture'}]\n"


def _duplicate(raw: bytes) -> bytes:
    value = yaml.safe_load(raw)
    key = next(iter(value))
    return raw + b"\n" + yaml.safe_dump({key: value[key]}, sort_keys=False).encode()


def _api(raw: bytes, path: str, repository_id="1207503211"):
    main = MainIdentity(repository_id, "main", SHA, TREE)
    reads = []

    def content(repository, observed_path, *, ref):
        assert (repository, observed_path, ref) == ("owner/repo", path, SHA)
        reads.append(path)
        oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        return GitHubContent(path=path, blob_oid=oid, content=raw)

    return SimpleNamespace(content=content), main, reads


def _forbidden(*args, **kwargs):
    raise AssertionError("ambiguous input reached downstream work")


def test_authority_duplicates_reject_before_schema_or_role_selection(monkeypatch):
    path = "governance/ci-authority.yml"
    raw = (ROOT / path).read_bytes()
    api, main, _ = _api(raw, path)
    assert ci_github_authority.load_authority(api, "owner/repo", main) == yaml.safe_load(raw)
    api, main, reads = _api(_duplicate(raw), path)
    monkeypatch.setattr(ci_github_authority, "validate_ci_contract", _forbidden)
    with pytest.raises(GitHubControllerError) as error:
        ci_github_authority.load_authority(api, "owner/repo", main)
    assert isinstance(error.value.__cause__, semantic_yaml.SemanticYAMLError)
    assert reads == [path]


@pytest.mark.parametrize("raw", [
    b"policy: allow\npolicy: deny\n",
    b"policy:\n  required: false\n  required: true\n",
    b"policy: {true: allow, 1: deny}\n",
])
def test_policy_mapping_rejects_ambiguous_keys_at_every_depth(raw):
    with pytest.raises(GitHubControllerError) as error:
        prior_evidence_transport._mapping(raw, label="protected policy")
    assert isinstance(error.value.__cause__, semantic_yaml.SemanticYAMLError)


@pytest.mark.parametrize("local", [False, True])
def test_protection_duplicates_reject_before_schema_or_provider_mutation(tmp_path, monkeypatch, local):
    raw = (ROOT / "governance/github-protection.yml").read_bytes()
    schema = ci_github_authority.packaged_repo_root() / github_protection.SCHEMA_PATH
    assert github_protection.load_protection_bytes(raw, schema_path=schema) == yaml.safe_load(raw)
    if local:
        path = tmp_path / github_protection.PROTECTION_PATH
        path.parent.mkdir(parents=True)
        path.write_bytes(_duplicate(raw))
        operation = lambda: github_protection.load_protection(tmp_path)
    else:
        operation = lambda: github_protection.load_protection_bytes(_duplicate(raw), schema_path=schema)
    monkeypatch.setattr(github_protection, "_validate_protection", _forbidden)
    with pytest.raises(GitHubControllerError) as error:
        operation()
    assert isinstance(error.value.__cause__, semantic_yaml.SemanticYAMLError)


def test_release_contract_duplicates_reject_before_version_or_artifact_work(monkeypatch):
    path = "governance/public-contracts.yml"
    raw = (ROOT / path).read_bytes()
    api, main, _ = _api(raw, path)
    assert ci_github_release_inputs._release_version_at_main(api, repository="owner/repo", main=main)
    api, main, _ = _api(_duplicate(raw), path)
    monkeypatch.setattr(ci_github_release_inputs, "parse_release_version", _forbidden)
    with pytest.raises(GitHubControllerError) as error:
        ci_github_release_inputs._release_version_at_main(api, repository="owner/repo", main=main)
    assert isinstance(error.value.__cause__, semantic_yaml.SemanticYAMLError)


@pytest.mark.parametrize("kind", ["jobs", "events", "rotation"])
def test_workflow_duplicates_cannot_change_or_hide_inventory(kind):
    if kind == "jobs":
        operation = lambda raw: ci_authority_pins.compiled_workflow_jobs(raw, roles=None)
        failure = ci_authority_pins.CIAuthorityPinError
    elif kind == "events":
        operation = ci_authority_pins.compiled_workflow_events
        failure = ci_authority_pins.CIAuthorityPinError
    else:
        operation = routine_controller_rotation._workflow_jobs
        failure = routine_controller_rotation.RoutineCallbackTopologyError
    assert operation(WORKFLOW)
    with pytest.raises(failure) as error:
        operation(_duplicate(WORKFLOW))
    assert isinstance(error.value.__cause__, semantic_yaml.SemanticYAMLError)


def test_authority_pinning_rejects_duplicates_before_history_or_projection(tmp_path):
    path = tmp_path / "authority.yml"
    raw = (ROOT / "governance/ci-authority.yml").read_bytes()
    path.write_bytes(raw)
    assert ci_authority_pins._mapping(path)[1] == yaml.safe_load(raw)
    path.write_bytes(_duplicate(raw))
    with pytest.raises(ci_authority_pins.CIAuthorityPinError) as error:
        ci_authority_pins._mapping(path)
    assert isinstance(error.value.__cause__, semantic_yaml.SemanticYAMLError)


@pytest.mark.parametrize("target", ["graph", "policy"])
def test_controller_source_rejects_duplicate_policy_before_installation(target):
    graph = "governance/ci-graph.yml"
    policy = "governance/self-governance-policy.yml"
    sources = {path: (ROOT / path).read_bytes() for path in (graph, policy)}
    assert ci_controller_policy.source_controller_policy(
        sources.__getitem__, schema_root=ci_github_authority.packaged_repo_root(),
    )
    path = graph if target == "graph" else policy
    sources[path] = _duplicate(sources[path])
    observed = []

    def fetch(path):
        observed.append(path)
        return sources[path]

    with pytest.raises(ci_controller_policy.TrustedControllerPolicyError) as error:
        ci_controller_policy.source_controller_policy(fetch, schema_root=ci_github_authority.packaged_repo_root())
    assert isinstance(error.value.__cause__, semantic_yaml.SemanticYAMLError)
    assert observed == ([graph] if target == "graph" else [graph, policy])


@pytest.mark.parametrize("kind", ["env", "topology"])
def test_controller_projection_rejects_ambiguous_source_before_edits(kind):
    if kind == "env":
        raw = b"name: fixture\nenv:\n  PIN: a\n"
        operation = lambda value: ci_self_controller._replace_env(value, {"PIN": "b"})
    else:
        raw = b"name: fixture\ncontroller_commit: " + SHA.encode() + b"\n"
        operation = lambda value: ci_self_controller._replace_topology_controller(value, TREE)
    assert operation(raw) != raw
    with pytest.raises((GitHubControllerError, semantic_yaml.SemanticYAMLError)):
        operation(_duplicate(raw))


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_supported_yaml_aliases_and_explicit_merge_override_remain_valid(encoding):
    raw = "defaults: &defaults {required: false}\npolicy: {<<: *defaults, required: true}\n".encode(encoding)
    value = semantic_yaml.load_unique_mapping_text(raw)
    assert value == {"defaults": {"required": False}, "policy": {"required": True}}
