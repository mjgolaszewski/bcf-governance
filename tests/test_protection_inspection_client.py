from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_github_api import GitHubAPIError
from bcf_governance.tooling.ci_github_extension_commands import _prior_evidence
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.github_protection import (
    desired_ruleset, inspect_protection_declaration,
)
from bcf_governance.tooling.protection_inspection_client import ProtectionInspectionClient


REPOSITORY = "mjgolaszewski/bcf-governance"
REPOSITORY_ID = 1207503211
RULESET_ID = 21862678


def _client(**changes: object) -> ProtectionInspectionClient:
    values: dict[str, object] = {
        "token": "fake-installation-token",
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "installation_id": 123,
        "observed_installation_id": 123,
    }
    values.update(changes)
    return ProtectionInspectionClient(**values)


def _responses(monkeypatch: pytest.MonkeyPatch, ruleset: dict) -> list[str]:
    observed: list[str] = []
    inventory = {
        "total_count": 1,
        "repositories": [{"id": REPOSITORY_ID, "full_name": REPOSITORY}],
    }
    values = {
        "/installation/repositories?per_page=100": inventory,
        f"/repos/{REPOSITORY}": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        f"/repos/{REPOSITORY}/rulesets?includes_parents=false&per_page=100": [
            {"id": RULESET_ID, "name": "main-governance"}
        ],
        f"/repos/{REPOSITORY}/rulesets/{RULESET_ID}": ruleset,
    }

    def open_request(request):
        assert request.get_method() == "GET"
        path = request.full_url.removeprefix("https://api.github.com")
        observed.append(path)
        return BytesIO(json.dumps(values[path]).encode())

    monkeypatch.setattr(
        "bcf_governance.tooling.protection_inspection_client._open_inspection",
        open_request,
    )
    return observed


def _declaration() -> dict:
    import yaml
    from pathlib import Path

    return yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "governance/github-protection.yml").read_text()
    )


def test_inspector_authenticates_exact_single_repository_and_clean_protection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _declaration()
    observed = _responses(
        monkeypatch, {"id": RULESET_ID, **desired_ruleset(declaration)}
    )
    client = _client()
    client.verify_installation()
    result = inspect_protection_declaration(
        client, repository=REPOSITORY, declaration=declaration
    )
    assert result.status == "clean"
    assert len(observed) == 4


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", f"/repos/{REPOSITORY}/rulesets"),
        ("PUT", f"/repos/{REPOSITORY}/rulesets/{RULESET_ID}"),
        ("DELETE", f"/repos/{REPOSITORY}/rulesets/{RULESET_ID}"),
        ("PATCH", f"/repos/{REPOSITORY}/rulesets/{RULESET_ID}"),
        ("GET", f"/repos/{REPOSITORY}/branches/main/protection"),
        ("GET", f"/repos/{REPOSITORY}/issues"),
        ("GET", "/repos/other/repository/rulesets/1"),
    ],
)
def test_inspector_rejects_mutation_methods_and_unlisted_endpoints(
    method: str, path: str,
) -> None:
    with pytest.raises(GitHubAPIError, match="declared GET endpoints"):
        _client()._request(method, path)


def test_inspector_rejects_wrong_installation_and_repository() -> None:
    with pytest.raises(GitHubAPIError, match="installation identity"):
        _client(observed_installation_id=124)
    with pytest.raises(GitHubAPIError, match="not authorized"):
        _client().repository("other/repository")


@pytest.mark.parametrize("value", [None, "redacted", [{"actor_id": 1}]])
def test_inspector_rejects_redacted_or_unexpected_bypass_actors(
    monkeypatch: pytest.MonkeyPatch, value: object,
) -> None:
    declaration = _declaration()
    detail = {"id": RULESET_ID, **desired_ruleset(declaration)}
    if value is None:
        del detail["bypass_actors"]
    else:
        detail["bypass_actors"] = value
    _responses(monkeypatch, detail)
    client = _client()
    client.verify_installation()
    if value is None or value == "redacted":
        with pytest.raises(GitHubAPIError, match="absent or redacted"):
            inspect_protection_declaration(client, repository=REPOSITORY, declaration=declaration)
    else:
        assert inspect_protection_declaration(
            client, repository=REPOSITORY, declaration=declaration
        ).status == "drift"


def test_inspector_rejects_multi_repository_installation(monkeypatch: pytest.MonkeyPatch) -> None:
    _responses(monkeypatch, {})

    def wrong_scope(request):
        assert request.get_method() == "GET"
        return BytesIO(json.dumps({
            "total_count": 2,
            "repositories": [
                {"id": REPOSITORY_ID, "full_name": REPOSITORY},
                {"id": 99, "full_name": "other/repository"},
            ],
        }).encode())

    monkeypatch.setattr(
        "bcf_governance.tooling.protection_inspection_client._open_inspection",
        wrong_scope,
    )
    with pytest.raises(GitHubAPIError, match="scope is not exact"):
        _client().verify_installation()


def test_activated_transport_rejects_missing_inspection_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("BCF_PROTECTION_INSPECT_REQUIRED", "true")
    monkeypatch.delenv("BCF_PROTECTION_INSPECT_APP_TOKEN", raising=False)
    with pytest.raises(GitHubControllerError, match="missing BCF_PROTECTION_INSPECT_APP_TOKEN"):
        _prior_evidence([
            "transport", "--repository", REPOSITORY, "--main-sha", "a" * 40,
            "--output", str(tmp_path / "transport"),
        ])
