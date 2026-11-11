"""Consumer-boundary controls for response-bearing opener exceptions.

These cases use real HTTPError bodies and the existing transport entry points.
A translated error is not enough: its owned response must already be retired.
"""
from __future__ import annotations

from email.message import Message
from io import BytesIO
from urllib.error import HTTPError

import pytest

from bcf_governance.tooling import ci_github_api, evidence_storage_github_api
from bcf_governance.tooling import protection_inspection_client
from bcf_governance.tooling.ci_github_api import GitHubAPI, GitHubAPIError
from bcf_governance.tooling.ci_github_errors import GitHubAPIConflictError
from bcf_governance.tooling.evidence_storage_github_api import GitHubEvidenceAPI
from bcf_governance.tooling.protection_inspection_client import ProtectionInspectionClient


class _Body(BytesIO):
    close_calls = 0

    def close(self):
        self.close_calls += 1
        super().close()


def _failure(code):
    body = _Body(b'{"message":"controlled provider failure"}')
    error = HTTPError("https://api.github.com/repos/acme/project", code,
                      "controlled failure", Message(), body)
    calls = []

    def opener(request, **_kwargs):
        calls.append(request)
        raise error

    return body, error, calls, opener


def _assert_retired(body, error, calls, failure, method):
    assert len(calls) == 1, "response cleanup cannot authorize another request"
    assert calls[0].get_method() == method
    assert body.closed, "response-bearing opener exception escaped with its body open"
    assert body.close_calls == 1, "each error body must have one retirement owner"
    assert failure.value.__cause__ is error or failure.value.__cause__.__cause__ is error


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("code", [409, 422, 503])
def test_json_mutation_retires_error_before_translation(monkeypatch, method, code):
    body, error, calls, opener = _failure(code)
    monkeypatch.setattr(ci_github_api, "open_download", opener)
    client = GitHubAPI(token="fixture-token")
    expected = GitHubAPIConflictError if code in {409, 422} else GitHubAPIError
    with pytest.raises(expected) as failure:
        client._request(method, "/repos/acme/project/value", payload={"value": "exact"})
    _assert_retired(body, error, calls, failure, method)


@pytest.mark.parametrize("code", [403, 409, 422])
def test_existing_get_retirement_survives_outer_mapping(monkeypatch, code):
    body, error, calls, opener = _failure(code)
    monkeypatch.setattr(ci_github_api, "open_download", opener)
    client = GitHubAPI(token="fixture-token")
    with pytest.raises(GitHubAPIError) as failure:
        client._request("GET", "/repos/acme/project/value")
    _assert_retired(body, error, calls, failure, "GET")


@pytest.mark.parametrize("code", [403, 404, 503])
def test_protection_get_retires_error_before_translation(monkeypatch, code):
    body, error, calls, opener = _failure(code)
    monkeypatch.setattr(protection_inspection_client, "_open_inspection", opener)
    client = ProtectionInspectionClient(token="fixture-token", repository="acme/project",
        repository_id=1, installation_id=2, observed_installation_id=2)
    with pytest.raises(GitHubAPIError) as failure:
        client._request("GET", "/repos/acme/project")
    _assert_retired(body, error, calls, failure, "GET")


@pytest.mark.parametrize("kind", ["release", "evidence"])
@pytest.mark.parametrize("code", [409, 422, 503])
def test_asset_post_retires_error_without_retry(monkeypatch, tmp_path, kind, code):
    body, error, calls, opener = _failure(code)
    url = "https://uploads.github.com/repos/acme/project/releases/1/assets"
    if kind == "release":
        monkeypatch.setattr(ci_github_api, "open_download", opener)
        client = GitHubAPI(token="fixture-token")
        with pytest.raises(GitHubAPIError) as failure:
            client._upload_bytes(url, payload=b"exact", media_type="application/octet-stream")
    else:
        monkeypatch.setattr(evidence_storage_github_api, "open_download", opener)
        client = GitHubEvidenceAPI(token="fixture-token")
        source = tmp_path / "evidence.bin"
        source.write_bytes(b"exact")
        with pytest.raises(GitHubAPIError) as failure:
            client.upload_evidence_asset(upload_url=url, repository="acme/project",
                release_id=1, name="evidence.bin", path=source, maximum_bytes=5)
    _assert_retired(body, error, calls, failure, "POST")
