"""Byte-budget errors precede filesystem and network allocation."""
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import ci_github_transport, evidence_storage_github_api
from bcf_governance.tooling.ci_github_api import GitHubAPIError
from bcf_governance.tooling.ci_github_downloads import GitHubDownloadKind


@pytest.mark.parametrize("limit", [True, False, 0, -1, 1.5, float("nan"), float("inf"), "30", None])
@pytest.mark.parametrize("consumer", ["transport", "asset", "action", "upload", "endpoint"])
def test_invalid_byte_limit_precedes_allocation(limit, consumer, tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid byte limit allocated a network or temporary resource")

    monkeypatch.setattr(evidence_storage_github_api, "open_download", forbidden)
    monkeypatch.setattr(evidence_storage_github_api, "tempfile", SimpleNamespace(mkstemp=forbidden))
    api = evidence_storage_github_api.GitHubEvidenceAPI(token="fixture-only")
    destination = tmp_path / "unallocated" / "asset.zip"
    error_type = ci_github_transport.GitHubTransportError if consumer == "transport" else GitHubAPIError
    with pytest.raises(error_type, match="limit"):
        if consumer == "transport":
            ci_github_transport.request_bytes(
                api_url="https://api.github.com", path="/fixture", token="fixture-only",
                kind=GitHubDownloadKind.RELEASE_ASSET, maximum_bytes=limit,
                opener=forbidden, observations=[],
            )
        elif consumer == "upload":
            api.upload_evidence_asset(
                upload_url="https://uploads.github.com/repos/example/repo/releases/1/assets",
                repository="example/repo", release_id=1, name="asset.zip",
                path=tmp_path / "absent-input.zip", maximum_bytes=limit,
            )
        elif consumer == "endpoint":
            api._download_endpoint(
                "/fixture", kind=GitHubDownloadKind.RELEASE_ASSET,
                destination=destination, maximum_bytes=limit,
            )
        else:
            method = api.download_evidence_asset if consumer == "asset" else api.download_action_artifact
            method("example/repo", 1, destination=destination, maximum_bytes=limit)
    assert not destination.parent.exists()
