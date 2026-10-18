"""Read-only, exact Git-tree custody for main-side closure recomputation."""

from __future__ import annotations

import pytest

import base64
import subprocess

from bcf_governance.tooling.ci_github_api import GitHubAPI, GitHubAPIError


TREE = "a" * 40


def _content_response(raw: bytes) -> dict:
    oid = subprocess.check_output(["git", "hash-object", "--stdin"], input=raw).decode().strip()
    encoded = base64.b64encode(raw).decode()
    return {
        "type": "file", "path": "plans/build-plan.yml", "sha": oid,
        "encoding": "base64", "content": "\n".join(encoded[i:i + 16] for i in range(0, len(encoded), 16)),
    }


@pytest.mark.parametrize("raw", [b"", b"active: true\n", b"\x00\xff\xfe\r\n\x80"])
def test_content_preserves_exact_git_blob_bytes_and_read_only_request(monkeypatch, raw):
    response = _content_response(raw)
    api = GitHubAPI(token="fake")
    observed = []

    def request(method, path, **kwargs):
        observed.append((method, path, kwargs))
        return response

    monkeypatch.setattr(api, "_request", request)
    content = api.content("owner/repo", "plans/build-plan.yml", ref=TREE)
    assert (content.path, content.blob_oid, content.content) == (
        response["path"], response["sha"], raw,
    )
    assert observed == [("GET", f"/repos/owner/repo/contents/plans/build-plan.yml?ref={TREE}", {})]


@pytest.mark.parametrize("observed_path", [None, "plans/other.yml", "../plans/build-plan.yml", 1])
def test_content_rejects_missing_or_contradictory_observed_path(monkeypatch, observed_path):
    response = _content_response(b"active: true\n")
    if observed_path is None:
        response.pop("path")
    else:
        response["path"] = observed_path
    api = GitHubAPI(token="fake")
    monkeypatch.setattr(api, "_request", lambda *args, **kwargs: response)
    with pytest.raises(GitHubAPIError, match="path"):
        api.content("owner/repo", "plans/build-plan.yml", ref=TREE)


@pytest.mark.parametrize("substitution", ["bytes", "oid"])
def test_content_rejects_bytes_and_declared_blob_identity_disagreement(monkeypatch, substitution):
    response = _content_response(b"active: true\n")
    replacement = _content_response(b"active: false\n")
    field = "content" if substitution == "bytes" else "sha"
    response[field] = replacement[field]
    api = GitHubAPI(token="fake")
    monkeypatch.setattr(api, "_request", lambda *args, **kwargs: response)
    with pytest.raises(GitHubAPIError, match="blob"):
        api.content("owner/repo", "plans/build-plan.yml", ref=TREE)


@pytest.mark.parametrize("field,value,reason", [
    ("type", "dir", "file"), ("encoding", "none", "base64"),
    ("content", "%%%", "base64"), ("sha", "not-a-sha", "SHA"),
])
def test_content_preserves_existing_malformed_response_rejection(monkeypatch, field, value, reason):
    response = _content_response(b"active: true\n")
    response[field] = value
    api = GitHubAPI(token="fake")
    monkeypatch.setattr(api, "_request", lambda *args, **kwargs: response)
    with pytest.raises(GitHubAPIError, match=reason):
        api.content("owner/repo", "plans/build-plan.yml", ref=TREE)


def _response() -> dict:
    return {
        "sha": TREE, "truncated": False,
        "tree": [
            {"path": "src/a.py", "type": "blob", "sha": "b" * 40},
            {"path": "src", "type": "tree", "sha": "c" * 40},
            {"path": "governance/gate-contracts.yml", "type": "blob", "sha": "d" * 40},
        ],
    }


def test_complete_tree_reads_only_exact_provider_blob_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    api = GitHubAPI(token="fake")
    observed = []

    def request(method: str, path: str, **_kwargs: object) -> dict:
        observed.append((method, path))
        return _response()

    monkeypatch.setattr(api, "_request", request)
    assert api.complete_tree("owner/repo", TREE) == (
        ("governance/gate-contracts.yml", "d" * 40), ("src/a.py", "b" * 40),
    )
    assert observed == [("GET", f"/repos/owner/repo/git/trees/{TREE}?recursive=1")]


@pytest.mark.parametrize("mutation", [
    lambda value: value.update({"truncated": True}),
    lambda value: value.update({"sha": "e" * 40}),
    lambda value: value["tree"].append(value["tree"][0]),
    lambda value: value["tree"][0].update({"path": "../escape"}),
    lambda value: value["tree"][0].update({"sha": "not-a-sha"}),
])
def test_complete_tree_rejects_incomplete_or_ambiguous_provider_state(
    monkeypatch: pytest.MonkeyPatch, mutation,
) -> None:
    value = _response()
    mutation(value)
    api = GitHubAPI(token="fake")
    monkeypatch.setattr(api, "_request", lambda *_args, **_kwargs: value)
    with pytest.raises(GitHubAPIError):
        api.complete_tree("owner/repo", TREE)


@pytest.mark.parametrize("mode", [None, "040000", "160000", "invalid", True])
def test_mode_preserving_tree_rejects_missing_or_invalid_blob_mode(monkeypatch, mode):
    value = _response()
    for row in value["tree"]:
        if row["type"] == "blob":
            row["mode"] = "100644"
    value["tree"][0]["mode"] = mode
    api = GitHubAPI(token="fake")
    monkeypatch.setattr(api, "_request", lambda *args, **kwargs: value)
    with pytest.raises(GitHubAPIError, match="mode"):
        api.complete_tree_with_modes("owner/repo", TREE)


def test_mode_preserving_tree_retains_actual_git_regular_and_symlink_modes(tmp_path, monkeypatch):
    import subprocess
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, text=True).strip()
    git("init", "-q")
    (tmp_path / "regular.yml").write_text("active: true\n")
    (tmp_path / "symlink.yml").symlink_to("regular.yml")
    git("add", ".")
    tree = git("write-tree")
    rows = []
    for line in git("ls-tree", "-r", tree).splitlines():
        metadata, path = line.split("\t")
        mode, kind, oid = metadata.split()
        rows.append({"path": path, "type": kind, "sha": oid, "mode": mode})
    api = GitHubAPI(token="fake")
    monkeypatch.setattr(api, "_request", lambda *args, **kwargs: {"sha": tree, "truncated": False, "tree": rows})
    assert api.complete_tree_with_modes("owner/repo", tree) == tuple(sorted(
        (row["path"], row["sha"], row["mode"]) for row in rows
    ))
    assert {row["mode"] for row in rows} == {"100644", "120000"}
    assert api.complete_tree("owner/repo", tree) == tuple(sorted((row["path"], row["sha"]) for row in rows))
