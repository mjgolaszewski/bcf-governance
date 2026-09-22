"""Provider-read main closure must equal canonical local Git-tree closure."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import GitHubControllerError, MainIdentity
from bcf_governance.tooling.evidence_planning import build_dependency_manifest
from bcf_governance.tooling.provider_reuse_closure import trusted_main_claim_context


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "governance/gate-contracts.yml"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


class Provider:
    def __init__(self) -> None:
        self.main = MainIdentity(
            repository_id="1207503211", default_branch="main",
            checkout_sha=_git("rev-parse", "HEAD"), tree_sha=_git("rev-parse", "HEAD^{tree}"),
        )
        self.entries = tuple(
            (line.split("\t", 1)[1], line.split("\t", 1)[0].split()[2])
            for line in _git("ls-tree", "-r", "--full-tree", "HEAD").splitlines()
        )
        self.content_bytes = (ROOT / CONTRACT).read_bytes()
        self.commit_tree = self.main.tree_sha
        self.blob_oid = dict(self.entries)[CONTRACT]

    def commit(self, repository: str, sha: str) -> dict:
        assert (repository, sha) == ("owner/repo", self.main.checkout_sha)
        return {"tree": {"sha": self.commit_tree}}

    def complete_tree(self, repository: str, sha: str) -> tuple[tuple[str, str], ...]:
        assert (repository, sha) == ("owner/repo", self.main.tree_sha)
        return self.entries

    def content(self, repository: str, path: str, *, ref: str) -> GitHubContent:
        assert (repository, path, ref) == ("owner/repo", CONTRACT, self.main.checkout_sha)
        return GitHubContent(path=path, blob_oid=self.blob_oid, content=self.content_bytes)


def test_provider_read_claim_closure_matches_canonical_local_tree() -> None:
    provider = Provider()
    _, entries, manifest = trusted_main_claim_context(
        provider, "owner/repo", provider.main, ["runtime-smoke"], repo_root=ROOT,
    )
    assert entries == provider.entries
    assert manifest == build_dependency_manifest(ROOT, ["runtime-smoke"])


@pytest.mark.parametrize("mutation", ["commit_tree", "blob_oid", "content_bytes"])
def test_provider_read_claim_closure_rejects_mismatched_main_bytes(mutation: str) -> None:
    provider = Provider()
    if mutation == "content_bytes":
        provider.content_bytes += b"\n# changed"
    else:
        setattr(provider, mutation, "0" * 40)
    with pytest.raises(GitHubControllerError):
        trusted_main_claim_context(
            provider, "owner/repo", provider.main, ["runtime-smoke"], repo_root=ROOT,
        )
