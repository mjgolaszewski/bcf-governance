"""Exact protected phase policy must belong to its authenticated Git tree."""
import hashlib
import os
import posixpath
import subprocess

import pytest
import yaml

from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.trusted_inputs import verify_required_phase_closure_inputs

PATHS = ("plans/build-plan.yml", "plans/phase-ledger.yml", "plans/phase-history.yml")


def _oid(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


class PolicySource:
    def __init__(self, root):
        self.root = root
        self.head = self.git("rev-parse", "HEAD").decode().strip()
        self.content_reads = []
        self.inventory_reads = []
        self.artifact_reads = 0
        self.substitute = None

    def git(self, *args, check=True):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
             "-c", "gc.auto=0", "-c", "maintenance.auto=false",
             "-C", str(self.root), *args],
            env=env, capture_output=True, check=check, timeout=20,
        )
        return result.stdout

    def repository(self, repository):
        assert repository == "owner/repo"
        return {"id": 42, "full_name": repository, "default_branch": "main"}

    def reference(self, repository, ref):
        assert repository == "owner/repo" and ref == "heads/main"
        return {"object": {"type": "commit", "sha": self.head}}

    def commit(self, repository, sha):
        assert repository == "owner/repo"
        commit, tree = self.git("show", "-s", "--format=%H %T", sha).decode().split()
        return {"sha": commit, "tree": {"sha": tree}}

    def compare_commits(self, repository, *, base, head):
        assert repository == "owner/repo"
        ancestor = self.git("merge-base", base, head).decode().strip()
        return {
            "status": "identical" if base == head else "ahead" if ancestor == base else "diverged",
            "base_commit": {"sha": base}, "merge_base_commit": {"sha": ancestor},
        }

    def complete_tree_with_modes(self, repository, tree):
        assert repository == "owner/repo"
        self.inventory_reads.append(tree)
        rows = []
        for raw in self.git("ls-tree", "-r", "-z", tree).split(b"\0"):
            if not raw:
                continue
            meta, path = raw.split(b"\t", 1)
            mode, kind, oid = meta.decode().split()
            assert kind == "blob"
            rows.append((path.decode(), oid, mode))
        return tuple(rows)

    def content(self, repository, path, *, ref):
        assert repository == "owner/repo"
        self.content_reads.append((path, ref))
        meta = self.git("ls-tree", ref, "--", path).decode().split("\t", 1)[0].split()
        mode, _, oid = meta
        raw = self.git("show", ref + ":" + path)
        if mode == "120000":
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), raw.decode()))
            assert not target.startswith(("/", "../"))
            raw = self.git("show", ref + ":" + target)
            oid = _oid(raw)
        if self.substitute == path:
            raw += b"\n# self-consistent bytes from another blob\n"
            oid = _oid(raw)
        assert _oid(raw) == oid
        return GitHubContent(path=path, blob_oid=oid, content=raw)

    def artifact_bytes(self, *args, **kwargs):
        self.artifact_reads += 1
        raise AssertionError("policy-source rejection must precede proof download")


def _source(tmp_path, *, mode="100644", symlink=None, oversized=False):
    root = tmp_path / "policy"
    root.mkdir()
    api = PolicySource.__new__(PolicySource)
    api.root = root
    api.git("init", "--quiet", "--initial-branch=main", "--object-format=sha1")
    docs = (
        {"phase_sequence": [{"phase_id": "P32", "hard_dependencies": []}]},
        {"active_phase": {"id": "P32"}},
        {"entries": []},
    )
    for path, doc in zip(PATHS, docs, strict=True):
        raw = yaml.safe_dump(doc).encode()
        if oversized:
            raw += (b"#" + b"x" * 898 + b"\n") * 1000
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if symlink == path:
            real = root / "policy-data" / target.name
            real.parent.mkdir(exist_ok=True)
            real.write_bytes(raw)
            target.symlink_to("../policy-data/" + target.name)
        else:
            target.write_bytes(raw)
            target.chmod(0o755 if mode == "100755" else 0o644)
    api.git("-c", "core.filemode=true", "add", ".")
    api.git("-c", "user.name=Policy Fixture", "-c", "user.email=policy@example.test",
            "commit", "--quiet", "-m", "exact protected lifecycle data")
    for path in PATHS:
        observed = api.git("ls-tree", "HEAD", "--", path).decode().split()[0]
        assert observed == ("120000" if symlink == path else mode)
    return PolicySource(root)


@pytest.mark.parametrize("mode", ["100644", "100755"])
def test_regular_exact_policy_source_retains_empty_predecessor_result(tmp_path, mode):
    api = _source(tmp_path, mode=mode)
    selected, proofs = verify_required_phase_closure_inputs(
        api, repository="owner/repo", phase_id="P32",
    )
    assert selected.checkout_sha == api.head and proofs == {}
    assert len(api.content_reads) == 3 and api.artifact_reads == 0


@pytest.mark.parametrize("path", PATHS)
def test_self_consistent_wrong_tree_policy_blob_rejects_before_proof(tmp_path, path):
    api = _source(tmp_path)
    api.substitute = path
    with pytest.raises(GitHubControllerError, match="(blob|exact|source)"):
        verify_required_phase_closure_inputs(api, repository="owner/repo", phase_id="P32")
    assert api.artifact_reads == 0


@pytest.mark.parametrize("path", PATHS)
def test_nonregular_policy_tree_cannot_borrow_regular_content(tmp_path, path):
    api = _source(tmp_path, symlink=path)
    with pytest.raises(GitHubControllerError, match="regular"):
        verify_required_phase_closure_inputs(api, repository="owner/repo", phase_id="P32")
    assert api.artifact_reads == 0


def test_policy_source_total_budget_rejects_before_proof(tmp_path):
    api = _source(tmp_path, oversized=True)
    with pytest.raises(GitHubControllerError, match="bounded input"):
        verify_required_phase_closure_inputs(api, repository="owner/repo", phase_id="P32")
    assert api.artifact_reads == 0

def test_missing_inventory_capability_rejects_before_policy_consumption(tmp_path):
    api = _source(tmp_path)
    api.complete_tree_with_modes = None
    api.repository = lambda *args: pytest.fail("missing inventory allocated provider identity")
    with pytest.raises(GitHubControllerError, match="inventory"):
        verify_required_phase_closure_inputs(api, repository="owner/repo", phase_id="P32")
    assert api.content_reads == [] and api.artifact_reads == 0


def test_malformed_inventory_rejects_before_policy_consumption(tmp_path):
    api = _source(tmp_path)
    api.complete_tree_with_modes = lambda repository, tree: None
    with pytest.raises(GitHubControllerError, match="inventory"):
        verify_required_phase_closure_inputs(api, repository="owner/repo", phase_id="P32")
    assert api.content_reads == [] and api.artifact_reads == 0
