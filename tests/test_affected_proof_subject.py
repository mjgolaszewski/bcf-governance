"""Real Git subject changes cannot produce mislabeled reuse frontiers."""
import pytest

from bcf_governance.tooling import affected_proof_closure as owner
from bcf_governance.tooling.evidence_execution import EvidenceError
from test_affected_proof_closure import _git, _repo, _subject


def derive(root, model, current, prior):
    return owner.derive_affected_proof_set(root, model, ["app-valid"],
                                         current_subject=current, prior_subjects=prior)


def change(root):
    (root / "src/app.py").write_text("VALUE = 2\n")
    _git(root, "commit", "-qam", "change")


def test_matching_clean_subject_can_be_unaffected(tmp_path):
    root, commit, tree, model = _repo(tmp_path)
    assert derive(root, model, _subject(root), [(commit, tree)])["classifications"][0]["classification"] == "demonstrably_unaffected"


@pytest.mark.parametrize("field", ["commit_sha", "tree_sha"])
def test_forged_current_identity_refuses_before_classification(tmp_path, field):
    root, commit, tree, model = _repo(tmp_path)
    current = _subject(root)
    current[field] = "f" * 40
    with pytest.raises(EvidenceError, match="affected proof current subject"):
        derive(root, model, current, [(commit, tree)])


def test_moved_checkout_cannot_claim_another_commit_is_unaffected(tmp_path):
    root, commit, tree, model = _repo(tmp_path)
    change(root)
    current = _subject(root)
    _git(root, "checkout", "--detach", "-q", commit)
    with pytest.raises(EvidenceError, match="affected proof current subject"):
        derive(root, model, current, [(commit, tree)])


@pytest.mark.parametrize("state", ["unstaged", "staged", "untracked"])
def test_dirty_source_cannot_authorize_reuse(tmp_path, state):
    root, commit, tree, model = _repo(tmp_path)
    current = _subject(root)
    target = root / ("src/new.py" if state == "untracked" else "src/app.py")
    target.write_text("VALUE = 99\n")
    if state == "staged":
        _git(root, "add", "src/app.py")
    with pytest.raises(EvidenceError, match="affected proof current subject"):
        derive(root, model, current, [(commit, tree)])


def test_ignored_execution_evidence_does_not_invalidate_source_subject(tmp_path):
    root, _, _, model = _repo(tmp_path)
    (root / ".gitignore").write_text(".artifacts/\n")
    _git(root, "add", ".gitignore")
    _git(root, "commit", "-qm", "ignore owned evidence")
    current = _subject(root)
    (root / ".artifacts").mkdir()
    (root / ".artifacts/raw.json").write_text("{}")
    assert derive(root, model, current, [(current["commit_sha"], current["tree_sha"])])["classifications"][0]["classification"] == "demonstrably_unaffected"


def test_same_tree_different_commit_still_requires_exact_current_identity(tmp_path):
    root, commit, tree, model = _repo(tmp_path)
    current = _subject(root)
    _git(root, "commit", "--allow-empty", "-qm", "different commit same tree")
    assert _subject(root)["tree_sha"] == tree
    with pytest.raises(EvidenceError, match="affected proof current subject"):
        derive(root, model, current, [(commit, tree)])


def test_head_movement_during_derivation_refuses_a_completed_frontier(tmp_path, monkeypatch):
    root, commit, tree, model = _repo(tmp_path)
    change(root)
    current = _subject(root)
    def moved(_root):
        _git(root, "checkout", "--detach", "-q", commit)
        return []
    monkeypatch.setattr(owner, "_projection_rows", moved)
    with pytest.raises(EvidenceError, match="affected proof current subject"):
        derive(root, model, current, [(commit, tree)])


def test_source_movement_during_derivation_refuses_a_completed_frontier(tmp_path, monkeypatch):
    root, commit, tree, model = _repo(tmp_path)
    current = _subject(root)
    def moved(_root):
        (root / "src/app.py").write_text("VALUE = 99\n")
        return []
    monkeypatch.setattr(owner, "_projection_rows", moved)
    with pytest.raises(EvidenceError, match="affected proof current subject"):
        derive(root, model, current, [(commit, tree)])


@pytest.mark.parametrize("revision", ["HEAD", "HEAD^{tree}", ""])
def test_nonexact_prior_revision_expands_execution(tmp_path, revision):
    root, _, _, model = _repo(tmp_path)
    result = derive(root, model, _subject(root), [(revision, None)])
    assert result["classifications"][0]["classification"] == "ambiguous_requires_execution", "nonexact prior revision falsely unaffected"


def test_tree_substituted_for_prior_commit_expands_execution(tmp_path):
    root, _, tree, model = _repo(tmp_path)
    result = derive(root, model, _subject(root), [(tree, tree)])
    assert result["classifications"][0]["classification"] == "ambiguous_requires_execution", "tree object falsely accepted as prior commit"


def test_authenticated_transported_prior_tree_fallback_remains_usable(tmp_path):
    root, _, tree, model = _repo(tmp_path)
    result = derive(root, model, _subject(root), [("f" * 40, tree)])
    assert result["classifications"][0]["classification"] == "demonstrably_unaffected"


def test_contradictory_prior_commit_tree_retains_conservative_expansion(tmp_path):
    root, commit, _, model = _repo(tmp_path)
    change(root)
    current = _subject(root)
    result = derive(root, model, current, [(commit, current["tree_sha"])])
    assert result["classifications"][0]["classification"] == "ambiguous_requires_execution"
