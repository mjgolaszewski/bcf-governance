"""Real Git/filesystem oracles for the existing exact-source owner."""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from bcf_governance.tooling import ci_controller_builder as owner


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True,
                            capture_output=True, text=True, timeout=30)
    return result.stdout.strip()


@pytest.fixture
def case(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.name", "Custody Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    (repo / ".gitignore").write_text("build/\n.artifacts/\n", encoding="utf-8")
    (repo / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "fixture")
    owned = tmp_path / "owned"
    owned.mkdir()
    original = owner.tempfile.mkdtemp
    parents = []

    def allocate(*, prefix):
        value = Path(original(prefix=prefix, dir=owned)).resolve()
        parents.append(value)
        return str(value)

    monkeypatch.setattr(owner.tempfile, "mkdtemp", allocate)
    return repo, owned, parents


def retained(parent: Path):
    source, intent = parent / "source", parent / "intent.json"
    assert source.is_dir(), "unresolved checkout must remain"
    assert intent.is_file(), "unresolved durable intent must remain"
    record = json.loads(intent.read_text(encoding="utf-8"))
    assert record["source"] == str(source)
    assert record["repo"] and len(record["subject"]) == 2
    assert source.is_dir()
    marker = (source / ".git").read_text(encoding="utf-8")
    assert marker.startswith("gitdir: ")
    admin = Path(marker[8:].strip())
    assert admin.is_dir()
    assert (admin / "gitdir").read_text().strip() == str(source / ".git")
    return source, intent, admin


def intercept(monkeypatch, action, behavior):
    native = owner.subprocess.run
    seen = []

    def call(argv, **kwargs):
        if "worktree" in argv and action in argv:
            seen.append(list(argv))
            return behavior(native, argv, kwargs)
        return native(argv, **kwargs)

    monkeypatch.setattr(owner.subprocess, "run", call)
    return seen


def test_successful_exact_checkout_and_verified_retirement(case, monkeypatch):
    repo, _, parents = case
    synced = []
    native_sync, native_git = owner.os.fsync, owner._exact_git

    def fsync(descriptor):
        value = os.fstat(descriptor)
        native_sync(descriptor)
        synced.append((value.st_dev, value.st_ino))

    def checked_git(root, *args):
        if args[:2] == ('worktree', 'add'):
            parent = Path(args[-2]).parent
            positions = []
            for path in [parent / 'intent.json', parent, parent.parent]:
                value = path.stat()
                assert (value.st_dev, value.st_ino) in synced, 'intent bytes and directory must be fsynced before native add'
                positions.append(synced.index((value.st_dev, value.st_ino)))
            assert positions[0] < positions[1] < positions[2], 'intent file, parent and parent namespace must become durable in order'
        return native_git(root, *args)

    monkeypatch.setattr(owner.os, 'fsync', fsync)
    monkeypatch.setattr(owner, '_exact_git', checked_git)
    head = git(repo, "rev-parse", "HEAD")
    with owner.exact_head_source(repo) as source:
        assert (source / "source.py").read_text() == "VALUE = 1\n"
        _, intent, admin = retained(source.parent)
        assert json.loads(intent.read_bytes())["subject"][0] == head
    assert not source.exists()
    assert not admin.exists()
    assert not parents[-1].exists()
    assert git(repo, "rev-parse", "HEAD") == head


def test_body_failure_retires_and_preserves_original_failure(case, monkeypatch):
    repo, owned, parents = case
    primary = RuntimeError("body sentinel")
    with pytest.raises(RuntimeError) as caught:
        with owner.exact_head_source(repo):
            raise primary
    assert caught.value is primary
    assert not parents[-1].exists()
    native_sync = owner._exact_sync
    owner_namespace_syncs = 0

    def fail_final_namespace_sync(path):
        nonlocal owner_namespace_syncs
        if path == owned:
            owner_namespace_syncs += 1
            if owner_namespace_syncs == 2:
                raise OSError("final retirement namespace sentinel")
        native_sync(path)

    monkeypatch.setattr(owner, "_exact_sync", fail_final_namespace_sync)
    with pytest.raises(owner.TrustedControllerBuildError) as late:
        with owner.exact_head_source(repo):
            raise primary
    assert late.value.__cause__ is primary
    assert isinstance(late.value.secondary_failure, OSError)
    assert late.value.recovery["source_admin_absence_verified"] is True
    assert late.value.recovery["source_admin_retirement_durable"] is True
    assert late.value.recovery["intent_unlinked"] is True
    assert late.value.recovery["parent_removed"] is True
    assert late.value.recovery_intent is None
    assert not parents[-1].exists()


def test_nonzero_remove_preserves_checkout_admin_and_intent(case, monkeypatch):
    repo, _, parents = case
    intercept(monkeypatch, "remove", lambda native, argv, kw: subprocess.CompletedProcess(argv, 7, "", "fixture"))
    with pytest.raises(owner.TrustedControllerBuildError):
        with owner.exact_head_source(repo):
            pass
    retained(parents[-1])


def test_remove_exception_preserves_checkout_admin_and_intent(case, monkeypatch):
    repo, _, parents = case

    def fail(native, argv, kwargs):
        raise OSError("removal sentinel")

    intercept(monkeypatch, "remove", fail)
    with pytest.raises(owner.TrustedControllerBuildError) as caught:
        with owner.exact_head_source(repo):
            pass
    assert isinstance(caught.value.__cause__, OSError)
    retained(parents[-1])


def test_false_success_with_residue_is_unresolved(case, monkeypatch):
    repo, _, parents = case
    intercept(monkeypatch, "remove", lambda native, argv, kw: subprocess.CompletedProcess(argv, 0, "", ""))
    with pytest.raises(owner.TrustedControllerBuildError):
        with owner.exact_head_source(repo):
            pass
    retained(parents[-1])


def test_accepted_add_callback_failure_preserves_registered_state(case, monkeypatch):
    repo, _, parents = case

    def fail(*args):
        raise RuntimeError("accepted callback sentinel")

    monkeypatch.setattr(owner, "_exact_link", fail)
    with pytest.raises(owner.TrustedControllerBuildError) as caught:
        with owner.exact_head_source(repo):
            pytest.fail("uncertain creation was yielded")
    assert isinstance(caught.value.__cause__, RuntimeError)
    retained(parents[-1])


def test_nonzero_add_after_real_mutation_preserves_state(case, monkeypatch):
    repo, _, parents = case

    def mutate_then_fail(native, argv, kwargs):
        actual = native(argv, **kwargs)
        assert actual.returncode == 0
        return subprocess.CompletedProcess(argv, 9, "", "accepted mutation sentinel")

    intercept(monkeypatch, "add", mutate_then_fail)
    with pytest.raises(owner.TrustedControllerBuildError):
        with owner.exact_head_source(repo):
            pytest.fail("uncertain creation was yielded")
    retained(parents[-1])


def test_add_exception_after_real_mutation_preserves_state(case, monkeypatch):
    repo, _, parents = case

    def mutate_then_raise(native, argv, kwargs):
        actual = native(argv, **kwargs)
        assert actual.returncode == 0
        raise OSError("accepted mutation sentinel")

    intercept(monkeypatch, "add", mutate_then_raise)
    with pytest.raises(owner.TrustedControllerBuildError) as caught:
        with owner.exact_head_source(repo):
            pytest.fail("uncertain creation was yielded")
    assert isinstance(caught.value.__cause__, OSError)
    retained(parents[-1])


def test_changed_admin_linkage_is_typed_block(case, monkeypatch):
    repo, _, parents = case
    seen = intercept(monkeypatch, "remove", lambda native, argv, kw: subprocess.CompletedProcess(argv, 17, "", "must not attempt removal after identity mismatch"))
    with pytest.raises(owner.TrustedControllerBuildError):
        with owner.exact_head_source(repo) as source:
            _, _, admin = retained(source.parent)
            moved = admin.with_name(admin.name + "-moved")
            admin.rename(moved)
    assert not seen, "administration mismatch must block before native removal"
    assert (parents[-1] / "source").is_dir()
    assert (parents[-1] / "intent.json").is_file()
    assert moved.is_dir()


def test_replaced_owned_parent_is_typed_block(case):
    repo, _, parents = case
    with pytest.raises(owner.TrustedControllerBuildError):
        with owner.exact_head_source(repo) as source:
            previous = source.parent
            moved = previous.with_name(previous.name + "-moved")
            previous.rename(moved)
            previous.mkdir()
            foreign = previous / "foreign"
            foreign.write_text("preserve", encoding="utf-8")
    assert foreign.read_text() == "preserve"
    assert (moved / "source/source.py").read_text() == "VALUE = 1\n"
    assert (moved / "intent.json").is_file()


def test_body_plus_cleanup_failure_retains_primary_cause(case, monkeypatch):
    repo, _, parents = case
    primary = RuntimeError("primary body sentinel")

    def fail(native, argv, kwargs):
        raise OSError("secondary removal sentinel")

    intercept(monkeypatch, "remove", fail)
    with pytest.raises(owner.TrustedControllerBuildError) as caught:
        with owner.exact_head_source(repo):
            raise primary
    assert caught.value.__cause__ is primary
    assert isinstance(caught.value.secondary_failure, OSError)
    assert caught.value.stage == "retirement"
    assert caught.value.recovery["source_admin_absence_verified"] is False
    assert Path(caught.value.recovery["parent"]) == parents[-1]
    assert Path(caught.value.recovery["source"]) == parents[-1] / "source"
    assert caught.value.recovery["admin"] is not None
    assert any("OSError" in note for note in caught.value.__notes__)
    retained(parents[-1])


def test_duplicate_retirement_cannot_delete_foreign_state(case):
    repo, _, parents = case
    manager = owner.exact_head_source(repo)
    manager.__enter__()
    manager.__exit__(None, None, None)
    parent = parents[-1]
    parent.mkdir()
    foreign = parent / "foreign"
    foreign.write_text("preserve", encoding="utf-8")
    manager.__exit__(None, None, None)
    assert foreign.read_text() == "preserve"


def test_forced_interruption_leaves_durable_reconciliation_intent(case, monkeypatch):
    repo, owned, _ = case
    assert hasattr(os, "fork"), "this qualification requires a declared fork-capable profile"
    child = os.fork()
    if child == 0:
        try:
            with owner.exact_head_source(repo):
                os._exit(77)
        except BaseException:
            os._exit(78)
    deadline = time.monotonic() + 30
    status = None
    try:
        while time.monotonic() < deadline:
            waited, value = os.waitpid(child, os.WNOHANG)
            if waited:
                status = value
                break
            time.sleep(0.01)
        assert status is not None, "interruption child did not finish within qualification bound"
    finally:
        if status is None:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    parents = list(owned.iterdir())
    assert len(parents) == 1
    retained(parents[0])
    native_sync = owner._exact_sync

    def fail_parent_namespace(path):
        if path == owned:
            raise OSError("namespace durability sentinel")
        native_sync(path)

    seen = intercept(monkeypatch, "add", lambda native, argv, kw: native(argv, **kw))
    monkeypatch.setattr(owner, "_exact_sync", fail_parent_namespace)
    with pytest.raises(owner.TrustedControllerBuildError) as caught:
        with owner.exact_head_source(repo):
            pytest.fail("namespace durability failure must block before native add")
    assert not seen
    assert caught.value.recovery["mutation_may_have_started"] is False
    assert caught.value.recovery_intent.is_file()
    assert not Path(caught.value.recovery["source"]).exists()


def test_controller_build_consumes_maintained_owner(case, monkeypatch):
    repo, _, parents = case
    (repo / "bcf_governance").mkdir()
    (repo / "bcf_governance/cli.py").write_text("", encoding="utf-8")
    (repo / "ci_controller_builder.py").write_text("raise RuntimeError('candidate evaluator ran')\n")
    (repo / "pyproject.toml").write_text(
        '[project]\nname="fixture"\nversion="1"\ndependencies=["PyYAML>=6.0,<7"]\n')
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "source-build fixture")
    observed = []
    output = repo / ".artifacts/controller"
    wheel = output / "fixture.whl"

    def run(root, argv, **kwargs):
        if "build" in argv:
            observed.append(root)
            assert root != repo and root.parent in parents
            assert (root / "source.py").read_text() == "VALUE = 1\n"
            wheel.write_bytes(b"fixture wheel; inventory/install are mocked in this wiring oracle")

    monkeypatch.setattr(owner, "_run", run)
    monkeypatch.setattr(owner, "verify_controller_inventory", lambda path: (wheel, None))
    monkeypatch.setattr(owner, "_verify_offline_install", lambda *args: None)
    value = owner.build(repo, output, run_id="1", run_attempt="1")
    assert len(observed) == 1
    assert value["commit_sha"] == git(repo, "rev-parse", "HEAD")
    assert not observed[0].exists()


def test_private_runtime_projection_matches_canonical_owner():
    root = Path(__file__).resolve().parents[1]
    canonical = (root / "bcf_governance/tooling/ci_controller_builder.py").read_bytes()
    for prefix in ["template-repo", "bcf_governance/pack/template-repo"]:
        assert (root / prefix / "scripts/_bcf_runtime/ci_controller_builder.py").read_bytes() == canonical


def test_retained_anchor_source_history_and_shared_objects_preserved(case):
    repo, owned, _ = case
    peer = owned / "peer"
    git(repo, "worktree", "add", "--quiet", "--detach", str(peer), "HEAD")
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    before = {p.relative_to(common).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in (common / "objects").rglob("*") if p.is_file()}
    subject = git(repo, "rev-parse", "HEAD")
    refs = git(repo, "show-ref")
    with owner.exact_head_source(repo):
        assert git(peer, "rev-parse", "HEAD") == subject
    after = {p.relative_to(common).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (common / "objects").rglob("*") if p.is_file()}
    assert after == before
    assert git(repo, "show-ref") == refs
    assert git(repo, "rev-parse", "HEAD") == subject
    assert (peer / "source.py").read_text() == "VALUE = 1\n"


def test_exact_git_uses_fresh_injected_child_environment(tmp_path, monkeypatch):
    from bcf_governance.tooling.bootstrap.environment import child_process_environment

    values = {"PATH": "/fixture", "EMPTY": "", "GIT_OPTIONAL_LOCKS": "1"}
    port = child_process_environment(values)
    observed = []

    def run(argv, **kwargs):
        observed.append(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, "subject\n", "")

    monkeypatch.setattr(owner.subprocess, "run", run)
    assert owner._exact_git(tmp_path, "rev-parse", "HEAD", process_environment=port) == "subject"
    values["EMPTY"] = "later"
    owner._exact_git(tmp_path, "rev-parse", "HEAD", process_environment=port)
    assert observed[0]["EMPTY"] == ""
    assert observed[1]["EMPTY"] == "later"
    assert all(value["GIT_OPTIONAL_LOCKS"] == "0" for value in observed)
    assert values["GIT_OPTIONAL_LOCKS"] == "1"
