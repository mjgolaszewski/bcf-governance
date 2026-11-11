"""Source observations must bind the explicit repository, not ambient Git state."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling import semantic_source_paths as source
from bcf_governance.tooling.governance_validation import preflight_repository_context as preflight

ROOT_BYTES = b'raise AssertionError("source must remain data")\n'


def _git(root, *args):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
        cwd=root, env=environment, check=True, capture_output=True,
    ).stdout.decode().strip()


@pytest.fixture
def repositories(tmp_path):
    active = tmp_path / "active"
    foreign = tmp_path / "foreign"
    for root in (active, foreign):
        root.mkdir()
        _git(root, "init", "-q")
        _git(root, "config", "user.name", "Source Context")
        _git(root, "config", "user.email", "source-context@example.invalid")
    (active / "root.py").write_bytes(ROOT_BYTES)
    (active / "foreign.py").write_text("ACTIVE = True\n")
    (active / ".gitignore").write_text("root.py\n")
    _git(active, "add", "-f", "root.py", "foreign.py", ".gitignore")
    _git(active, "commit", "-qm", "active source")
    (foreign / "foreign.py").write_text("FOREIGN = True\n")
    _git(foreign, "add", ".")
    _git(foreign, "commit", "-qm", "foreign source")
    config = tmp_path / "ambient.gitconfig"
    config.write_text("[core]\n    worktree = " + str(foreign) + "\n")
    identity = {
        "commit_sha": _git(active, "rev-parse", "HEAD"),
        "tree_sha": _git(active, "rev-parse", "HEAD^{tree}"),
    }
    expected_blobs = tuple(
        (name, "100644", _git(active, "rev-parse", "HEAD:" + name))
        for name in ("foreign.py", "root.py")
    )
    preserved = {
        path: path.read_bytes()
        for root in (active, foreign)
        for path in (root / ".git/config", root / ".git/index")
    }
    return active, foreign, config, identity, expected_blobs, preserved


def _redirect(monkeypatch, kind, foreign, config):
    changes = {}
    if kind == "none":
        return changes
    if kind == "config-injection":
        changes = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.worktree",
            "GIT_CONFIG_VALUE_0": str(foreign),
        }
    else:
        changes[kind] = {
            "GIT_DIR": str(foreign / ".git"),
            "GIT_COMMON_DIR": str(foreign / ".git"),
            "GIT_WORK_TREE": str(foreign),
            "GIT_INDEX_FILE": str(foreign / ".git/index"),
            "GIT_OBJECT_DIRECTORY": str(foreign / ".git/objects"),
            "GIT_CONFIG_GLOBAL": str(config),
            "GIT_AUTHOR_NAME": "Ambient Author Must Not Select Source",
        }[kind]
    for name, value in changes.items():
        monkeypatch.setenv(name, value)
    return changes


@pytest.mark.parametrize("kind", [
    "none", "GIT_AUTHOR_NAME", "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE",
    "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "config-injection", "GIT_CONFIG_GLOBAL",
])
@pytest.mark.parametrize("consumer", [
    "candidate-paths", "committed-population", "committed-blob",
    "preflight-tracked", "preflight-subject",
])
def test_source_reads_bind_explicit_repository(repositories, monkeypatch, kind, consumer):
    active, foreign, config, identity, expected_blobs, preserved = repositories
    changes = _redirect(monkeypatch, kind, foreign, config)
    if consumer == "candidate-paths":
        observed = source.candidate_source_files(
            active, ("*.py",), label="Python", error=ValueError,
        )
        assert observed == [active / "foreign.py", active / "root.py"], (
            "ambient Git context changed the active source population"
        )
    elif consumer == "committed-population":
        observed = source.committed_python_source_population(active, **identity)
        assert observed["python_blobs"] == expected_blobs
        assert observed["subject"] == identity and observed["authority"] is False
    elif consumer == "committed-blob":
        _capture, observed = source.committed_regular_blob_capture(
            active, **identity, path="root.py",
        )
        assert observed == ROOT_BYTES
    elif consumer == "preflight-tracked":
        assert preflight.tracked_files(active) == [
            active / ".gitignore", active / "foreign.py", active / "root.py",
        ], "preflight accepted another repository's tracked population"
    else:
        assert preflight.git_state(active) == {
            **identity, "status_porcelain_sha256": hashlib.sha256(b"").hexdigest(),
        }, "preflight bound its subject to ambient repository state"
    assert {name: os.environ[name] for name in changes} == changes, (
        "source read mutated the caller's environment"
    )
    assert {path: path.read_bytes() for path in preserved} == preserved, (
        "source read mutated repository configuration or index bytes"
    )


@pytest.mark.parametrize("consumer", ["preflight", "committed-source"])
def test_source_tree_identity_ignores_local_replacement(repositories, consumer):
    import shutil

    active, foreign, _config, identity, expected_blobs, preserved = repositories
    # Supply actual foreign Git objects without a provider or network operation.
    shutil.copytree(foreign / ".git/objects", active / ".git/objects", dirs_exist_ok=True)
    foreign_commit = _git(foreign, "rev-parse", "HEAD")
    _git(active, "replace", identity["commit_sha"], foreign_commit)
    if consumer == "preflight":
        assert preflight.git_value(active, "rev-parse", "HEAD^{tree}") == identity["tree_sha"], (
            "local replacement changed the tree bound to an exact source commit"
        )
    else:
        observed = source.committed_python_source_population(active, **identity)
        assert observed["python_blobs"] == expected_blobs
    assert {path: path.read_bytes() for path in preserved} == preserved

