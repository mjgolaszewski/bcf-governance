from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
try:
    from scripts.publish_audit import audit_history
finally:
    sys.path.pop(0)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "BCF Test")
    return repo


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)


def test_publish_audit_finds_deleted_secret_without_returning_its_value(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    path = repo / "config.py"
    path.write_text(f'token_secret = "{secret}"\n', encoding="utf-8")
    _commit(repo, "add config")
    path.unlink()
    _commit(repo, "remove config")

    findings = audit_history(repo)

    assert {finding.rule_id for finding in findings} >= {"github-token", "assigned-secret"}
    assert all(secret not in repr(finding) for finding in findings)
    assert {finding.path for finding in findings} == {"config.py"}


def test_publish_audit_finds_deleted_private_endpoint_and_deduplicates_blob(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    content = "endpoint: https://service.example.internal\n"
    (repo / "one.yml").write_text(content, encoding="utf-8")
    _commit(repo, "one")
    (repo / "two.yml").write_text(content, encoding="utf-8")
    _commit(repo, "same blob again")

    findings = [item for item in audit_history(repo) if item.rule_id == "internal-hostname"]

    assert len(findings) == 1


def test_publish_audit_ignores_reserved_domains_and_binary_blobs(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "config.yml").write_text(
        "one: https://service.example.invalid\ntwo: https://service.example.test\n",
        encoding="utf-8",
    )
    (repo / "image.bin").write_bytes(b"\0ghp_abcdefghijklmnopqrstuvwxyz123456")
    _commit(repo, "safe examples")

    assert audit_history(repo) == []


def test_publish_audit_rejects_shallow_history(tmp_path: Path) -> None:
    origin = _repo(tmp_path)
    (origin / "README.md").write_text("safe\n", encoding="utf-8")
    _commit(origin, "initial")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--depth", "1", f"file://{origin}", str(shallow)],
        check=True,
        capture_output=True,
    )

    with pytest.raises(RuntimeError, match="git fetch --unshallow --tags"):
        audit_history(shallow)
