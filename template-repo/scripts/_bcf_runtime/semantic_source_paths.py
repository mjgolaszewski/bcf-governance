"""Current candidate source-path discovery for semantic analysis."""

from __future__ import annotations

import subprocess
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any
from typing import Callable


def candidate_source_files(
    repo_root: Path,
    patterns: tuple[str, ...],
    *,
    label: str,
    error: Callable[[str], Exception],
    allow_empty: bool = False,
) -> list[Path]:
    """Return the Git-known files present in the proposed working tree."""
    result = subprocess.run(
        [
            "git", "ls-files", "-z", "--cached", "--others",
            "--exclude-standard", "--", *patterns,
        ],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise error(f"{label} discovery requires a Git worktree")
    files: set[Path] = set()
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = Path(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise error(f"candidate {label} path is not UTF-8") from exc
        if relative.is_absolute() or ".." in relative.parts:
            raise error(f"candidate {label} path escapes the repository")
        path = repo_root / relative
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file():
            raise error(
                f"candidate {label} source must be a regular file: "
                f"{relative.as_posix()}"
            )
        files.add(path)
    if not files and not allow_empty:
        raise error(f"{label} discovery returned zero files")
    return sorted(files)


def _exact_subject(subject: dict[str, str]) -> None:
    if set(subject) != {"commit_sha", "tree_sha"} or any(
        not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{40}", value) is None
        for value in subject.values()
    ):
        raise ValueError("source population requires exact commit and tree identities")


def _committed_git(repo_root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", *args], cwd=repo_root,
        capture_output=True, check=False,
    )
    if result.returncode:
        raise ValueError("cannot resolve exact committed source population")
    return result.stdout


def _validate_committed_subject(repo_root: Path, subject: dict[str, str]) -> None:
    _exact_subject(subject)
    commit_sha, tree_sha = subject["commit_sha"], subject["tree_sha"]
    if _committed_git(repo_root, "cat-file", "-t", commit_sha) != b"commit\n":
        raise ValueError("source subject must identify an exact commit object")
    actual_tree = _committed_git(repo_root, "rev-parse", f"{commit_sha}^{{tree}}")
    if actual_tree != (tree_sha + "\n").encode():
        raise ValueError("source subject commit and tree differ")


def committed_python_source_population(
    repo_root: Path, *, commit_sha: str, tree_sha: str,
) -> dict[str, Any]:
    """Observe all exact-tree Python blobs; caller authenticates repository/subject.

    No candidate source is evaluated. Git object identity is an observation, not
    provider authority or a complete interpretation of runtime effects.
    """
    subject = dict(commit_sha=commit_sha, tree_sha=tree_sha)
    _validate_committed_subject(repo_root, subject)
    raw = _committed_git(repo_root, "ls-tree", "-r", "-z", "--full-tree", tree_sha)
    if raw and not raw.endswith(b"\0"):
        raise ValueError("committed source tree records are malformed")
    blobs, unresolved = [], []
    paths: set[str] = set()
    for entry in raw.split(b"\0")[:-1]:
        if not entry:
            raise ValueError("committed source tree records are malformed")
        try:
            metadata, path_bytes = entry.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8")
        except (ValueError, UnicodeError) as exc:
            raise ValueError("committed source tree records are malformed") from exc
        relative = PurePosixPath(path)
        if (not path or path in paths or relative.is_absolute()
                or ".." in relative.parts or relative.as_posix() != path
                or re.fullmatch(r"[a-f0-9]{40}", oid) is None):
            raise ValueError("committed source tree path or object identity is invalid")
        paths.add(path)
        if (mode, kind) in {("120000", "blob"), ("160000", "commit")}:
            unresolved.append((path, mode, oid))
        elif (mode, kind) in {("100644", "blob"), ("100755", "blob")}:
            if path.endswith(".py"):
                blobs.append((path, mode, oid))
        else:
            raise ValueError("committed source tree entry kind is unsupported")
    return dict(authority=False, execution_qualified=False, subject=subject,
                scope="all_python_blobs_in_exact_git_tree",
                python_blobs=tuple(sorted(blobs)), unresolved_entries=tuple(sorted(unresolved)))


def committed_python_source_delta(
    repo_root: Path, *, base: dict[str, str], candidate: dict[str, str],
) -> dict[str, Any]:
    """Retain removals and unresolved entries; never authorize their retirement."""
    if not isinstance(base, dict) or not isinstance(candidate, dict):
        raise ValueError("source population delta requires exact subject mappings")
    _exact_subject(base)
    _exact_subject(candidate)
    before = committed_python_source_population(repo_root, **base)
    after = committed_python_source_population(repo_root, **candidate)
    previous = {row[0]: row[1:] for row in before["python_blobs"]}
    current = {row[0]: row[1:] for row in after["python_blobs"]}
    return dict(authority=False, execution_qualified=False, base=before, candidate=after,
                added=tuple(sorted(current.keys() - previous.keys())),
                removed=tuple(sorted(previous.keys() - current.keys())),
                changed=tuple(sorted(path for path in previous.keys() & current.keys()
                                     if previous[path] != current[path])),
                unresolved_changed=before["unresolved_entries"] != after["unresolved_entries"])


def _capture_committed_regular_blob(
    repo_root: Path, *, commit_sha: str, tree_sha: str, path: str, label: str,
) -> tuple[dict[str, Any], bytes]:
    if (not isinstance(path, str) or not path or "\\" in path or "\0" in path
            or PurePosixPath(path).is_absolute()
            or any(part in {"", ".", ".."} for part in path.split("/"))):
        raise ValueError("committed source path must be canonical and repository relative")
    try:
        path.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("committed source path is not UTF-8") from exc
    subject = dict(commit_sha=commit_sha, tree_sha=tree_sha)
    _validate_committed_subject(repo_root, subject)
    record = _committed_git(repo_root, "--literal-pathspecs", "ls-tree", "-z", "--full-tree", tree_sha, "--", path)
    try:
        entry, terminator = record.split(b"\0")
        metadata, actual_path = entry.split(b"\t")
        mode, kind, oid = metadata.decode("ascii").split()
        if (terminator or actual_path != path.encode()
                or mode not in {"100644", "100755"} or kind != "blob"
                or re.fullmatch(r"[a-f0-9]{40}", oid) is None):
            raise ValueError("invalid record")
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"{label} must be one regular blob") from exc
    raw = _committed_git(repo_root, "cat-file", "blob", oid)
    if hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest() != oid:
        raise ValueError(f"{label} blob identity differs")
    return dict(authority=False, execution_qualified=False, subject=subject,
                path=path, blob_oid=oid, sha256=hashlib.sha256(raw).hexdigest()), raw



def committed_regular_blob_capture(
    repo_root: Path, *, commit_sha: str, tree_sha: str, path: str,
) -> tuple[dict[str, Any], bytes]:
    """Capture exact regular source bytes; caller authenticates repository/subject."""
    return _capture_committed_regular_blob(
        repo_root, commit_sha=commit_sha, tree_sha=tree_sha, path=path, label="committed source",
    )


def committed_application_registry_identity(
    repo_root: Path, *, commit_sha: str, tree_sha: str,
) -> dict[str, Any]:
    """Observe fixed consumer policy bytes; caller authenticates the subject."""
    identity, _ = _capture_committed_regular_blob(
        repo_root, commit_sha=commit_sha, tree_sha=tree_sha,
        path="governance/application-operations.yml", label="committed application policy",
    )
    identity["registry_sha256"] = identity.pop("sha256")
    return identity
