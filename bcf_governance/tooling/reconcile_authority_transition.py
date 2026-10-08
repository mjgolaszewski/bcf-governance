"""Closed Git custody for reconcile operations that change trusted workflows."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable, Iterable, Protocol

import yaml

from .governance_install.transaction import copy_repository_shadow


class ReconcileAuthorityTransitionError(ValueError):
    """The workflow-definition/authority transition is ambiguous or unsafe."""


class Step(Protocol):
    step_id: str
    check: Callable[[], None]
    apply: Callable[[], None]
    apply_verifies: bool


@dataclass(frozen=True)
class ReconcileAuthorityTransitionResult:
    rounds: int
    definition_commit: str
    authority_commit: str


_SAFE_BRANCH = re.compile(r"(?!.*\.\.)(?!.*@\{)[A-Za-z0-9][A-Za-z0-9._/-]*")
_DEFINITION_MESSAGE = "chore(bcf): reconcile canonical workflow projection"
_AUTHORITY_MESSAGE = "chore(bcf): pin reconciled workflow authority"
_COMMITTER_NAME = "BCF Reconciler"
_COMMITTER_EMAIL = "bcf-reconciler@example.invalid"


def _git(
    root: Path,
    *args: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if check and result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
        raise ReconcileAuthorityTransitionError(
            f"Git custody operation failed ({' '.join(args)}): {detail or result.returncode}"
        )
    return result


def _text(root: Path, *args: str) -> str:
    return _git(root, *args).stdout.decode("utf-8").strip()


def _workflow_paths(root: Path) -> tuple[str, ...]:
    authority = root / "governance/ci-authority.yml"
    try:
        payload = yaml.safe_load(authority.read_text(encoding="utf-8"))
        registry = payload["workflow_registry"]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise ReconcileAuthorityTransitionError(
            "workflow-authority transition requires a readable canonical registry"
        ) from exc
    if not isinstance(registry, dict) or not registry:
        raise ReconcileAuthorityTransitionError(
            "workflow-authority transition requires a non-empty canonical registry"
        )
    paths = tuple(
        sorted(
            str(entry.get("active_path", ""))
            for entry in registry.values()
            if isinstance(entry, dict)
        )
    )
    if len(paths) != len(registry) or any(
        not value.startswith(".github/workflows/") or ".." in Path(value).parts
        for value in paths
    ):
        raise ReconcileAuthorityTransitionError(
            "workflow-authority registry contains an unsafe or incomplete active path"
        )
    return paths


def _bytes_at(root: Path, commit: str, relative: str) -> bytes:
    result = _git(root, "show", f"{commit}:{relative}", check=False)
    if result.returncode:
        raise ReconcileAuthorityTransitionError(
            f"workflow authority path is absent from {commit}: {relative}"
        )
    return result.stdout


def _reject_unexplained_workflow_drift(
    root: Path, shadow: Path, head: str, paths: Iterable[str]
) -> None:
    drift = [
        relative
        for relative in paths
        if not (root / relative).is_file()
        or (root / relative).read_bytes()
        not in {_bytes_at(root, head, relative), (shadow / relative).read_bytes()}
    ]
    if drift:
        raise ReconcileAuthorityTransitionError(
            "workflow bytes differ from both committed authority and canonical projection: "
            + ", ".join(drift)
        )


def _branch(root: Path, head: str) -> str:
    resolved = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    if resolved.returncode:
        return "detached-head"
    branch = resolved.stdout.decode("utf-8").strip()
    if _SAFE_BRANCH.fullmatch(branch) is None:
        raise ReconcileAuthorityTransitionError(
            "workflow-authority transition requires a safe named branch"
        )
    try:
        graph = yaml.safe_load(_bytes_at(root, head, "governance/ci-graph.yml"))
        default_branch = graph["default_branch"]
    except (ReconcileAuthorityTransitionError, KeyError, TypeError, yaml.YAMLError):
        default_branch = None
    if not isinstance(default_branch, str) or _SAFE_BRANCH.fullmatch(default_branch) is None:
        remote_head = _git(
            root,
            "symbolic-ref",
            "--quiet",
            "--short",
            "refs/remotes/origin/HEAD",
            check=False,
        )
        default_branch = (
            remote_head.stdout.decode("utf-8").strip().removeprefix("origin/")
            if remote_head.returncode == 0
            else None
        )
    if branch == default_branch or (default_branch is None and branch in {"main", "master"}):
        raise ReconcileAuthorityTransitionError(
            "workflow-authority transition is forbidden on the default branch"
        )
    return branch


def _reject_unowned_untracked_files(root: Path) -> None:
    raw = _git(root, "ls-files", "--others", "--exclude-standard", "-z").stdout
    untracked = {
        value.decode("utf-8") for value in raw.split(b"\0") if value
    }
    if not untracked:
        return
    lock_path = root / "governance/bcf-runtime-lock.json"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        owned = set(lock["files"])
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        owned = set()
    unexplained = sorted(untracked - owned)
    if unexplained:
        raise ReconcileAuthorityTransitionError(
            "workflow-authority transition requires new candidate files to be staged "
            "or authenticated by the runtime lock: " + ", ".join(unexplained)
        )


def _preconditions(root: Path, paths: tuple[str, ...]) -> tuple[str, str, str]:
    if Path(_text(root, "rev-parse", "--show-toplevel")).resolve() != root:
        raise ReconcileAuthorityTransitionError(
            "workflow-authority transition requires the repository root"
    )
    head = _text(root, "rev-parse", "HEAD")
    branch = _branch(root, head)
    _reject_unowned_untracked_files(root)
    status = _text(root, "status", "--porcelain=v1", "-z")
    return head, branch, status


def _commit_all(root: Path, message: str) -> str:
    _git(root, "add", "--all")
    if _git(root, "diff", "--cached", "--quiet", check=False).returncode == 0:
        raise ReconcileAuthorityTransitionError(
            f"workflow-authority transition produced no commit for {message}"
        )
    _git(
        root,
        "-c",
        f"user.name={_COMMITTER_NAME}",
        "-c",
        f"user.email={_COMMITTER_EMAIL}",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _text(root, "rev-parse", "HEAD")


def _snapshot_commit(root: Path) -> str:
    """Create an ephemeral exact working-tree commit for rollback only."""

    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        f"user.name={_COMMITTER_NAME}",
        "-c",
        f"user.email={_COMMITTER_EMAIL}",
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "bcf internal reconcile rollback snapshot",
    )
    return _text(root, "rev-parse", "HEAD")


def _changed_workflows(root: Path, head: str, paths: Iterable[str]) -> tuple[str, ...]:
    return tuple(
        relative
        for relative in paths
        if (root / relative).is_file()
        and (root / relative).read_bytes() != _bytes_at(root, head, relative)
    )


def _split_steps(steps: tuple[Step, ...]) -> tuple[tuple[Step, ...], tuple[Step, ...]]:
    matches = [index for index, step in enumerate(steps) if step.step_id == "workflow-authority"]
    if len(matches) != 1:
        raise ReconcileAuthorityTransitionError(
            "workflow-authority transition requires exactly one canonical authority step"
        )
    index = matches[0]
    return steps[:index], steps[index:]


def _workflow_projection_steps(before_authority: tuple[Step, ...]) -> tuple[Step, ...]:
    owners = {
        "ci-graph-post-merge-scope",
        "ci-graph-lock",
        "ci-graph-render",
    }
    selected = tuple(step for step in before_authority if step.step_id in owners)
    return selected or before_authority


def apply_workflow_authority_transition(
    repo_root: Path,
    *,
    step_factory: Callable[[Path], tuple[Step, ...]],
    converge: Callable[[Iterable[Step], Callable[[], str]], int],
    snapshot: Callable[[Path], str],
) -> ReconcileAuthorityTransitionResult | None:
    """Prove and promote the mandatory definition-then-authority commit pair.

    Returns ``None`` when canonical projection does not alter trusted workflow
    bytes; the caller may then use the ordinary file-only reconciliation path.
    """

    root = repo_root.resolve()
    paths = _workflow_paths(root)
    head, branch, original_status = _preconditions(root, paths)
    original_snapshot = snapshot(root)
    original_index_tree = _text(root, "write-tree")
    with tempfile.TemporaryDirectory(prefix="bcf-reconcile-authority-") as temporary:
        backup = Path(temporary) / "backup"
        shadow = Path(temporary) / "repo"
        copy_repository_shadow(root, backup, preserve_git_history=True)
        backup_commit = _snapshot_commit(backup)
        copy_repository_shadow(root, shadow, preserve_git_history=True)
        before_authority, authority_and_after = _split_steps(step_factory(shadow))
        first_rounds = converge(before_authority, lambda: snapshot(shadow))
        _reject_unexplained_workflow_drift(root, shadow, head, paths)
        if not _changed_workflows(shadow, head, paths):
            return None
        definition_commit = _commit_all(shadow, _DEFINITION_MESSAGE)
        second_rounds = converge(authority_and_after, lambda: snapshot(shadow))
        authority_commit = _commit_all(shadow, _AUTHORITY_MESSAGE)
        for step in step_factory(shadow):
            step.check()
        if _text(shadow, "status", "--porcelain=v1", "-z"):
            raise ReconcileAuthorityTransitionError(
                "workflow-authority transition did not produce a clean fixed point"
            )
        if _text(root, "rev-parse", "HEAD") != head or snapshot(root) != original_snapshot:
            raise ReconcileAuthorityTransitionError(
                "repository changed while workflow-authority transition was being proved"
            )
        if _text(root, "status", "--porcelain=v1", "-z") != original_status:
            raise ReconcileAuthorityTransitionError(
                "repository status changed while workflow-authority transition was being proved"
            )
        temporary_ref = f"refs/bcf/reconcile/{authority_commit}"
        backup_ref = f"refs/bcf/reconcile-backup/{backup_commit}"
        promoted = False
        try:
            _git(root, "fetch", "--quiet", str(shadow), f"{authority_commit}:{temporary_ref}")
            _git(root, "fetch", "--quiet", str(backup), f"{backup_commit}:{backup_ref}")
            if _text(root, "rev-parse", f"{authority_commit}^") != definition_commit:
                raise ReconcileAuthorityTransitionError(
                    "authority commit is not the direct child of the definition commit"
                )
            if _text(root, "rev-parse", f"{definition_commit}^") != head:
                raise ReconcileAuthorityTransitionError(
                    "definition commit is not based on the original exact subject"
                )
            promoted = True
            _git(root, "reset", "--hard", "--quiet", authority_commit)
            promoted_branch = _git(
                root, "symbolic-ref", "--quiet", "--short", "HEAD", check=False
            )
            promoted_identity = (
                promoted_branch.stdout.decode("utf-8").strip()
                if promoted_branch.returncode == 0
                else "detached-head"
            )
            if promoted_identity != branch:
                raise ReconcileAuthorityTransitionError(
                    "workflow-authority transition changed the active branch identity"
                )
            if snapshot(root) != snapshot(shadow):
                raise ReconcileAuthorityTransitionError(
                    "promoted workflow-authority tree differs from the proved shadow"
                )
        except BaseException:
            if promoted:
                try:
                    _git(root, "reset", "--hard", "--quiet", backup_commit)
                    _git(root, "reset", "--mixed", "--quiet", head)
                    _git(root, "read-tree", original_index_tree)
                    if (
                        _text(root, "rev-parse", "HEAD") != head
                        or snapshot(root) != original_snapshot
                        or _text(root, "status", "--porcelain=v1", "-z")
                        != original_status
                    ):
                        raise ReconcileAuthorityTransitionError(
                            "workflow-authority rollback did not restore exact custody"
                        )
                except BaseException as rollback_exc:
                    raise ReconcileAuthorityTransitionError(
                        "workflow-authority promotion and exact rollback both failed"
                    ) from rollback_exc
            raise
        finally:
            _git(root, "update-ref", "-d", temporary_ref, check=False)
            _git(root, "update-ref", "-d", backup_ref, check=False)
    return ReconcileAuthorityTransitionResult(
        rounds=first_rounds + second_rounds,
        definition_commit=definition_commit,
        authority_commit=authority_commit,
    )


def result_json(result: ReconcileAuthorityTransitionResult) -> str:
    return json.dumps(
        {
            "status": "committed_workflow_authority_transition",
            "rounds": result.rounds,
            "definition_commit": result.definition_commit,
            "authority_commit": result.authority_commit,
        },
        sort_keys=True,
    )
