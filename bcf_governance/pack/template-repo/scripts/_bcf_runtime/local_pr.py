"""Canonical local pull-request context and validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Callable


class LocalPRError(ValueError):
    """Raised before validation when local and remote PR identity cannot agree."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class LocalPRContext:
    remote: str
    default_branch: str
    base_sha: str
    head_sha: str
    head_ref: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _checked(
    runner: Runner,
    command: list[str],
    *,
    cwd: Path,
) -> str:
    result = runner(command, cwd=cwd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise LocalPRError(f"{' '.join(command)}: {detail}")
    return result.stdout.strip()


def resolve_local_pr_context(
    repo_root: Path,
    *,
    remote: str = "origin",
    runner: Runner = _run,
) -> LocalPRContext:
    """Resolve/fetch remote default branch and prove current HEAD descends from it."""

    repo_root = repo_root.resolve()
    symbolic = _checked(
        runner,
        ["git", "ls-remote", "--symref", remote, "HEAD"],
        cwd=repo_root,
    )
    prefix = "ref: refs/heads/"
    default_branch = ""
    for line in symbolic.splitlines():
        if line.startswith(prefix) and line.endswith("\tHEAD"):
            default_branch = line[len(prefix) : -len("\tHEAD")]
            break
    if not default_branch or "/" in default_branch and default_branch.startswith("../"):
        raise LocalPRError("remote HEAD did not identify a safe default branch")
    remote_ref = f"refs/remotes/{remote}/{default_branch}"
    _checked(
        runner,
        [
            "git",
            "fetch",
            "--no-tags",
            remote,
            f"refs/heads/{default_branch}:{remote_ref}",
        ],
        cwd=repo_root,
    )
    base_sha = _checked(runner, ["git", "rev-parse", "--verify", remote_ref], cwd=repo_root)
    head_sha = _checked(runner, ["git", "rev-parse", "--verify", "HEAD"], cwd=repo_root)
    ancestry = runner(
        ["git", "merge-base", "--is-ancestor", base_sha, head_sha], cwd=repo_root
    )
    if ancestry.returncode != 0:
        raise LocalPRError("current HEAD does not descend from the fetched default branch")
    head_ref = _checked(
        runner, ["git", "branch", "--show-current"], cwd=repo_root
    ) or "detached-head"
    return LocalPRContext(
        remote=remote,
        default_branch=default_branch,
        base_sha=base_sha,
        head_sha=head_sha,
        head_ref=head_ref,
    )


def run_local_pr_validation(
    repo_root: Path,
    *,
    command: tuple[str, ...],
    remote: str = "origin",
    runner: Runner = _run,
) -> subprocess.CompletedProcess[str]:
    """Run exact argv with the same base and event identity used by remote PR CI."""

    if not command or any(not value for value in command):
        raise LocalPRError("local PR validation requires non-empty exact argv")
    context = resolve_local_pr_context(repo_root, remote=remote, runner=runner)
    event = {
        "pull_request": {
            "base": {"ref": context.default_branch, "sha": context.base_sha},
            "head": {"ref": context.head_ref, "sha": context.head_sha},
        },
        "repository": {"default_branch": context.default_branch},
    }
    with tempfile.TemporaryDirectory(prefix="bcf-local-pr-") as temporary:
        event_path = Path(temporary) / "event.json"
        event_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "BCF_PR_BASE_SHA": context.base_sha,
                "GITHUB_BASE_REF": context.default_branch,
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_HEAD_REF": context.head_ref,
                "GITHUB_SHA": context.head_sha,
            }
        )
        return runner(list(command), cwd=repo_root.resolve(), env=environment)
