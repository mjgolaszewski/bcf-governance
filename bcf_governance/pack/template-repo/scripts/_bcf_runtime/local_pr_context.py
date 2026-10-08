"""Exact local pull-request identity, environment, and stability boundary."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from enum import Enum
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Callable, Iterator

from .local_execution_admission import project_python_environment


class LocalPRError(ValueError):
    """Local and remote PR identity cannot agree."""


class ProspectiveValidationError(ValueError):
    """The exact candidate has a mechanically knowable downstream rejection."""


class LocalValidationLane(str, Enum):
    """Closed local validation contexts that cannot confer provider authority."""

    PROVIDER_PR = "provider_pr"
    ISOLATED_CANDIDATE_QUALIFICATION = "isolated_candidate_qualification"


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


@dataclass(frozen=True)
class CandidateIdentity:
    commit_sha: str
    tree_sha: str
    base_sha: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _checked(runner: Runner, command: list[str], *, cwd: Path) -> str:
    result = runner(command, cwd=cwd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise LocalPRError(f"{' '.join(command)}: {detail}")
    return result.stdout.strip()


def resolve_local_pr_context(
    repo_root: Path, *, remote: str = "origin", runner: Runner = _run
) -> LocalPRContext:
    """Resolve/fetch remote default branch and prove current HEAD descends from it."""

    repo_root = repo_root.resolve()
    symbolic = _checked(runner, ["git", "ls-remote", "--symref", remote, "HEAD"], cwd=repo_root)
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
        ["git", "fetch", "--no-tags", remote, f"refs/heads/{default_branch}:{remote_ref}"],
        cwd=repo_root,
    )
    base_sha = _checked(runner, ["git", "rev-parse", "--verify", remote_ref], cwd=repo_root)
    head_sha = _checked(runner, ["git", "rev-parse", "--verify", "HEAD"], cwd=repo_root)
    ancestry = runner(
        ["git", "merge-base", "--is-ancestor", base_sha, head_sha], cwd=repo_root
    )
    if ancestry.returncode != 0:
        raise LocalPRError("current HEAD does not descend from the fetched default branch")
    head_ref = _checked(runner, ["git", "branch", "--show-current"], cwd=repo_root) or "detached-head"
    return LocalPRContext(remote, default_branch, base_sha, head_sha, head_ref)


def _pr_environment_values(
    context: LocalPRContext,
    *,
    event_path: str | None = None,
    validation_lane: LocalValidationLane = LocalValidationLane.PROVIDER_PR,
) -> dict[str, str]:
    values = {
        "BCF_PROVIDER_EVENT": "pull_request",
        "BCF_INVOCATION_KIND": "direct_event",
        "BCF_CALLER_COMPARISON_BASE_SHA": "",
        "BCF_ORIGIN_COMPARISON_BASE_SHA": context.base_sha,
        "BCF_COMPARISON_BASE_SHA": context.base_sha,
        "BCF_ENFORCE_PR_CHANGELOG": "true",
        "BCF_PR_BASE_SHA": context.base_sha,
        "BCF_VALIDATION_LANE": validation_lane.value,
        "GITHUB_BASE_REF": context.default_branch,
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_HEAD_REF": context.head_ref,
        "GITHUB_SHA": context.head_sha,
    }
    if event_path is not None:
        values["GITHUB_EVENT_PATH"] = event_path
    return values


def run_local_pr_validation(
    repo_root: Path,
    *,
    command: tuple[str, ...],
    remote: str = "origin",
    runner: Runner = _run,
    project_python: Path | None = None,
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
        environment = (
            project_python_environment(repo_root, project_python, os.environ)
            if project_python is not None
            else os.environ.copy()
        )
        environment.update(_pr_environment_values(context, event_path=str(event_path)))
        return runner(list(command), cwd=repo_root.resolve(), env=environment)


def _candidate_identity(
    repo_root: Path, context: LocalPRContext, *, runner: Runner
) -> CandidateIdentity:
    head = _checked(runner, ["git", "rev-parse", "--verify", "HEAD"], cwd=repo_root)
    tree = _checked(runner, ["git", "rev-parse", "--verify", "HEAD^{tree}"], cwd=repo_root)
    status = _checked(
        runner,
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"],
        cwd=repo_root,
    )
    if status:
        raise ProspectiveValidationError("prospective validation requires a clean committed tree")
    if head != context.head_sha:
        raise ProspectiveValidationError("local PR context does not bind current HEAD")
    return CandidateIdentity(head, tree, context.base_sha)


@contextmanager
def _pr_environment(
    context: LocalPRContext,
    *,
    validation_lane: LocalValidationLane = LocalValidationLane.PROVIDER_PR,
) -> Iterator[None]:
    values = _pr_environment_values(context, validation_lane=validation_lane)
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _changed_paths(
    repo_root: Path, identity: CandidateIdentity, *, runner: Runner
) -> tuple[str, ...]:
    output = _checked(
        runner,
        ["git", "diff", "--name-only", identity.base_sha, identity.commit_sha],
        cwd=repo_root,
    )
    return tuple(sorted(value for value in output.splitlines() if value))


def _confirm_unchanged(
    repo_root: Path,
    *,
    initial_context: LocalPRContext,
    initial_identity: CandidateIdentity,
    remote: str,
    runner: Runner,
    context_resolver: Callable[..., LocalPRContext] = resolve_local_pr_context,
    identity_resolver: Callable[..., CandidateIdentity] = _candidate_identity,
) -> None:
    current_context = context_resolver(repo_root, remote=remote, runner=runner)
    if current_context != initial_context:
        raise ProspectiveValidationError("remote PR base or local branch identity changed during validation")
    current_identity = identity_resolver(repo_root, current_context, runner=runner)
    if current_identity != initial_identity:
        raise ProspectiveValidationError("candidate commit or tree changed during validation")
