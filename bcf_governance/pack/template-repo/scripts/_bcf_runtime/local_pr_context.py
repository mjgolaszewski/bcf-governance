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
import time
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlparse

from .ci_github_api import GitHubAPI
from .ci_github_values import (
    GitHubValueError, candidate_pull_request_identity, remote_repository, sha,
)

from .governance_install.runtime_custody import (
    RuntimeCustodyError,
    RuntimeCustodyState,
    candidate_qualification_matches,
    inspect_runtime_custody,
)
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
_REMOTE_READ_ATTEMPTS = 2
_TRANSIENT_REMOTE_READ_MARKERS = (
    "connection reset by peer",
    "operation timed out",
    "received disconnect",
    "remote end hung up unexpectedly",
)


@dataclass(frozen=True)
class LocalPRContext:
    remote: str
    default_branch: str
    base_sha: str
    head_sha: str
    head_ref: str
    base_ref: str | None = None
    repository: str | None = None
    repository_id: int | None = None
    pull_request_number: int | None = None
    pull_request_node_id: str | None = None
    provider_head_sha: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}

    @property
    def comparison_base_ref(self) -> str:
        return self.default_branch if self.base_ref is None else self.base_ref


@dataclass(frozen=True)
class CandidateIdentity:
    commit_sha: str
    tree_sha: str
    base_sha: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def derive_local_validation_lane(
    repo_root: Path,
    context: LocalPRContext,
    *,
    requested: LocalValidationLane | None = None,
    runner: Runner | None = None,
) -> LocalValidationLane:
    """Derive candidate qualification only from exact custody and base identity."""

    if requested is not None:
        return requested
    try:
        snapshot = inspect_runtime_custody(repo_root.resolve())
    except RuntimeCustodyError as exc:
        raise LocalPRError(f"local validation custody is invalid: {exc}") from exc
    if snapshot.state is not RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT:
        return LocalValidationLane.PROVIDER_PR
    base_tree = _checked(
        _run if runner is None else runner,
        ["git", "rev-parse", f"{context.base_sha}^{{tree}}"],
        cwd=repo_root.resolve(),
    )
    if (
        candidate_qualification_matches(
            snapshot, commit_sha=context.base_sha, tree_sha=base_tree
        )
    ):
        return LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION
    return LocalValidationLane.PROVIDER_PR


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _checked(runner: Runner, command: list[str], *, cwd: Path) -> str:
    result = runner(command, cwd=cwd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise LocalPRError(f"{' '.join(command)}: {detail}")
    return result.stdout.strip()


def _checked_remote_read(runner: Runner, command: list[str], *, cwd: Path) -> str:
    """Run one immutable Git remote read with one closed transient retry."""

    if command[:2] not in (["git", "ls-remote"], ["git", "fetch"]):
        raise LocalPRError("remote-read retry accepts immutable Git reads only")
    for attempt in range(_REMOTE_READ_ATTEMPTS):
        result = runner(command, cwd=cwd)
        if result.returncode == 0:
            return result.stdout.strip()
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        transient = any(
            marker in detail.lower() for marker in _TRANSIENT_REMOTE_READ_MARKERS
        )
        if not transient or attempt + 1 == _REMOTE_READ_ATTEMPTS:
            raise LocalPRError(f"{' '.join(command)}: {detail}")
        time.sleep(1.0)
    raise AssertionError("bounded remote read loop did not terminate")


def _bound_pr_projection(value: Mapping[str, Any], *, repository_id: int, branch: str) -> dict[str, Any]:
    """Check a provider observation through the shared candidate identity owner."""
    head, base = value.get("head"), value.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise LocalPRError("bound PR provider identity is incomplete")
    for endpoint in (head, base):
        repository = endpoint.get("repo")
        if not isinstance(repository, Mapping) or type(repository.get("id")) is not int:
            raise LocalPRError("bound PR provider repository identity is incomplete")
    base_ref = base.get("ref")
    if not isinstance(base_ref, str) or not base_ref or base_ref == branch:
        raise LocalPRError("bound PR provider base ref is invalid")
    base_sha = sha(base.get("sha"), field="bound PR base")
    head_sha = sha(head.get("sha"), field="bound PR head")
    if {base_sha, head_sha} & {"0" * 40}:
        raise LocalPRError("bound PR provider subject is zero")
    projection = candidate_pull_request_identity(
        value, repository_id=repository_id, branch=branch,
        base_ref=base_ref, base_sha=base_sha, head_sha=head_sha,
    )
    return {**projection, "base_ref": base_ref}


def _bound_pr_context(
    repo_root: Path, *, remote: str, default_branch: str, head_ref: str,
    head_sha: str, runner: Runner, provider_api: GitHubAPI | None,
) -> dict[str, Any] | None:
    """Authenticate branch binding; unavailable GitHub facts never mean no PR."""
    remote_url = _checked(runner, ["git", "remote", "get-url", remote], cwd=repo_root)
    try:
        repository = remote_repository(remote_url)
    except GitHubValueError as exc:
        if urlparse(remote_url).hostname in {"github.com", "ssh.github.com"} or remote_url.startswith("git@github.com:"):
            raise LocalPRError("local PR remote GitHub identity is invalid") from exc
        return None
    api = provider_api if provider_api is not None else GitHubAPI(
        token=os.environ.get("GITHUB_TOKEN", ""),
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    observed_repository = api.repository(repository)
    repository_id = observed_repository.get("id")
    if (type(repository_id) is not int or repository_id < 1
            or observed_repository.get("full_name") != repository
            or observed_repository.get("default_branch") != default_branch):
        raise LocalPRError("local PR provider repository does not match selected remote")
    if head_ref == "detached-head":
        raise LocalPRError("bound PR discovery requires an exact local branch")
    matches = []
    for value in api.pull_requests(repository, state="open"):
        head = value.get("head")
        if (not isinstance(head, Mapping) or not isinstance(head.get("ref"), str)
                or not head["ref"] or value.get("state") != "open"):
            raise LocalPRError("open PR inventory has an incomplete head or state")
        if head.get("ref") != head_ref:
            continue
        head_repository = head.get("repo")
        if not isinstance(head_repository, Mapping) or type(head_repository.get("id")) is not int:
            raise LocalPRError("open PR inventory cannot resolve the head repository")
        if head_repository["id"] == repository_id:
            matches.append(_bound_pr_projection(value, repository_id=repository_id, branch=head_ref))
    if len(matches) > 1:
        raise LocalPRError("local branch has ambiguous open PR bindings")
    if not matches:
        return {"repository": repository, "repository_id": repository_id}
    binding = matches[0]
    for ref, expected in ((binding["base_ref"], binding["base_sha"]), (head_ref, binding["head_sha"])):
        _checked(runner, ["git", "check-ref-format", "--branch", ref], cwd=repo_root)
        tracking = f"refs/remotes/{remote}/{ref}"
        _checked_remote_read(runner, ["git", "fetch", "--no-tags", remote, f"refs/heads/{ref}:{tracking}"], cwd=repo_root)
        actual = _checked(runner, ["git", "rev-parse", "--verify", tracking], cwd=repo_root)
        if actual != expected:
            raise LocalPRError("bound PR ref moved between provider observation and Git fetch")
    if runner(["git", "merge-base", "--is-ancestor", binding["head_sha"], head_sha], cwd=repo_root).returncode:
        raise LocalPRError("local candidate is not the observed PR head or its descendant")
    current = _bound_pr_projection(api.pull_request(repository, binding["number"]),
                                   repository_id=repository_id, branch=head_ref)
    if current != binding:
        raise LocalPRError("bound PR identity moved during local discovery")
    return {"base_ref": binding["base_ref"], "base_sha": binding["base_sha"],
            "repository": repository, "repository_id": repository_id,
            "pull_request_number": binding["number"], "pull_request_node_id": binding["node_id"],
            "provider_head_sha": binding["head_sha"]}


def resolve_local_pr_context(
    repo_root: Path, *, remote: str = "origin", runner: Runner = _run,
    provider_api: GitHubAPI | None = None,
) -> LocalPRContext:
    """Bind the exact provider PR base, or authenticated unbound default branch."""

    repo_root = repo_root.resolve()
    symbolic = _checked_remote_read(
        runner, ["git", "ls-remote", "--symref", remote, "HEAD"], cwd=repo_root
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
    _checked_remote_read(
        runner,
        ["git", "fetch", "--no-tags", remote, f"refs/heads/{default_branch}:{remote_ref}"],
        cwd=repo_root,
    )
    base_sha = _checked(runner, ["git", "rev-parse", "--verify", remote_ref], cwd=repo_root)
    head_sha = _checked(runner, ["git", "rev-parse", "--verify", "HEAD"], cwd=repo_root)
    head_ref = _checked(runner, ["git", "branch", "--show-current"], cwd=repo_root) or "detached-head"
    try:
        binding = _bound_pr_context(repo_root, remote=remote, default_branch=default_branch,
                                   head_ref=head_ref, head_sha=head_sha, runner=runner, provider_api=provider_api)
    except ValueError as exc:
        raise LocalPRError(str(exc)) from exc
    if binding is not None:
        base_sha = binding.pop("base_sha", base_sha)
    ancestry = runner(
        ["git", "merge-base", "--is-ancestor", base_sha, head_sha], cwd=repo_root
    )
    if ancestry.returncode != 0:
        detail = "bound PR comparison base" if binding and binding.get("base_ref") else "default branch"
        raise LocalPRError(f"current HEAD does not descend from the fetched {detail}")
    return LocalPRContext(remote, default_branch, base_sha, head_sha, head_ref, **(binding or {}))


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
        "GITHUB_BASE_REF": context.comparison_base_ref,
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
            "base": {"ref": context.comparison_base_ref, "sha": context.base_sha},
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
