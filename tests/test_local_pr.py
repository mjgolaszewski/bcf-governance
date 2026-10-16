from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import local_pr_context
from bcf_governance.tooling.ci_commands import _local_pr_command
from bcf_governance.tooling.governance_install.runtime_custody import (
    RuntimeCustodySnapshot,
    RuntimeCustodyState,
)
from bcf_governance.tooling.local_execution_admission import (
    LocalExecutionAdmissionError,
    resolve_local_project_python,
)
from bcf_governance.tooling.local_pr import (
    LocalPRError,
    resolve_local_pr_context,
    run_local_pr_validation,
)
from bcf_governance.tooling.local_pr_context import LocalPRContext, LocalValidationLane


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    _git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
    repo = tmp_path / "repo"
    subprocess.run(["git", "clone", str(remote), str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "BCF Tests")
    (repo / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
    (repo / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "CHANGELOG.md", "source.py")
    _git(repo, "commit", "-m", "initial")
    _git(repo, "push", "-u", "origin", "main")
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-b", "feature")
    (repo / "source.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "source.py")
    _git(repo, "commit", "-m", "feature")
    return repo, base


def test_local_pr_cli_defaults_to_canonical_selected_interpreter_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_python = tmp_path / ".venv/bin/python"
    project_python.parent.mkdir(parents=True)
    project_python.write_text("#!/bin/sh\n", encoding="utf-8")
    project_python.chmod(0o755)

    def select_project_python(
        repo_root: Path, _controller_python: Path
    ) -> Path:
        if repo_root == tmp_path:
            return project_python
        raise LocalExecutionAdmissionError("runtime authority is unavailable")

    monkeypatch.setattr(
        "bcf_governance.tooling.ci_commands.ensure_local_project_python",
        select_project_python,
    )
    assert _local_pr_command((), repo_root=tmp_path) == (
        str(project_python),
        "scripts/preflight_governance.py",
        "--repo-root",
        ".",
        "--mode",
        "pr",
        "--python",
        str(project_python),
        "--format",
        "text",
    )
    with pytest.raises(LocalExecutionAdmissionError, match="runtime authority is unavailable"):
        _local_pr_command((), repo_root=Path("/nonexistent"))
    assert _local_pr_command(
        ("--", "python", "custom.py"), repo_root=tmp_path
    ) == (
        "python",
        "custom.py",
    )


def test_local_pr_default_accepts_one_external_project_python(tmp_path: Path) -> None:
    external = tmp_path / "project-env/bin/python"
    external.parent.mkdir(parents=True)
    external.write_text("#!/bin/sh\n", encoding="utf-8")
    external.chmod(0o755)

    selected = resolve_local_project_python(
        tmp_path / "checkout", Path(sys.executable), requested=external
    )
    command = _local_pr_command(
        (), repo_root=tmp_path / "checkout", project_python=selected
    )

    assert command[0] == str(external)
    assert command[command.index("--python") + 1] == str(external)


def test_local_pr_context_fetches_default_branch_and_supplies_exact_event(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    context = resolve_local_pr_context(repo)
    assert context.default_branch == "main"
    assert context.base_sha == base
    script = (
        "import json,os,pathlib; "
        "event=json.loads(pathlib.Path(os.environ['GITHUB_EVENT_PATH']).read_text()); "
        "assert os.environ['BCF_ENFORCE_PR_CHANGELOG']=='true'; "
        "assert os.environ['BCF_VALIDATION_LANE']=='provider_pr'; "
        "assert os.environ['GITHUB_EVENT_NAME']=='pull_request'; "
        "assert event['pull_request']['base']['sha']==os.environ['BCF_PR_BASE_SHA']; "
        "assert event['pull_request']['head']['sha']==os.environ['GITHUB_SHA']"
    )
    result = run_local_pr_validation(repo, command=(sys.executable, "-c", script))
    assert result.returncode == 0, result.stderr


def test_candidate_qualification_lane_is_derived_from_exact_custody_and_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = LocalPRContext("origin", "main", "a" * 40, "c" * 40, "qualification")
    snapshot = RuntimeCustodySnapshot(
        state=RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT,
        version="2.3.2",
        runtime_owned={},
        consumer_preserved={},
        legacy_overlap=(),
        provenance_claim={
            "adopter": {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
        },
        lock_bytes=b"{}",
    )
    monkeypatch.setattr(
        local_pr_context, "inspect_runtime_custody", lambda _root: snapshot
    )

    def runner(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        assert argv == ["git", "rev-parse", f"{'a' * 40}^{{tree}}"]
        return SimpleNamespace(returncode=0, stdout="b" * 40 + "\n", stderr="")

    assert local_pr_context.derive_local_validation_lane(
        tmp_path, context, runner=runner
    ) is LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION


def test_candidate_marker_cannot_suppress_ordinary_pr_changelog_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = LocalPRContext("origin", "main", "a" * 40, "c" * 40, "feature")
    snapshot = RuntimeCustodySnapshot(
        state=RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT,
        version="2.3.2",
        runtime_owned={},
        consumer_preserved={},
        legacy_overlap=(),
        provenance_claim={
            "adopter": {"commit_sha": "d" * 40, "tree_sha": "e" * 40}
        },
        lock_bytes=b"{}",
    )
    monkeypatch.setattr(
        local_pr_context, "inspect_runtime_custody", lambda _root: snapshot
    )
    runner = lambda *_a, **_k: SimpleNamespace(
        returncode=0, stdout="b" * 40 + "\n", stderr=""
    )

    assert local_pr_context.derive_local_validation_lane(
        tmp_path, context, runner=runner
    ) is LocalValidationLane.PROVIDER_PR
    assert local_pr_context.derive_local_validation_lane(
        tmp_path,
        context,
        requested=LocalValidationLane.PROVIDER_PR,
        runner=lambda *_a, **_k: pytest.fail("explicit lane consulted custody"),
    ) is LocalValidationLane.PROVIDER_PR


def test_local_pr_context_retries_only_identical_transient_remote_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[tuple[str, ...]] = []
    fetches = 0

    def runner(command: list[str], **_kwargs: object) -> SimpleNamespace:
        nonlocal fetches
        commands.append(tuple(command))
        if command[:2] == ["git", "ls-remote"]:
            return SimpleNamespace(
                returncode=0, stdout="ref: refs/heads/main\tHEAD\n", stderr=""
            )
        if command[:2] == ["git", "fetch"]:
            fetches += 1
            if fetches == 1:
                return SimpleNamespace(
                    returncode=128,
                    stdout="",
                    stderr="Received disconnect from provider:11: Bye Bye",
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[1:3] == ["rev-parse", "--verify"]:
            return SimpleNamespace(returncode=0, stdout="a" * 40 + "\n", stderr="")
        if command[1:3] == ["merge-base", "--is-ancestor"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[1:3] == ["branch", "--show-current"]:
            return SimpleNamespace(returncode=0, stdout="feature\n", stderr="")
        if command[1:3] == ["remote", "get-url"]:
            return SimpleNamespace(returncode=0, stdout="file:///fixture.git\n", stderr="")
        raise AssertionError(command)

    monkeypatch.setattr("bcf_governance.tooling.local_pr_context.time.sleep", lambda _value: None)
    context = resolve_local_pr_context(tmp_path, runner=runner)
    fetch_commands = [command for command in commands if command[:2] == ("git", "fetch")]
    assert fetch_commands == [fetch_commands[0], fetch_commands[0]]
    assert context.base_sha == "a" * 40


def test_local_pr_context_never_retries_nontransient_remote_failure(
    tmp_path: Path,
) -> None:
    calls = 0

    def runner(command: list[str], **_kwargs: object) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return SimpleNamespace(returncode=128, stdout="", stderr="Permission denied")

    with pytest.raises(LocalPRError, match="Permission denied"):
        resolve_local_pr_context(tmp_path, runner=runner)
    assert calls == 1


def test_pr_only_changelog_rule_fails_locally_before_remote_ci(tmp_path: Path) -> None:
    repo, _base = _repository(tmp_path)
    script = (
        "import os,subprocess,sys; "
        "changed=subprocess.check_output(['git','diff','--name-only',os.environ['BCF_PR_BASE_SHA'],'HEAD'],text=True).splitlines(); "
        "sys.exit(0 if 'CHANGELOG.md' in changed else 19)"
    )
    red = run_local_pr_validation(repo, command=(sys.executable, "-c", script))
    assert red.returncode == 19
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n- feature\n", encoding="utf-8")
    _git(repo, "add", "CHANGELOG.md")
    _git(repo, "commit", "-m", "changelog")
    green = run_local_pr_validation(repo, command=(sys.executable, "-c", script))
    assert green.returncode == 0


def test_local_pr_rejects_head_without_default_branch_ancestry(tmp_path: Path) -> None:
    repo, _base = _repository(tmp_path)
    _git(repo, "checkout", "--orphan", "unrelated")
    _git(repo, "rm", "-rf", ".")
    (repo / "other.txt").write_text("unrelated\n", encoding="utf-8")
    _git(repo, "add", "other.txt")
    _git(repo, "commit", "-m", "unrelated")
    with pytest.raises(LocalPRError, match="does not descend"):
        resolve_local_pr_context(repo)


def test_local_pr_event_file_is_removed_after_execution(tmp_path: Path) -> None:
    repo, _base = _repository(tmp_path)
    script = "import os; print(os.environ['GITHUB_EVENT_PATH'])"
    result = run_local_pr_validation(repo, command=(sys.executable, "-c", script))
    assert result.returncode == 0
    assert not Path(result.stdout.strip()).exists()


@pytest.fixture
def authenticated_stacked_pr(tmp_path, monkeypatch):
    """A real Git stack with an independently mocked provider read producer."""
    import copy
    from bcf_governance.tooling.ci_github_api import GitHubAPI
    repo, default_base = _repository(tmp_path)
    stack_base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "push", "origin", "HEAD:refs/heads/stack")
    (repo / "source.py").write_text("VALUE = 3\n", encoding="utf-8")
    _git(repo, "add", "source.py")
    _git(repo, "commit", "-m", "stacked leaf")
    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "push", "origin", "HEAD:refs/heads/feature")
    provider_repo = {"id": 17, "full_name": "owner/repository", "default_branch": "main"}
    pull = {"number": 7, "node_id": "PR_exact7", "state": "open",
            "head": {"sha": head, "ref": "feature", "repo": provider_repo},
            "base": {"sha": stack_base, "ref": "stack", "repo": provider_repo}}
    state = {"repository": provider_repo, "pulls": [pull], "current": pull, "error": None, "reads": []}
    def repository(_api, name):
        assert name == "owner/repository"
        state["reads"].append("repository")
        return copy.deepcopy(state["repository"])
    def pulls(_api, name, *, state="open"):
        assert name == "owner/repository" and state == "open"
        observation = provider_state
        observation["reads"].append("pulls")
        if observation["error"] is not None:
            raise observation["error"]
        return tuple(copy.deepcopy(observation["pulls"]))
    provider_state = state
    def current(_api, name, number):
        assert name == "owner/repository" and number == 7
        state["reads"].append("current")
        return copy.deepcopy(state["current"])
    monkeypatch.setenv("GITHUB_TOKEN", "fixture-read-only-token")
    def reference(_api, name, ref):
        assert name == "owner/repository" and ref == "heads/main"
        state["reads"].append("reference")
        sequence = state.get("default_reference_sequence")
        return copy.deepcopy(sequence.pop(0) if sequence else state.get("default_reference", {"ref": "refs/heads/main", "object": {"type": "commit", "sha": default_base}}))
    monkeypatch.setattr(GitHubAPI, "reference", reference)
    monkeypatch.setattr(GitHubAPI, "repository", repository)
    monkeypatch.setattr(GitHubAPI, "pull_requests", pulls)
    monkeypatch.setattr(GitHubAPI, "pull_request", current)
    for name in ["create_pull_request", "update_pull_request_metadata", "enable_pull_request_auto_merge", "merge_clean_pull_request"]:
        monkeypatch.setattr(GitHubAPI, name, lambda *_a, **_k: pytest.fail("identity discovery crossed provider mutation"))
    def runner(command, **kwargs):
        if command == ["git", "remote", "get-url", "origin"]:
            return subprocess.CompletedProcess(command, 0, "https://github.com/owner/repository.git\n", "")
        return local_pr_context._run(command, **kwargs)
    return SimpleNamespace(repo=repo, default_base=default_base, stack_base=stack_base,
                           head=head, state=state, runner=runner)


def test_bound_stacked_pr_context_uses_authenticated_base_instead_of_default(authenticated_stacked_pr):
    fixture = authenticated_stacked_pr
    context = resolve_local_pr_context(fixture.repo, runner=fixture.runner)
    assert context.base_sha == fixture.stack_base
    assert context.base_sha != fixture.default_base
    assert context.default_branch == "main"
    assert context.head_sha == fixture.head
    assert fixture.state["reads"]


def test_bound_stacked_pr_synthetic_event_preserves_provider_base_ref(authenticated_stacked_pr):
    fixture = authenticated_stacked_pr
    script = ("import json,os,pathlib; "
              "event=json.loads(pathlib.Path(os.environ['GITHUB_EVENT_PATH']).read_text()); "
              "assert event['repository']['default_branch']=='main'; "
              "assert event['pull_request']['base']['ref']=='stack'; "
              f"assert event['pull_request']['base']['sha']=='{fixture.stack_base}'; "
              "assert os.environ['GITHUB_BASE_REF']=='stack'; "
              f"assert os.environ['BCF_COMPARISON_BASE_SHA']=='{fixture.stack_base}'")
    result = run_local_pr_validation(fixture.repo, command=(sys.executable, "-c", script), runner=fixture.runner)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("cause", ["ambiguous", "provider-failure", "wrong-repository", "wrong-head", "missing-base"])
def test_bound_pr_discovery_never_defaults_on_unprovable_provider_facts(authenticated_stacked_pr, cause):
    import copy
    from bcf_governance.tooling.ci_github_errors import GitHubAPIError
    fixture = authenticated_stacked_pr
    if cause == "ambiguous":
        duplicate = copy.deepcopy(fixture.state["pulls"][0]); duplicate["number"] = 8
        fixture.state["pulls"].append(duplicate)
    elif cause == "provider-failure":
        fixture.state["error"] = GitHubAPIError("fixture terminal provider read")
    elif cause == "wrong-repository":
        fixture.state["repository"]["id"] = 99
        # Preserve the independent PR repository observation as the original identity.
        fixture.state["pulls"][0]["base"]["repo"] = {"id": 17, "full_name": "owner/repository"}
    elif cause == "wrong-head":
        fixture.state["pulls"][0]["head"]["sha"] = "9" * 40
    else:
        fixture.state["pulls"][0]["base"]["sha"] = ""
    with pytest.raises(LocalPRError):
        resolve_local_pr_context(fixture.repo, runner=fixture.runner)


def test_bound_pr_local_descendant_keeps_distinct_provider_head(authenticated_stacked_pr):
    fixture = authenticated_stacked_pr
    (fixture.repo / "source.py").write_text("VALUE = 4\n")
    _git(fixture.repo, "add", "source.py")
    _git(fixture.repo, "commit", "-m", "new local candidate")
    candidate = _git(fixture.repo, "rev-parse", "HEAD")
    context = resolve_local_pr_context(fixture.repo, runner=fixture.runner)
    assert context.head_sha == candidate and context.provider_head_sha == fixture.head
    assert context.base_sha == fixture.stack_base and context.comparison_base_ref == "stack"


def test_authenticated_unbound_github_context_keeps_repository_identity(authenticated_stacked_pr):
    fixture = authenticated_stacked_pr
    fixture.state["pulls"] = []
    context = resolve_local_pr_context(fixture.repo, runner=fixture.runner)
    assert context.base_sha == fixture.default_base and context.comparison_base_ref == "main"
    assert context.repository == "owner/repository" and context.repository_id == 17
    assert context.pull_request_number is None


@pytest.mark.parametrize("cause", ["fresh-base", "fresh-head", "fresh-node", "missing-head-ref", "closed-record", "missing-credential"])
def test_bound_pr_discovery_rejects_movement_and_incomplete_absence(authenticated_stacked_pr, monkeypatch, cause):
    import copy
    fixture = authenticated_stacked_pr
    if cause.startswith("fresh-"):
        fixture.state["current"] = copy.deepcopy(fixture.state["current"])
        if cause == "fresh-base": fixture.state["current"]["base"]["sha"] = "8" * 40
        elif cause == "fresh-head": fixture.state["current"]["head"]["sha"] = "9" * 40
        else: fixture.state["current"]["node_id"] = "PR_moved8"
    elif cause == "missing-head-ref": fixture.state["pulls"][0]["head"].pop("ref")
    elif cause == "closed-record": fixture.state["pulls"][0]["state"] = "closed"
    else: monkeypatch.delenv("GITHUB_TOKEN")
    with pytest.raises(LocalPRError):
        resolve_local_pr_context(fixture.repo, runner=fixture.runner)


def test_local_unbound_context_serialization_remains_exactly_legacy(tmp_path):
    repo, base = _repository(tmp_path)
    context = resolve_local_pr_context(repo)
    assert context.as_dict() == {"remote": "origin", "default_branch": "main", "base_sha": base,
                                 "head_sha": _git(repo, "rev-parse", "HEAD"), "head_ref": "feature"}


def test_bound_stacked_context_retains_distinct_protected_default_subject(authenticated_stacked_pr):
    fixture = authenticated_stacked_pr
    context = resolve_local_pr_context(fixture.repo, runner=fixture.runner)
    assert context.base_sha == fixture.stack_base
    assert getattr(context, 'protected_default_sha', None) == fixture.default_base
    expected_tree = subprocess.check_output(['git', 'rev-parse', fixture.default_base + '^{tree}'], cwd=fixture.repo, text=True).strip()
    assert context.protected_default_tree == expected_tree
    assert context.as_dict()['protected_default_sha'] != context.as_dict()['base_sha']


@pytest.mark.parametrize('cause', ['wrong-ref', 'tag-object', 'wrong-sha', 'missing-object', 'noncanonical-sha'])
def test_protected_default_subject_rejects_before_pr_discovery(authenticated_stacked_pr, cause):
    import copy
    fixture = authenticated_stacked_pr
    reference = {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': fixture.default_base}}
    if cause == 'wrong-ref': reference['ref'] = 'refs/heads/stack'
    elif cause == 'tag-object': reference['object']['type'] = 'tag'
    elif cause == 'wrong-sha': reference['object']['sha'] = fixture.head
    elif cause == 'missing-object': del reference['object']
    else: reference['object']['sha'] = ' ' + fixture.default_base
    fixture.state['default_reference'] = copy.deepcopy(reference)
    with pytest.raises(LocalPRError, match='protected default'):
        resolve_local_pr_context(fixture.repo, runner=fixture.runner)
    assert fixture.state['reads'] == ['repository', 'reference']


@pytest.mark.parametrize('bound', [False, True])
def test_protected_default_movement_during_bound_or_absence_discovery_rejects(authenticated_stacked_pr, bound):
    fixture = authenticated_stacked_pr
    fixture.state['default_reference_sequence'] = [
        {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': fixture.default_base}},
        {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': fixture.head}},
    ]
    if not bound: fixture.state['pulls'] = []
    with pytest.raises(LocalPRError, match='protected default ref disagrees'):
        resolve_local_pr_context(fixture.repo, runner=fixture.runner)
    assert fixture.state['reads'].count('reference') == 2


def test_late_protected_source_movement_rejects_with_unchanged_stacked_subject(authenticated_stacked_pr):
    """Reauthenticate protected source even when semantic PR comparison is stable."""
    from bcf_governance.tooling import local_pr
    from bcf_governance.tooling.local_pr_context import ProspectiveValidationError

    fixture = authenticated_stacked_pr
    initial = resolve_local_pr_context(fixture.repo, runner=fixture.runner)
    identity = local_pr._candidate_identity(fixture.repo, initial, runner=fixture.runner)
    local_pr._confirm_unchanged(fixture.repo, initial_context=initial,
        initial_identity=identity, remote='origin', runner=fixture.runner)
    _git(fixture.repo, 'push', 'origin', f'{fixture.stack_base}:refs/heads/main')
    fixture.state['default_reference'] = {'ref': 'refs/heads/main',
        'object': {'type': 'commit', 'sha': fixture.stack_base}}
    current = resolve_local_pr_context(fixture.repo, runner=fixture.runner)
    assert (current.base_sha, current.head_sha, current.provider_head_sha) == (
        initial.base_sha, initial.head_sha, initial.provider_head_sha)
    assert current.protected_default_sha != initial.protected_default_sha
    assert local_pr._candidate_identity(fixture.repo, current, runner=fixture.runner) == identity
    with pytest.raises(ProspectiveValidationError, match='identity changed during validation'):
        local_pr._confirm_unchanged(fixture.repo, initial_context=initial,
            initial_identity=identity, remote='origin', runner=fixture.runner)


@pytest.mark.parametrize('change', ['tracked', 'untracked'])
def test_ordinary_local_context_discovery_keeps_dirty_read_only_behavior(tmp_path, change):
    repo, base = _repository(tmp_path)
    path = repo/('source.py' if change == 'tracked' else 'new.py')
    path.write_text('VALUE = 99\n')
    before = _git(repo, 'status', '--porcelain=v1', '--untracked-files=all')
    context = resolve_local_pr_context(repo)
    assert context.base_sha == base
    assert context.head_sha == _git(repo, 'rev-parse', 'HEAD')
    assert _git(repo, 'status', '--porcelain=v1', '--untracked-files=all') == before
    assert path.read_text() == 'VALUE = 99\n'


def test_clean_candidate_admission_does_not_replace_later_exact_identity_recheck(tmp_path):
    repo, _base = _repository(tmp_path)
    context = resolve_local_pr_context(repo)
    assert local_pr_context.require_clean_candidate_root(repo, runner=local_pr_context._run) == repo.resolve()
    (repo/'source.py').write_text('VALUE = 99\n')
    with pytest.raises(local_pr_context.ProspectiveValidationError, match='clean committed tree'):
        local_pr_context._candidate_identity(repo, context, runner=local_pr_context._run)
