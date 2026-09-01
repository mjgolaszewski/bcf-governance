from __future__ import annotations

from types import SimpleNamespace

import pytest

from bcf_governance.tooling import ci_github_canary as canary
from bcf_governance.tooling import ci_github_status as github_status
from bcf_governance.tooling.ci_authority_decisions import StatusConclusion
from bcf_governance.tooling.ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
)


COMMIT = "a" * 40
TREE = "b" * 40
AUTHORITY = {
    "schema_version": "1.1",
    "roles": {"authority_canary": "canary"},
    "workflow_registry": {
        "canary": {
            "expected_jobs": [
                {"job_id": "Admit", "role": "admission"},
                {"job_id": "Producer A", "role": "producer"},
                {"job_id": "Producer B", "role": "producer"},
                {"job_id": "Observe", "role": "observer"},
            ]
        }
    },
}


def _jobs(*, failed: str | None = None, incomplete: str | None = None):
    return tuple(
        {
            "name": name,
            "status": "in_progress" if name in {"Observe", incomplete} else "completed",
            "conclusion": None if name in {"Observe", incomplete} else (
                "failure" if name == failed else "success"
            ),
        }
        for name in ("Admit", "Producer A", "Producer B", "Observe")
    )


class _StatusAPI:
    def __init__(self) -> None:
        self.statuses: list[dict[str, object]] = []

    def commit_statuses(self, repository: str, *, sha: str):
        return tuple(self.statuses)

    def status(self, repository: str, **payload: object) -> None:
        self.statuses.insert(0, dict(payload))


def _provider_status(state: str, *, ordinal: int = 10, attempt: int = 1):
    return {
        "context": "bcf/authority-canary",
        "state": state,
        "target_url": (
            "https://github.com/owner/repo/actions/runs/10"
            f"?bcf_ordinal={ordinal}&bcf_attempt={attempt}"
        ),
    }


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    run_id: str,
    attempt: int,
    jobs: tuple[dict[str, object], ...],
) -> None:
    identity = SimpleNamespace(run_id=run_id, run_attempt=attempt)
    monkeypatch.setattr(
        canary, "resolve_main", lambda *_: MainIdentity("101", "main", COMMIT, TREE)
    )
    monkeypatch.setattr(canary, "load_authority", lambda *_, **__: AUTHORITY)
    monkeypatch.setattr(canary, "authenticate_role_run", lambda *_, **__: identity)
    monkeypatch.setattr(
        canary,
        "authenticate_role_job_inventory",
        lambda *_, **__: (identity, jobs),
    )


def test_canary_computes_only_exact_admission_and_producer_results() -> None:
    assert canary._canary_conclusion(AUTHORITY, _jobs()) == (
        StatusConclusion.SUCCESS,
        "exact current-attempt producers succeeded",
    )
    assert canary._canary_conclusion(
        AUTHORITY, _jobs(failed="Producer B")
    )[0] is StatusConclusion.FAILURE
    assert canary._canary_conclusion(
        AUTHORITY, _jobs(incomplete="Producer A")
    )[0] is StatusConclusion.FAILURE


def test_newer_same_sha_failure_revokes_success_without_producer_mixing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _StatusAPI()
    _patch(monkeypatch, run_id="10", attempt=1, jobs=_jobs())
    canary.admit_authority_canary(
        api, repository="owner/repo", expected_sha=COMMIT, run_id="10",
        run_attempt=1, target_url="https://github.com/owner/repo/actions/runs/10",
    )
    first = canary.observe_authority_canary(
        api, repository="owner/repo", expected_sha=COMMIT, run_id="10",
        run_attempt=1, target_url="https://github.com/owner/repo/actions/runs/10",
    )
    assert first["conclusion"] == "success"
    assert [value["state"] for value in api.statuses] == ["success", "pending"]

    _patch(monkeypatch, run_id="11", attempt=1, jobs=_jobs(failed="Producer B"))
    second = canary.observe_authority_canary(
        api, repository="owner/repo", expected_sha=COMMIT, run_id="11",
        run_attempt=1, target_url="https://github.com/owner/repo/actions/runs/11",
    )

    assert second["conclusion"] == "failure"
    assert api.statuses[0]["state"] == "failure"
    assert api.statuses[0]["context"] == "bcf/authority-canary"


@pytest.mark.parametrize("reverse", [False, True])
def test_terminal_status_mechanically_dominates_pending_without_list_order(
    reverse: bool,
) -> None:
    api = _StatusAPI()
    api.statuses = [_provider_status("pending"), _provider_status("success")]
    if reverse:
        api.statuses.reverse()

    observed = github_status._current_status(
        api, "owner/repo", COMMIT, github_status.StatusContext.AUTHORITY_CANARY
    )

    assert observed is not None
    assert observed.conclusion is StatusConclusion.SUCCESS


def test_conflicting_terminal_statuses_fail_closed() -> None:
    api = _StatusAPI()
    api.statuses = [_provider_status("failure"), _provider_status("success")]

    with pytest.raises(GitHubControllerError, match="conflicting terminal"):
        github_status._current_status(
            api, "owner/repo", COMMIT, github_status.StatusContext.AUTHORITY_CANARY
        )


def test_canary_attempt_two_has_higher_total_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _StatusAPI()
    _patch(monkeypatch, run_id="20", attempt=1, jobs=_jobs())
    canary.observe_authority_canary(
        api, repository="owner/repo", expected_sha=COMMIT, run_id="20",
        run_attempt=1, target_url="https://github.com/owner/repo/actions/runs/20",
    )
    _patch(monkeypatch, run_id="20", attempt=2, jobs=_jobs(failed="Producer A"))
    result = canary.observe_authority_canary(
        api, repository="owner/repo", expected_sha=COMMIT, run_id="20",
        run_attempt=2, target_url="https://github.com/owner/repo/actions/runs/20",
    )
    assert result["status"] == "published"
    assert result["conclusion"] == "failure"


def test_canary_rejects_moved_main_before_status_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _StatusAPI()
    _patch(monkeypatch, run_id="30", attempt=1, jobs=_jobs())
    with pytest.raises(GitHubControllerError, match="current default main"):
        canary.admit_authority_canary(
            api, repository="owner/repo", expected_sha="c" * 40, run_id="30",
            run_attempt=1, target_url="https://github.com/owner/repo/actions/runs/30",
        )
    assert api.statuses == []
