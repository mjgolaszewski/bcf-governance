from pathlib import Path

import pytest

from bcf_governance.tooling import scheduled_control_preflight as scheduled


COMMIT = "a" * 40
TREE = "b" * 40
WHEEL = "c" * 64


def _effective() -> dict[str, object]:
    return {
        "source": "provider_transition",
        "subject": {"commit_sha": COMMIT, "tree_sha": TREE},
        "pin": {
            "BCF_BOOTSTRAP_COMMIT_SHA": COMMIT,
            "BCF_BOOTSTRAP_WHEEL_SHA256": WHEEL,
        },
    }


def test_scheduled_control_preflight_binds_one_provider_effective_pair(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    monkeypatch.setattr(
        scheduled, "resolve_effective_controller", lambda *_args, **_kwargs: _effective()
    )

    def fake_preflight(*_args: object, **kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "subject": {
                "commit_sha": COMMIT,
                "tree_sha": TREE,
                "status_porcelain_sha256": "d" * 64,
            }
        }

    monkeypatch.setattr(scheduled, "run_preflight", fake_preflight)
    monkeypatch.setattr(
        scheduled,
        "write_preflight_diagnostic",
        lambda *_args, **kwargs: diagnostics.append(kwargs),
    )
    result = scheduled.run_scheduled_control_preflight(
        object(),
        repository="owner/repo",
        repo_root=tmp_path,
        python_executable=Path("python"),
        output_path=tmp_path / "preflight.json",
    )
    assert calls == [{
        "mode": "release",
        "python_executable": Path("python"),
        "evaluation_mode": "pr",
        "transported_authority": {
            "controller_commit_sha": COMMIT,
            "controller_bundle_sha256": WHEEL,
        },
    }]
    assert diagnostics[0]["report"]["subject"] == result["subject"]
    assert result["release_authority"] is False


def test_scheduled_control_preflight_rejects_nonmain_checkout_and_retains_diagnostic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    diagnostics: list[dict[str, object]] = []
    monkeypatch.setattr(
        scheduled, "resolve_effective_controller", lambda *_args, **_kwargs: _effective()
    )
    monkeypatch.setattr(
        scheduled,
        "run_preflight",
        lambda *_args, **_kwargs: {
            "subject": {"commit_sha": "d" * 40, "tree_sha": TREE}
        },
    )
    monkeypatch.setattr(
        scheduled,
        "write_preflight_diagnostic",
        lambda *_args, **kwargs: diagnostics.append(kwargs),
    )
    with pytest.raises(
        scheduled.ScheduledControlPreflightError,
        match="differs from provider-effective main",
    ):
        scheduled.run_scheduled_control_preflight(
            object(),
            repository="owner/repo",
            repo_root=tmp_path,
            python_executable=Path("python"),
            output_path=tmp_path / "preflight.json",
        )
    assert diagnostics == [{
        "mode": "release",
        "evaluation_mode": "pr",
        "error": "scheduled checkout differs from provider-effective main subject",
    }]
