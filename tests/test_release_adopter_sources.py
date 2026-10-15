from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_github_identity import MainIdentity
from bcf_governance.tooling import release_adopter_sources as sources
from bcf_governance.tooling.release_adopter_sources import (
    AdopterSourceError,
    AdopterSourceIdentity,
    authenticate_adopter_sources,
    materialize_provider_source,
    require_adopter_profile,
    resolve_adopter_sources,
    source_inventory_sha256,
    adopter_provider_access_from_environment,
)


def _contract() -> dict[str, object]:
    return {
        "required_adopters": [
            {"id": "one-lite", "repository": "owner/one", "profile": "lite"},
            {"id": "two-standard", "repository": "owner/two", "profile": "standard"},
        ]
    }


def _credential_contract() -> dict[str, object]:
    return {
        "provider_credentials": [
            {
                "id": "one-read",
                "owner": "owner",
                "repository": "one",
                "token_environment": "BCF_ADOPTER_PROVIDER_TOKEN_0",
            },
            {
                "id": "two-read",
                "owner": "owner",
                "repository": "two",
                "token_environment": "BCF_ADOPTER_PROVIDER_TOKEN_1",
            },
        ],
        "required_adopters": [
            {
                "id": "one-lite", "repository": "owner/one", "profile": "lite",
                "provider_credential": "one-read",
            },
            {
                "id": "two-standard", "repository": "owner/two", "profile": "standard",
                "provider_credential": "two-read",
            },
        ],
    }


def test_provider_credentials_are_complete_exact_and_scrubbed_before_execution() -> None:
    access = adopter_provider_access_from_environment(
        _credential_contract(),
        environment={
            "BCF_ADOPTER_PROVIDER_TOKEN_0": "token-one",
            "BCF_ADOPTER_PROVIDER_TOKEN_1": "token-two",
            "SAFE": "retained",
        },
    )
    assert set(access.tokens) == {"owner/one", "owner/two"}
    assert access.scrub({
        "BCF_ADOPTER_PROVIDER_TOKEN_0": "token-one",
        "BCF_ADOPTER_PROVIDER_TOKEN_1": "token-two",
        "SAFE": "retained",
    }) == {"SAFE": "retained"}

    with pytest.raises(AdopterSourceError, match="credential is absent"):
        adopter_provider_access_from_environment(
            _credential_contract(),
            environment={"BCF_ADOPTER_PROVIDER_TOKEN_0": "token-one"},
        )


def test_private_source_fetch_uses_only_ephemeral_git_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    access = adopter_provider_access_from_environment(
        _credential_contract(),
        environment={
            "BCF_ADOPTER_PROVIDER_TOKEN_0": "token-one",
            "BCF_ADOPTER_PROVIDER_TOKEN_1": "token-two",
        },
    )
    source = _identity("owner/one", 1)
    calls: list[tuple[tuple[str, ...], dict[str, str] | None]] = []

    def git(
        argv: list[str], *, cwd: Path,
        environment: dict[str, str] | None = None,
    ) -> str:
        del cwd
        calls.append((tuple(argv), environment))
        if argv[-1] == "HEAD":
            return source.commit_sha
        if argv[-1] == "HEAD^{tree}":
            return source.tree_sha
        return ""

    monkeypatch.setattr(sources, "_git", git)
    materialize_provider_source(
        source, tmp_path / "checkout", provider_access=access
    )
    fetch = next(item for item in calls if item[0][:2] == ("git", "fetch"))
    assert all("token-one" not in argument for argument in fetch[0])
    assert fetch[1] is not None
    assert fetch[1]["GIT_CONFIG_KEY_0"].endswith(".extraheader")


def _identity(repository: str, index: int) -> AdopterSourceIdentity:
    return AdopterSourceIdentity(
        id=("one-lite" if index == 1 else "two-standard"),
        repository=repository,
        repository_id=str(100 + index),
        profile=("lite" if index == 1 else "standard"),
        default_branch="main",
        commit_sha=str(index) * 40,
        tree_sha=str(index + 2) * 40,
    )


def test_provider_sources_resolve_as_one_ordered_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def resolve(_api: object, repository: str) -> MainIdentity:
        observed.append(repository)
        index = len(observed)
        return MainIdentity(str(100 + index), "main", str(index) * 40, str(index + 2) * 40)

    monkeypatch.setattr(sources, "resolve_main", resolve)
    resolved = resolve_adopter_sources(object(), _contract())  # type: ignore[arg-type]

    assert observed == ["owner/one", "owner/two"]
    assert resolved == (_identity("owner/one", 1), _identity("owner/two", 2))
    assert source_inventory_sha256(resolved) != source_inventory_sha256(tuple(reversed(resolved)))


def test_provider_source_resolution_fails_closed_before_partial_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def resolve(_api: object, _repository: str) -> MainIdentity:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise sources.GitHubControllerError("missing")
        return MainIdentity("101", "main", "1" * 40, "3" * 40)

    monkeypatch.setattr(sources, "resolve_main", resolve)
    with pytest.raises(AdopterSourceError, match="inventory is not exact"):
        resolve_adopter_sources(object(), _contract())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository_id", "999"),
        ("source_branch", "next"),
        ("source_commit", "9" * 40),
        ("source_tree", "8" * 40),
    ],
)
def test_trusted_collection_rejects_every_stale_provider_identity(
    monkeypatch: pytest.MonkeyPatch, field: str, value: str,
) -> None:
    source = _identity("owner/one", 1)
    receipt = {
        "adopters": [
            {
                "repository": source.repository,
                "repository_id": source.repository_id,
                "source_branch": source.default_branch,
                "source_commit": source.commit_sha,
                "source_tree": source.tree_sha,
            }
        ]
    }
    receipt["adopters"][0][field] = value  # type: ignore[index]
    monkeypatch.setattr(
        sources,
        "resolve_main",
        lambda *_args: MainIdentity(
            source.repository_id,
            source.default_branch,
            source.commit_sha,
            source.tree_sha,
        ),
    )
    with pytest.raises(AdopterSourceError, match="source is stale"):
        authenticate_adopter_sources(object(), receipt)  # type: ignore[arg-type]


def test_materialization_verifies_exact_commit_and_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _identity("owner/one", 1)
    calls: list[tuple[str, ...]] = []

    def git(argv: list[str], *, cwd: Path) -> str:
        del cwd
        calls.append(tuple(argv))
        if argv[-1] == "HEAD":
            return source.commit_sha
        if argv[-1] == "HEAD^{tree}":
            return source.tree_sha
        return ""

    monkeypatch.setattr(sources, "_git", git)
    materialize_provider_source(source, tmp_path / "checkout")
    assert any(call[:4] == ("git", "fetch", "--no-tags", "--depth=1") for call in calls)

    monkeypatch.setattr(
        sources,
        "_git",
        lambda argv, **_kwargs: "f" * 40 if argv[-1] == "HEAD^{tree}" else (
            source.commit_sha if argv[-1] == "HEAD" else ""
        ),
    )
    with pytest.raises(AdopterSourceError, match="differs from provider identity"):
        materialize_provider_source(source, tmp_path / "wrong")


def test_profile_mismatch_rejects_before_environment_allocation(tmp_path: Path) -> None:
    source = _identity("owner/one", 1)
    (tmp_path / "governance-profile.yml").write_text(
        "profile:\n  selected: standard\n", encoding="utf-8"
    )
    with pytest.raises(AdopterSourceError, match="profile differs"):
        require_adopter_profile(tmp_path, source)

    (tmp_path / "governance-profile.yml").write_text(
        "profile:\n  selected: lite\n", encoding="utf-8"
    )
    require_adopter_profile(tmp_path, replace(source, profile="lite"))
