"""Provider-resolved immutable source inventory for adopter qualification."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

import yaml  # type: ignore[import-untyped]

from .ci_github_api import GitHubAPI
from .ci_github_errors import GitHubAPIError
from .ci_github_identity import GitHubControllerError, resolve_main


class AdopterSourceError(ValueError):
    """The complete provider source inventory cannot be established."""


@dataclass(frozen=True)
class AdopterSourceIdentity:
    """One provider-resolved source in the frozen transaction inventory."""

    id: str
    repository: str
    repository_id: str
    profile: str
    default_branch: str
    commit_sha: str
    tree_sha: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class AdopterProviderAccess:
    """Exact repository-scoped read credentials for one qualification transaction."""

    tokens: Mapping[str, str]
    token_environments: tuple[str, ...]

    def api_for(self, repository: str) -> GitHubAPI:
        try:
            return GitHubAPI(token=self.tokens[repository])
        except KeyError as exc:
            raise AdopterSourceError(
                f"adopter provider credential is absent: {repository}"
            ) from exc

    def git_environment(self, repository: str) -> dict[str, str]:
        try:
            token = self.tokens[repository]
        except KeyError as exc:
            raise AdopterSourceError(
                f"adopter provider credential is absent: {repository}"
            ) from exc
        encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        return {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {encoded}",
        }

    def scrub(self, environment: Mapping[str, str]) -> dict[str, str]:
        scrubbed = dict(environment)
        for name in self.token_environments:
            scrubbed.pop(name, None)
        return scrubbed


def adopter_provider_access_from_environment(
    contract: Mapping[str, Any],
    *,
    environment: Mapping[str, str] | None = None,
) -> AdopterProviderAccess:
    """Compile the exact contract credential inventory before provider reads."""

    source = os.environ if environment is None else environment
    credentials = contract.get("provider_credentials")
    adopters = contract.get("required_adopters")
    if not isinstance(credentials, list) or not isinstance(adopters, list):
        raise AdopterSourceError("adopter provider credential contract is incomplete")
    by_id: dict[str, tuple[str, str]] = {}
    tokens: dict[str, str] = {}
    environment_names: list[str] = []
    for item in credentials:
        if not isinstance(item, dict):
            raise AdopterSourceError("adopter provider credential contract is invalid")
        credential_id = item.get("id")
        owner = item.get("owner")
        repository_name = item.get("repository")
        environment_name = item.get("token_environment")
        if not all(
            isinstance(value, str) and value
            for value in (credential_id, owner, repository_name, environment_name)
        ):
            raise AdopterSourceError("adopter provider credential contract is invalid")
        repository = f"{owner}/{repository_name}"
        if (
            credential_id in by_id
            or repository in tokens
            or environment_name in environment_names
        ):
            raise AdopterSourceError("adopter provider credential coverage is ambiguous")
        token = source.get(environment_name)
        if not isinstance(token, str) or not token:
            raise AdopterSourceError(
                f"adopter provider credential is absent: {repository}"
            )
        by_id[credential_id] = (repository, environment_name)
        tokens[repository] = token
        environment_names.append(environment_name)
    required: set[str] = set()
    for adopter in adopters:
        if not isinstance(adopter, dict):
            raise AdopterSourceError("adopter provider credential coverage is invalid")
        repository = adopter.get("repository")
        credential_id = adopter.get("provider_credential")
        if not isinstance(repository, str) or not isinstance(credential_id, str):
            raise AdopterSourceError("adopter provider credential coverage is invalid")
        if credential_id not in by_id or by_id[credential_id][0] != repository:
            raise AdopterSourceError("adopter provider credential coverage is not exact")
        required.add(repository)
    if required != set(tokens):
        raise AdopterSourceError("adopter provider credential coverage is not exact")
    return AdopterProviderAccess(tokens=tokens, token_environments=tuple(environment_names))


def source_inventory_sha256(sources: Sequence[AdopterSourceIdentity]) -> str:
    encoded = json.dumps(
        [source.as_dict() for source in sources],
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def resolve_adopter_sources(
    api: GitHubAPI | AdopterProviderAccess, contract: Mapping[str, Any]
) -> tuple[AdopterSourceIdentity, ...]:
    """Resolve the complete ordered provider inventory before qualification work."""

    resolved: list[AdopterSourceIdentity] = []
    try:
        required = contract["required_adopters"]
        for item in required:
            repository = str(item["repository"])
            selected_api = api.api_for(repository) if isinstance(
                api, AdopterProviderAccess
            ) else api
            main = resolve_main(selected_api, repository)
            resolved.append(
                AdopterSourceIdentity(
                    id=str(item["id"]),
                    repository=str(item["repository"]),
                    repository_id=main.repository_id,
                    profile=str(item["profile"]),
                    default_branch=main.default_branch,
                    commit_sha=main.checkout_sha,
                    tree_sha=main.tree_sha,
                )
            )
    except (KeyError, TypeError, GitHubAPIError, GitHubControllerError) as exc:
        raise AdopterSourceError(
            "required adopter provider inventory is not exact"
        ) from exc
    if len(resolved) != len(required):
        raise AdopterSourceError(
            "required adopter provider inventory is incomplete"
        )
    return tuple(resolved)


def authenticate_adopter_sources(
    api: GitHubAPI | AdopterProviderAccess, receipt: Mapping[str, Any]
) -> None:
    """Recompute current provider identities before trusted receipt collection."""

    adopters = receipt.get("adopters")
    if not isinstance(adopters, list):
        raise AdopterSourceError(
            "release qualification adopter inventory is incomplete"
        )
    for adopter in adopters:
        if not isinstance(adopter, dict) or not isinstance(
            adopter.get("repository"), str
        ):
            raise AdopterSourceError(
                "release qualification adopter identity is invalid"
            )
        try:
            selected_api = api.api_for(adopter["repository"]) if isinstance(
                api, AdopterProviderAccess
            ) else api
            main = resolve_main(selected_api, adopter["repository"])
        except (GitHubAPIError, GitHubControllerError) as exc:
            raise AdopterSourceError(
                "release qualification adopter provider identity is unavailable"
            ) from exc
        expected = {
            "repository_id": main.repository_id,
            "source_branch": main.default_branch,
            "source_commit": main.checkout_sha,
            "source_tree": main.tree_sha,
        }
        if any(adopter.get(key) != value for key, value in expected.items()):
            raise AdopterSourceError(
                "release qualification adopter source is stale"
            )


def _git(
    argv: Sequence[str], *, cwd: Path, environment: Mapping[str, str] | None = None
) -> str:
    result = subprocess.run(
        list(argv), cwd=cwd,
        env=(dict(os.environ) | dict(environment)) if environment is not None else None,
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or str(result.returncode)
        raise AdopterSourceError(
            f"{' '.join(argv[:3])} failed while materializing provider source: {detail}"
        )
    return result.stdout.strip()


def materialize_provider_source(
    source: AdopterSourceIdentity,
    destination: Path,
    *,
    provider_access: AdopterProviderAccess | None = None,
) -> None:
    """Materialize only the frozen provider commit and verify its exact tree."""

    _git(["git", "init", str(destination)], cwd=destination.parent)
    _git(
        [
            "git", "remote", "add", "origin",
            f"https://github.com/{source.repository}.git",
        ],
        cwd=destination,
    )
    fetch = ["git", "fetch", "--no-tags", "--depth=1", "origin", source.commit_sha]
    if provider_access is None:
        _git(fetch, cwd=destination)
    else:
        _git(
            fetch,
            cwd=destination,
            environment=provider_access.git_environment(source.repository),
        )
    _git(["git", "checkout", "--detach", source.commit_sha], cwd=destination)
    if (
        _git(["git", "rev-parse", "HEAD"], cwd=destination)
        != source.commit_sha
        or _git(["git", "rev-parse", "HEAD^{tree}"], cwd=destination)
        != source.tree_sha
    ):
        raise AdopterSourceError(
            f"materialized source differs from provider identity: {source.repository}"
        )


def require_adopter_profile(root: Path, source: AdopterSourceIdentity) -> None:
    """Reject a profile mismatch before environment or evidence allocation."""

    try:
        profile = yaml.safe_load(
            (root / "governance-profile.yml").read_text(encoding="utf-8")
        )
        selected = profile["profile"]["selected"]
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        raise AdopterSourceError(
            f"adopter profile is unreadable: {source.repository}"
        ) from exc
    if selected != source.profile:
        raise AdopterSourceError(
            f"adopter profile differs from contract: {source.repository}"
        )
