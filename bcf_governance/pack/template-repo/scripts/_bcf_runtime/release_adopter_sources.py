"""Provider-derived source identities for non-authoritative adopter compatibility."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml  # type: ignore[import-untyped]

from .ci_github_api import GitHubAPI
from .ci_github_errors import GitHubAPIError
from .ci_github_identity import GitHubControllerError, resolve_main


class AdopterSourceError(ValueError):
    """An exact pinned adopter source cannot be admitted."""


@dataclass(frozen=True)
class AdopterSourceIdentity:
    """One exact source in a non-authoritative compatibility observation."""

    id: str
    repository: str
    repository_id: str
    profile: str
    default_branch: str
    commit_sha: str
    tree_sha: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def source_inventory_sha256(sources: Sequence[AdopterSourceIdentity]) -> str:
    """Bind the exact ordered compatibility-source inventory."""

    encoded = json.dumps(
        [source.as_dict() for source in sources],
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def require_provider_source_policy(contract: Mapping[str, Any]) -> None:
    """Old caller-selected policy remains readable, but cannot start new work."""
    policy = contract.get('qualification')
    required = {
        'source': 'provider_default_branch_transaction',
        'caller_checkout_role': 'materialization_resource_only',
        'source_freshness': 'provider_exact_at_capture_and_collection',
    }
    if (contract.get('schema_version') != '1.4' or not isinstance(policy, dict)
            or any(policy.get(key) != value for key, value in required.items())):
        raise AdopterSourceError('adopter source policy requires explicit1.4 migration')


def resolve_adopter_sources(
    api: GitHubAPI, contract: Mapping[str, Any],
) -> tuple[AdopterSourceIdentity, ...]:
    """Freeze the complete policy-ordered inventory before allocating work."""
    require_provider_source_policy(contract)
    required = contract.get('required_adopters')
    keys = ('id', 'repository', 'profile')
    if (not isinstance(required, list) or not required
            or any(not isinstance(item, dict) or any(
                not isinstance(item.get(key), str) or not item[key] for key in keys
            ) for item in required)
            or any(len({item[key].casefold() if key == 'repository' else item[key]
                        for item in required}) != len(required)
                   for key in ('id', 'repository'))):
        raise AdopterSourceError('required adopter inventory is incomplete or ambiguous')
    result = []
    try:
        for item in required:
            main = resolve_main(api, item['repository'])
            if any(source.repository_id == main.repository_id for source in result):
                raise AdopterSourceError('required adopter provider inventory repeats repository ID')
            result.append(AdopterSourceIdentity(
                id=item['id'], repository=item['repository'], profile=item['profile'],
                repository_id=main.repository_id, default_branch=main.default_branch,
                commit_sha=main.checkout_sha, tree_sha=main.tree_sha,
            ))
    except (GitHubAPIError, GitHubControllerError) as exc:
        raise AdopterSourceError('required adopter provider inventory is not exact') from exc
    return tuple(result)


def authenticate_adopter_sources(
    api: GitHubAPI, sources: Sequence[AdopterSourceIdentity],
) -> None:
    """Recheck frozen provider identities before consuming completed observations."""
    if (not sources or any(not isinstance(source, AdopterSourceIdentity) for source in sources)
            or len({source.repository.casefold() for source in sources}) != len(sources)
            or len({source.repository_id for source in sources}) != len(sources)):
        raise AdopterSourceError('required adopter inventory is incomplete or ambiguous')
    try:
        for source in sources:
            main = resolve_main(api, source.repository)
            if (main.repository_id, main.default_branch, main.checkout_sha, main.tree_sha) != (
                source.repository_id, source.default_branch, source.commit_sha, source.tree_sha,
            ):
                raise AdopterSourceError('release qualification adopter source is stale')
    except (GitHubAPIError, GitHubControllerError) as exc:
        raise AdopterSourceError('required adopter provider inventory is unavailable') from exc


def require_adopter_profile(root: Path, source: AdopterSourceIdentity) -> None:
    """Reject a pinned clone whose declared profile differs from the contract."""

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
