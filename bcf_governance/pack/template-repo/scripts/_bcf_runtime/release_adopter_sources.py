"""Provider-resolved immutable source inventory for adopter qualification."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
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


def source_inventory_sha256(sources: Sequence[AdopterSourceIdentity]) -> str:
    encoded = json.dumps(
        [source.as_dict() for source in sources],
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def resolve_adopter_sources(
    api: GitHubAPI, contract: Mapping[str, Any]
) -> tuple[AdopterSourceIdentity, ...]:
    """Resolve the complete ordered provider inventory before qualification work."""

    resolved: list[AdopterSourceIdentity] = []
    try:
        required = contract["required_adopters"]
        for item in required:
            main = resolve_main(api, str(item["repository"]))
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
    api: GitHubAPI, receipt: Mapping[str, Any]
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
            main = resolve_main(api, adopter["repository"])
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


def _git(argv: Sequence[str], *, cwd: Path) -> str:
    result = subprocess.run(
        list(argv), cwd=cwd, capture_output=True, text=True, check=False
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or str(result.returncode)
        raise AdopterSourceError(
            f"{' '.join(argv[:3])} failed while materializing provider source: {detail}"
        )
    return result.stdout.strip()


def materialize_provider_source(
    source: AdopterSourceIdentity, destination: Path
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
    _git(
        ["git", "fetch", "--no-tags", "--depth=1", "origin", source.commit_sha],
        cwd=destination,
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
