"""Trusted native owner's explicit release context; persisted paths are data."""
from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .architecture_membership_compilation import NativeReleaseInputs
from .architecture_release_membership import ReleaseMembership, authenticate_release_membership
from .architecture_source_components import SourceComponentError
from .bootstrap.contracts import GitHubProviderSettings, ScopedExecutionEnvironment
from .bootstrap.environment import github_provider_settings, scoped_execution_environment
from .governance_install.release_custody import ReleaseProvider

KEY = "BCF_RELEASE_MEMBERSHIP_INPUTS"


def encode_release_inputs(inputs: NativeReleaseInputs) -> str:
    # Credentials and fixture provider objects never enter transport.
    raw = json.dumps({"assets_root": str(inputs.assets_root),
                      "template_root": str(inputs.template_root)}, sort_keys=True)
    if len(raw.encode()) > 8192:
        raise SourceComponentError("native release context: input size exceeded")
    return raw


def decode_release_inputs(raw: str) -> NativeReleaseInputs:
    if not isinstance(raw, str) or not raw or len(raw.encode()) > 8192:
        raise SourceComponentError("native release context: bounded explicit inputs required")
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SourceComponentError("native release context: duplicate field")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except json.JSONDecodeError as exc:
        raise SourceComponentError("native release context: invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"assets_root", "template_root"}:
        raise SourceComponentError("native release context: exact input fields required")
    paths = {}
    for name, item in value.items():
        if not isinstance(item, str):
            raise SourceComponentError("native release context: canonical source paths required")
        path = Path(item)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise SourceComponentError("native release context: canonical source paths required")
        paths[name] = path
    return NativeReleaseInputs(paths["assets_root"], paths["template_root"],
                               token=github_provider_settings().token())


@contextmanager
def released_native_membership(root: Path, *, assets_root: Path | None = None,
                               template_root: Path | None = None,
                               provider_settings: GitHubProviderSettings | None = None,
                               api: ReleaseProvider | None = None,
                               scoped_environment: ScopedExecutionEnvironment | None = None,
                               ) -> Iterator[NativeReleaseInputs | None]:
    """Authenticate around the existing native command and restore its scope.

    API injection is the existing maintained owner's closed fixture port. Normal
    CLI and subprocess readers use the canonical read-only provider each time.
    A serialized context is never the authentication result or a provider choice.
    """
    port = scoped_execution_environment() if scoped_environment is None else scoped_environment
    settings = github_provider_settings() if provider_settings is None else provider_settings
    if assets_root is None and template_root is None:
        with port.comparison({KEY: "", "BCF_CANDIDATE_MEMBERSHIP_INPUTS": ""}):
            yield None
        return
    if assets_root is None or template_root is None:
        raise SourceComponentError("native release context: both explicit assets and template required")
    inputs = NativeReleaseInputs(assets_root, template_root, token=settings.token(), api=api)
    def authenticate() -> ReleaseMembership:
        return authenticate_release_membership(root, assets_root=inputs.assets_root,
            template_root=inputs.template_root, token=inputs.token, api=inputs.api)
    initial = authenticate()
    with port.comparison({KEY: encode_release_inputs(inputs), "BCF_CANDIDATE_MEMBERSHIP_INPUTS": ""}):
        yield inputs
    if authenticate() != initial:
        raise SourceComponentError("native release context: membership changed during native command")
