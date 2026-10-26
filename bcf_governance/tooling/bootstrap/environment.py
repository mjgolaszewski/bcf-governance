"""Governance bootstrap adapters with typed, point-of-use environment capabilities.

This is the sole OS environment owner. Read settings never cache values, child
process views distinguish live data from snapshots, and command capabilities
preserve the original mutation lifetime. No general getter is exposed except
the explicitly restricted legacy CLI composition-root compatibility port.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from pathlib import Path
from types import MappingProxyType

from ..runtime_capacity import EXECUTION_STATE_ENVIRONMENT
from .contracts import (
    ChildProcessEnvironment,
    CLIRequiredVariables,
    ComparisonSettings,
    CustodySettings,
    EvidenceSettings,
    GitHubProviderSettings,
    InvocationEnvironment,
    RuntimeSettings,
    ScopedExecutionEnvironment,
    WorkflowSettings,
)
from .ownership import COMPARISON_MUTATION_KEYS


class _ReadEnvironment:
    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._provided = values

    @property
    def _source(self) -> Mapping[str, str]:
        return os.environ if self._provided is None else self._provided


class _AllowedEnvironmentView(Mapping[str, str]):
    def __init__(self, values: Mapping[str, str], names: Iterable[str]) -> None:
        self._values = values
        self._names = tuple(dict.fromkeys(names))

    def __getitem__(self, name: str) -> str:
        if name not in self._names:
            raise KeyError(name)
        return self._values[name]

    def __iter__(self) -> Iterator[str]:
        return (name for name in self._names if name in self._values)

    def __len__(self) -> int:
        return sum(1 for _ in self)


class _GitHubProviderSettings(_ReadEnvironment):
    def token(self) -> str:
        return self._source.get('GITHUB_TOKEN', "")

    def api_url(self) -> str:
        return self._source.get('GITHUB_API_URL', "https://api.github.com")



class _WorkflowSettings(_ReadEnvironment):
    def actions(self) -> str | None:
        return self._source.get('GITHUB_ACTIONS', None)

    def repository(self, default: str) -> str:
        return self._source.get('GITHUB_REPOSITORY', default)

    def repository_id(self, default: str) -> str:
        return self._source.get('GITHUB_REPOSITORY_ID', default)

    def run_id(self, default: str) -> str:
        return self._source.get('GITHUB_RUN_ID', default)

    def run_attempt(self, default: str) -> str:
        return self._source.get('GITHUB_RUN_ATTEMPT', default)

    def job(self, default: str) -> str:
        return self._source.get('GITHUB_JOB', default)

    def workflow_ref(self, default: str) -> str:
        return self._source.get('GITHUB_WORKFLOW_REF', default)

    def head_sha(self, default: str) -> str:
        return self._source.get('GITHUB_SHA', default)



class _ComparisonSettings(_ReadEnvironment):
    def declared_bases(self) -> dict[str, str]:
        return {
            "BCF_COMPARISON_BASE_SHA": self.base_sha(),
            "BCF_ORIGIN_COMPARISON_BASE_SHA": self.origin_base_sha(),
            "BCF_CALLER_COMPARISON_BASE_SHA": self.caller_base_sha(),
            "BCF_PR_BASE_SHA": self.pr_base_sha(),
        }

    def provider_event(self) -> str:
        return self._source.get('BCF_PROVIDER_EVENT', "")

    def event_name(self) -> str:
        return self._source.get('GITHUB_EVENT_NAME', "")

    def optional_event_name(self) -> str | None:
        return self._source.get('GITHUB_EVENT_NAME', None)

    def invocation_kind(self) -> str:
        return self._source.get('BCF_INVOCATION_KIND', "")

    def base_sha(self) -> str:
        return self._source.get('BCF_COMPARISON_BASE_SHA', "")

    def origin_base_sha(self) -> str:
        return self._source.get('BCF_ORIGIN_COMPARISON_BASE_SHA', "")

    def caller_base_sha(self) -> str:
        return self._source.get('BCF_CALLER_COMPARISON_BASE_SHA', "")

    def pr_base_sha(self) -> str:
        return self._source.get('BCF_PR_BASE_SHA', "")

    def optional_pr_base_sha(self) -> str | None:
        return self._source.get('BCF_PR_BASE_SHA', None)

    def validation_lane(self, default: str) -> str:
        return self._source.get('BCF_VALIDATION_LANE', default)

    def enforce_pr_changelog(self) -> str:
        return self._source.get('BCF_ENFORCE_PR_CHANGELOG', "")



class _EvidenceSettings(_ReadEnvironment):
    def actions(self) -> str | None:
        return self._source.get('GITHUB_ACTIONS', None)

    def producer_kind(self, default: str) -> str:
        return self._source.get('BCF_EVIDENCE_PRODUCER_KIND', default)

    def producer_id(self) -> str | None:
        return self._source.get('BCF_EVIDENCE_PRODUCER_ID', None)

    def actor(self) -> str | None:
        return self._source.get('GITHUB_ACTOR', None)

    def user(self) -> str | None:
        return self._source.get('USER', None)

    def durable_input_bindings(self) -> str:
        return self._source.get('BCF_EVIDENCE_INPUT_BINDINGS', "")



class _RuntimeSettings(_ReadEnvironment):
    def virtual_env(self) -> str | None:
        return self._source.get('VIRTUAL_ENV', None)

    def portable_sdist_test(self) -> str | None:
        return self._source.get('BCF_RELEASE_SDIST_PORTABLE_TEST', None)



class _CustodySettings(_ReadEnvironment):
    def controller_execution_required(self) -> str | None:
        return self._source.get('BCF_CONTROLLER_EXECUTION_REQUIRED', None)

    def protection_inspect_required(self) -> str | None:
        return self._source.get('BCF_PROTECTION_INSPECT_REQUIRED', None)

    def controller_custody_path(self) -> str:
        return self._source.get('BCF_CONTROLLER_CUSTODY_PATH', "")

    def execution_inputs(self) -> Mapping[str, str]:
        return _AllowedEnvironmentView(self._source, EXECUTION_STATE_ENVIRONMENT)


class _ChildProcessEnvironment(_ReadEnvironment):
    def snapshot(self) -> dict[str, str]:
        return dict(self._source)

    def live(self) -> Mapping[str, str]:
        return MappingProxyType(self._source)

    def required_values(self, names: Iterable[str]) -> Mapping[str, str]:
        return _AllowedEnvironmentView(self._source, names)


class _CLIRequiredVariables(_ReadEnvironment):
    def value(self, name: str) -> str:
        return self._source.get(name, "")


class _WriteEnvironment:
    def __init__(self, values: MutableMapping[str, str] | None = None) -> None:
        self._provided = values

    @property
    def _target(self) -> MutableMapping[str, str]:
        return os.environ if self._provided is None else self._provided


class _InvocationEnvironment(_WriteEnvironment):
    def prior_splinter_root(self, value: str) -> None:
        self._target["BCF_PRIOR_SPLINTER_PROOF_ROOT"] = value

    def evidence_shard(self, value: str) -> None:
        self._target["BCF_EVIDENCE_SHARD"] = value


class _ScopedExecutionEnvironment(_WriteEnvironment):
    @contextmanager
    def comparison(self, values: Mapping[str, str | None]) -> Iterator[None]:
        if set(values) - COMPARISON_MUTATION_KEYS:
            raise ValueError("comparison environment keys are not declared")
        previous = {key: self._target.get(key) for key in values}
        for key, value in values.items():
            if value is None:
                self._target.pop(key, None)
            else:
                self._target[key] = value
        try:
            yield
        finally:
            for key, value in previous.items():
                if value is None:
                    self._target.pop(key, None)
                else:
                    self._target[key] = value

    @contextmanager
    def toolchain_path(self, node_executable: str) -> Iterator[None]:
        previous = self._target.get("PATH")
        node_directory = str(Path(node_executable).parent)
        self._target["PATH"] = node_directory + (os.pathsep + previous if previous else "")
        try:
            yield
        finally:
            if previous is None:
                self._target.pop("PATH", None)
            else:
                self._target["PATH"] = previous


def github_provider_settings(values: Mapping[str, str] | None = None) -> GitHubProviderSettings:
    return _GitHubProviderSettings(values)


def workflow_settings(values: Mapping[str, str] | None = None) -> WorkflowSettings:
    return _WorkflowSettings(values)


def comparison_settings(values: Mapping[str, str] | None = None) -> ComparisonSettings:
    return _ComparisonSettings(values)


def evidence_settings(values: Mapping[str, str] | None = None) -> EvidenceSettings:
    return _EvidenceSettings(values)


def runtime_settings(values: Mapping[str, str] | None = None) -> RuntimeSettings:
    return _RuntimeSettings(values)


def custody_settings(values: Mapping[str, str] | None = None) -> CustodySettings:
    return _CustodySettings(values)


def child_process_environment(values: Mapping[str, str] | None = None) -> ChildProcessEnvironment:
    return _ChildProcessEnvironment(values)


def cli_required_variables(values: Mapping[str, str] | None = None) -> CLIRequiredVariables:
    return _CLIRequiredVariables(values)


def invocation_environment(values: MutableMapping[str, str] | None = None) -> InvocationEnvironment:
    return _InvocationEnvironment(values)


def scoped_execution_environment(values: MutableMapping[str, str] | None = None) -> ScopedExecutionEnvironment:
    return _ScopedExecutionEnvironment(values)
