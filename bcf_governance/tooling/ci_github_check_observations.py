"""Bounded read-only GitHub check observation operations."""

from __future__ import annotations

from typing import Any

from .ci_github_values import GitHubValueError, positive_id, repository


class GitHubCheckObservationMixin:
    """Read exact check annotations without adding mutation capability."""

    def _request(self, method: str, path: str, **kwargs: Any) -> Any: ...

    def check_run_annotations(
        self, repository_name: str, check_run_id: str | int
    ) -> tuple[dict[str, Any], ...]:
        """Return the complete bounded annotation inventory for one check run."""

        try:
            exact_repository = repository(repository_name)
            numeric = positive_id(check_run_id, field="check run ID")
        except GitHubValueError as exc:
            raise ValueError(str(exc)) from exc
        value = self._request(
            "GET",
            f"/repos/{exact_repository}/check-runs/"
            f"{numeric}/annotations?per_page=100",
        )
        if not isinstance(value, list) or any(
            not isinstance(item, dict) for item in value
        ):
            raise ValueError(
                "check-run annotation response must contain an object list"
            )
        if len(value) == 100:
            raise ValueError(
                "check-run annotation inventory exceeds one authenticated page"
            )
        return tuple(value)
