"""Typed provider-boundary failures shared by GitHub API facets."""


class GitHubAPIError(ValueError):
    """Provider state cannot be obtained or authenticated safely."""


class GitHubAPIConflictError(GitHubAPIError):
    """A concurrent exact provider mutation may have won the race."""
