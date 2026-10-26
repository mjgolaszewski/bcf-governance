"""Error contract shared by preflight adapters and orchestration."""

class PreflightError(ValueError):
    """Raised before evidence or expensive gates when deterministic state is invalid."""

