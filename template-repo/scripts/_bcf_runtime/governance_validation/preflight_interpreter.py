"""Selected-interpreter identity and virtual-environment validation."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from ..bootstrap.contracts import RuntimeSettings
from ..bootstrap.environment import runtime_settings as _default_runtime_settings
from .preflight_errors import PreflightError


def _interpreter_identity(
    python: Path,
    *,
    runtime_settings: RuntimeSettings | None=None,
) -> dict[str, str]:
    """Prove the selected executable and any lexical virtual environment agree."""
    runtime_settings = _default_runtime_settings() if runtime_settings is None else runtime_settings

    probe = (
        "import json,platform,sys\n"
        "print(json.dumps({'executable':sys.executable,'prefix':sys.prefix,"
        "'base_prefix':sys.base_prefix,'python_version':platform.python_version()},"
        "sort_keys=True))\n"
    )
    try:
        result = subprocess.run(
            [str(python), "-I", "-c", probe],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError("selected interpreter identity probe failed") from exc
    if result.returncode:
        raise PreflightError(
            "selected interpreter is not runnable: "
            + (result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown")
        )
    try:
        identity = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PreflightError("selected interpreter identity probe was invalid") from exc
    if not isinstance(identity, dict) or not all(
        isinstance(identity.get(key), str)
        for key in ("executable", "prefix", "base_prefix", "python_version")
    ):
        raise PreflightError("selected interpreter identity is incomplete")
    lexical = Path(os.path.abspath(python))
    if Path(identity["executable"]) != lexical:
        raise PreflightError("selected interpreter changed executable identity")
    environment_root = lexical.parent.parent
    venv_config = environment_root / "pyvenv.cfg"
    claims_venv = ".venv" in lexical.parts or runtime_settings.virtual_env() is not None
    if claims_venv and not venv_config.is_file():
        raise PreflightError("selected virtual environment has no pyvenv.cfg")
    if venv_config.is_file():
        config: dict[str, str] = {}
        for line in venv_config.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                config[key.strip().lower()] = value.strip()
        if Path(identity["prefix"]) != environment_root:
            raise PreflightError("selected virtual environment prefix is inconsistent")
        if identity["base_prefix"] == identity["prefix"]:
            raise PreflightError("selected virtual environment is not isolated from base Python")
        if config.get("include-system-site-packages", "false").lower() != "false":
            raise PreflightError("selected virtual environment exposes system site packages")
        declared = runtime_settings.virtual_env()
        if declared and Path(os.path.abspath(declared)) != environment_root:
            raise PreflightError("VIRTUAL_ENV does not identify the selected interpreter")
        identity["environment_kind"] = "virtualenv"
        identity["environment_root"] = str(environment_root)
    else:
        identity["environment_kind"] = "standalone"
        identity["environment_root"] = identity["prefix"]
    return {str(key): str(value) for key, value in sorted(identity.items())}

