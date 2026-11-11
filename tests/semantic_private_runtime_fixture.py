"""Ordinary isolated consumers of the generated private package."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys


def private_package_probe(tmp_path: Path, body: str, *, inventory=None, mutate=None):
    root = Path(__file__).parents[1]
    runtime = tmp_path / "scripts/_bcf_runtime"
    shutil.copytree(
        root / "bcf_governance/pack/template-repo/scripts/_bcf_runtime", runtime,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    if inventory is not None:
        (tmp_path / "inventory.json").write_text(json.dumps(inventory))
    if mutate is not None:
        mutate(tmp_path, runtime)
    driver = tmp_path / "probe.py"
    driver.write_text(
        "import importlib.util,json,sys\nfrom pathlib import Path\n"
        "assert importlib.util.find_spec('bcf_governance') is None, 'SDK must be absent in isolated probe'\n"
        "sys.path.insert(0, str(Path(__file__).parent / 'scripts'))\n"
        + body
        + "\nassert not any(name == 'bcf_governance' or name.startswith('bcf_governance.') for name in sys.modules)\n"
    )
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "BCF_", "GIT_", "GITHUB_", "AGENTBUS_"))
                   and key not in {"GH_TOKEN", "VIRTUAL_ENV"}}
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(driver)], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    return json.loads(result.stdout)
