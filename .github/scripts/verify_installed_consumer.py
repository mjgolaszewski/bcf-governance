"""Qualify an installed distribution's consumer pack in an SDK-absent target."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root.resolve()
    # The harness is source evidence; the installer and all imported runtime
    # helpers must come from the installed distribution in this interpreter.
    sys.path[:] = [item for item in sys.path if item and Path(item).resolve() != source]
    import bcf_governance

    package = Path(bcf_governance.__file__).resolve()
    if not package.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("consumer verification requires an installed BCF distribution")
    sys.path.insert(0, str(source / "tests"))
    from test_installed_evidence_storage import (
        create_isolated_python, exercise_installed_consumer,
    )

    from test_installed_provider_error_retirement_siblings import (
        exercise_installed_sibling_retirement,
    )

    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    with tempfile.TemporaryDirectory(prefix="bcf-installed-consumer-") as temporary:
        root = Path(temporary)
        consumer = root / "consumer"
        consumer.mkdir()
        subprocess.run(["git", "init", "--quiet"], cwd=consumer, check=True, env=environment)
        command = [
            sys.executable, "-m", "bcf_governance.cli", "install",
            "--target", str(consumer), "--profile", "lite", "--skip-validation",
            "--project-id", "consumer-qualification", "--project-name", "Consumer Qualification",
            "--product-name", "Consumer Qualification",
            "--candidate-runner-label", "ubuntu-24.04", "--candidate-runner-kind", "hosted",
            "--trusted-runner-label", "ubuntu-24.04", "--trusted-runner-kind", "hosted",
        ]
        installed = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True)
        if installed.returncode:
            raise RuntimeError(installed.stdout + installed.stderr)
        python = create_isolated_python(root / "consumer-python")
        fresh_siblings = exercise_installed_sibling_retirement(consumer, python)
        project_owned = consumer / "project-owned-sibling-qualification.txt"
        project_owned.write_bytes(b"project-owned bytes\n")
        project_owned.chmod(0o640)
        preserved = project_owned.read_bytes(), project_owned.stat().st_mode
        upgrade_command = [*command, "--upgrade"]
        upgraded = subprocess.run(
            upgrade_command, cwd=root, env=environment, capture_output=True, text=True,
        )
        if upgraded.returncode:
            raise RuntimeError(upgraded.stdout + upgraded.stderr)
        if (project_owned.read_bytes(), project_owned.stat().st_mode) != preserved:
            raise RuntimeError("installed SDK upgrade changed project-owned bytes or mode")
        upgrade_siblings = exercise_installed_sibling_retirement(consumer, python)
        report = exercise_installed_consumer(consumer, python, root / "acceptance")
        report["sibling_response_retirement"] = {
            "fresh": fresh_siblings, "upgrade": upgrade_siblings,
            "project_owned_preserved": True,
            "upgrade_installer": {"argv": upgrade_command, "exit_code": upgraded.returncode},
        }
        report["installed_package"] = str(package)
        report["installer"] = {"argv": command, "exit_code": installed.returncode}
        print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
