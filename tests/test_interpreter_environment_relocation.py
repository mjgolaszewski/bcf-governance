"""Causal launcher regression proposal; execute only in a Recovery allocation."""
import subprocess
import sys
from pathlib import Path

import pytest

from bcf_governance.tooling.interpreter_environment import (
    apply_interpreter_environment_projection,
    derive_interpreter_environment,
    materialize_interpreter_environment,
)
from tests.test_interpreter_environment import _fixture


def test_materialized_console_launcher_executes_after_atomic_cache_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    apply_interpreter_environment_projection(plan)
    real_run = subprocess.run
    builds: list[Path] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ['-m', 'venv']:
            venv = Path(argv[-1])
            builds.append(venv)
            (venv / 'bin').mkdir(parents=True)
            (venv / 'bin/python').symlink_to(sys.executable)
            (venv / 'pyvenv.cfg').write_text('home = ' + str(Path(sys.executable).resolve().parent) + '\ninclude-system-site-packages = false\n')
            launcher = venv / 'bin/causal-console'
            launcher.write_text(
                "#!/bin/sh\n'''exec' '" + str(venv / 'bin/python')
                + "' \"$0\" \"$@\"\n' '''\nprint(\"launcher-ran\")\n"
            )
            launcher.chmod(0o755)
        stdout = 'pip==26.2.2\nPyYAML==6.0.3\n' if argv[-2:] == ['freeze', '--all'] else ''
        return subprocess.CompletedProcess(argv, 0, stdout, '')

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, 'run', run)
        selected = materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert selected.is_file()
    assert len(builds) == 1 and not builds[0].exists()
    launcher = selected.parent / 'causal-console'
    assert launcher.is_file()
    # Uses the actual kernel shebang interpreter lookup after native rename.
    result = real_run([str(launcher)], capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode == 0
    assert result.stdout == 'launcher-ran\n'
