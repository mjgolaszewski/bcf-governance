from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from bcf_governance.tooling.interpreter_environment import (
    apply_interpreter_environment_projection,
    derive_interpreter_environment,
    materialize_interpreter_environment,
)
from bcf_governance.tooling.interpreter_environment_launchers import (
    launcher_custody,
    relocate_environment_launchers,
)
from bcf_governance.tooling.interpreter_environment_plan import InterpreterEnvironmentError
from tests.test_interpreter_environment import _fixture


def test_relocation_preserves_shell_launcher_activation_record_and_binary(tmp_path: Path) -> None:
    staged = tmp_path / ("long stage " + "x" * 150) / "venv"
    published = tmp_path / "published" / "venv"
    (staged / "bin").mkdir(parents=True)
    python = staged / "bin/python"
    python.symlink_to(sys.executable)
    (staged / "pyvenv.cfg").write_text(
        "home = " + str(Path(sys.executable).resolve().parent) + "\n"
        "command = python -m venv " + str(staged) + "\n"
    )
    console = staged / "bin/console"
    console.write_text(
        "#!/bin/sh\n'''exec' '" + str(python) + "' \"$0\" \"$@\"\n' '''\n"
        "print('shell-launcher-ran')\n"
    )
    console.chmod(0o755)
    activate = staged / "bin/activate"
    activate.write_text("VIRTUAL_ENV='" + str(staged) + "'\n")
    binary = staged / "bin/native-tool"
    binary.write_bytes(b"\x7fELF\0unchanged")
    binary.chmod(0o755)
    record = staged / "lib/python3.12/site-packages/example.dist-info/RECORD"
    record.parent.mkdir(parents=True)
    record.write_text("../../../bin/console,sha256=old,1\nexample.dist-info/RECORD,,\n")

    expected = relocate_environment_launchers(staged, published)
    assert str(staged) not in console.read_text()
    assert str(published) in activate.read_text()
    assert str(published) in (staged / "pyvenv.cfg").read_text()
    assert binary.read_bytes() == b"\x7fELF\0unchanged"
    assert console.stat().st_mode & 0o777 == 0o755
    rows = list(csv.reader(io.StringIO(record.read_text())))
    digest = base64.urlsafe_b64encode(hashlib.sha256(console.read_bytes()).digest()).rstrip(b"=")
    assert rows[0] == ["../../../bin/console", "sha256=" + digest.decode(), str(console.stat().st_size)]
    assert rows[1] == ["example.dist-info/RECORD", "", ""]
    published.parent.mkdir()
    staged.rename(published)
    assert launcher_custody(published) == expected
    result = subprocess.run([str(published / "bin/console")], capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode == 0
    assert result.stdout == "shell-launcher-ran\n"


@pytest.mark.parametrize("change", ["bytes", "mode", "legacy_manifest"])
def test_cached_materialization_rejects_launcher_custody_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    apply_interpreter_environment_projection(plan)

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ["-m", "venv"]:
            venv = Path(argv[-1])
            (venv / "bin").mkdir(parents=True)
            (venv / "bin/python").symlink_to(sys.executable)
            (venv / "pyvenv.cfg").write_text("home = exact\n")
            (venv / "bin/console").write_text("#!" + str(venv / "bin/python") + "\n")
        output = "pip==26.2.2\nPyYAML==6.0.3\n" if argv[-2:] == ["freeze", "--all"] else ""
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(subprocess, "run", run)
    python = materialize_interpreter_environment(tmp_path, Path(sys.executable))
    if change == "legacy_manifest":
        manifest = python.parent.parent.parent / "environment.json"
        payload = json.loads(manifest.read_text())
        payload["schema_version"] = "1.0"
        payload.pop("launchers_sha256")
        manifest.write_text(json.dumps(payload))
    elif change == "mode":
        (python.parent / "console").chmod(0o700)
    else:
        (python.parent / "console").write_text("#!/deleted/environment/python\n")
    with pytest.raises(InterpreterEnvironmentError, match="stale"):
        materialize_interpreter_environment(tmp_path, Path(sys.executable))


def test_binary_with_embedded_build_prefix_fails_before_publish(tmp_path: Path) -> None:
    staged = tmp_path / "staged"
    (staged / "bin").mkdir(parents=True)
    (staged / "pyvenv.cfg").write_text("home = exact\n")
    binary = staged / "bin/tool"
    original = b"\x7fELF\0" + bytes(staged)
    binary.write_bytes(original)
    with pytest.raises(InterpreterEnvironmentError, match="binary embeds"):
        relocate_environment_launchers(staged, tmp_path / "published")
    assert binary.read_bytes() == original
    assert not (tmp_path / "published").exists()
