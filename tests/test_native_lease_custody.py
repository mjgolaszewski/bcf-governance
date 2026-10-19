"""Real descriptor-lifetime controls for the existing native lease owner."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

import pytest

from bcf_governance.tooling.local_execution_admission import local_gate_lease
from bcf_governance.tooling.runtime_capacity import (
    EXECUTION_STATE_ENVIRONMENT,
    allocate_execution_state,
    retire_execution_state,
)
from tests.test_local_execution_admission import _runtime_contract


@pytest.fixture
def lease_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in EXECUTION_STATE_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    state = allocate_execution_state(
        tmp_path, _runtime_contract(), session_id=tmp_path.name,
        workload_id="native-custody-control", execution_id="descriptor", invocation={},
    )
    for name, value in state.environment().items():
        monkeypatch.setenv(name, value)
    try:
        yield Path(f"/tmp/bcf-local-gate-{os.getuid()}-{state.namespace}.lock")
    finally:
        retire_execution_state(state)


def _busy(path: Path) -> bool:
    with path.open("r+") as probe:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(probe, fcntl.LOCK_UN)
        return False


def _descriptor(path: Path) -> int:
    expected = path.stat()
    found = []
    for entry in Path("/proc/self/fd").iterdir():
        try:
            value = os.fstat(int(entry.name))
        except OSError:
            continue
        if (value.st_dev, value.st_ino) == (expected.st_dev, expected.st_ino):
            found.append(int(entry.name))
    assert len(found) == 1, "fixture must identify the actual acquired descriptor"
    return found[0]


def test_native_lease_releases_after_ordinary_unbound_scope(lease_path: Path) -> None:
    with local_gate_lease("a" * 40):
        identity = lease_path.stat()
        assert _busy(lease_path)
    assert not _busy(lease_path)


@pytest.mark.parametrize("consumer", ["workflow-authority", "authority-transition"])
def test_git_authority_stdin_has_real_native_custody(
    lease_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, consumer: str,
) -> None:
    import hashlib
    import shutil
    from bcf_governance.tooling import ci_authority_pins, reconcile_authority_transition
    from bcf_governance.tooling import evidence_process_supervisor

    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True)
    binary = tmp_path / "git"
    payload = b"native stdin\x00\xff\n"
    expected = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\x00" + payload).hexdigest()
    with local_gate_lease("8" * 40):
        identity = lease_path.stat()
        binary.write_text(f"""#!{sys.executable}
import json,os,sys
from pathlib import Path
parent=Path('/proc',str(os.getppid()))
expected=({identity.st_dev},{identity.st_ino})
def has_lease(root):
    for entry in (root/'fd').iterdir():
        try: value=entry.stat()
        except FileNotFoundError: continue
        if (value.st_dev,value.st_ino)==expected: return True
    return False
owned={str(Path(evidence_process_supervisor.__file__).resolve())!r}.encode() in (parent/'cmdline').read_bytes().split(bytes([0]))
parent_lease=has_lease(parent)
command_lease=has_lease(Path('/proc/self'))
Path({str(tmp_path / 'git-custody-observation.json')!r}).write_text(json.dumps(dict(guardian=owned,parent_lease=parent_lease,command_lease=command_lease)))
if not owned or not parent_lease or command_lease:
    print('git-stdin-native-owner-bypassed',file=sys.stderr)
    sys.exit(23)
os.execv({git!r},[{git!r},*sys.argv[1:]])
""")
        binary.chmod(0o700)
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
        owner = ci_authority_pins if consumer == "workflow-authority" else reconcile_authority_transition
        try:
            actual = owner._git(tmp_path, "hash-object", "--stdin", input_bytes=payload)
        finally:
            observation = tmp_path / "git-custody-observation.json"
            assert observation.is_file(), "real Git fixture never observed its native parent"
            print("real Git custody observation:", observation.read_text())
        assert actual.strip() == expected.encode()
    assert not _busy(lease_path)


@pytest.mark.parametrize("payload,text", [(b"\x00\xff\n", False), ("mañana\r\n", True), (b"", False), ("", True)])
def test_bound_native_stdin_delivers_exact_bytes(lease_path: Path, payload, text: bool) -> None:
    import hashlib
    import locale
    from bcf_governance.tooling.evidence_process_supervisor import run_admitted_command

    expected = payload.encode("utf-8" if sys.flags.utf8_mode else locale.getencoding()) if text else payload
    program = "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"
    with local_gate_lease("7" * 40):
        result = run_admitted_command(
            [sys.executable, "-I", "-c", program], capture_output=True, text=text,
            input=payload, timeout=5, check=True,
        )
        digest = result.stdout.strip()
        assert digest == (hashlib.sha256(expected).hexdigest() if text else hashlib.sha256(expected).hexdigest().encode())
    assert not _busy(lease_path)


def test_bound_native_none_input_preserves_inherited_stdin(lease_path: Path) -> None:
    from bcf_governance.tooling.evidence_process_supervisor import run_admitted_command

    identity = os.fstat(0)
    program = "import os; s=os.fstat(0); print(str(s.st_dev)+':'+str(s.st_ino))"
    with local_gate_lease("6" * 40):
        result = run_admitted_command(
            [sys.executable, "-I", "-c", program], capture_output=True, text=True,
            input=None, timeout=5, check=True,
        )
        assert result.stdout.strip() == f"{identity.st_dev}:{identity.st_ino}"


def test_bound_native_unread_large_input_cannot_stall_timeout(lease_path: Path) -> None:
    from bcf_governance.tooling.evidence_process_supervisor import run_admitted_command

    with local_gate_lease("5" * 40):
        with pytest.raises(subprocess.TimeoutExpired):
            run_admitted_command(
                [sys.executable, "-I", "-c", "import time; time.sleep(10)"],
                capture_output=True, input=b"x" * 1048576, timeout=.05,
            )
        assert _busy(lease_path)
    assert not _busy(lease_path)


@pytest.mark.parametrize("payload,text", [("wrong", False), (b"wrong", True), (23, False)])
def test_bound_native_invalid_input_rejects_before_child(
    lease_path: Path, tmp_path: Path, payload, text: bool,
) -> None:
    from bcf_governance.tooling.evidence_process_supervisor import OwnedProcessError, run_admitted_command

    marker = tmp_path / "invalid-stdin-child"
    with local_gate_lease("4" * 40):
        with pytest.raises((TypeError, OwnedProcessError)):
            run_admitted_command(
                [sys.executable, "-I", "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).touch()", str(marker)],
                capture_output=True, text=text, input=payload,
            )
        assert not marker.exists()


def test_bound_native_failed_exec_closes_input_descriptors(lease_path: Path) -> None:
    from bcf_governance.tooling.evidence_process_supervisor import run_admitted_command

    def descriptors():
        values = set()
        for entry in Path('/proc/self/fd').iterdir():
            try: values.add((entry.name, os.readlink(entry)))
            except FileNotFoundError: pass
        return values

    with local_gate_lease("3" * 40):
        before = descriptors()
        with pytest.raises(FileNotFoundError):
            run_admitted_command(
                [str(lease_path.parent / "missing-stdin-executable")],
                capture_output=True, input=b"owned input", timeout=5,
            )
        assert descriptors() == before
    assert lease_path.stat().st_ino == identity.st_ino


def test_native_lease_remains_owned_by_inherited_descriptor(lease_path: Path) -> None:
    child = None
    try:
        with local_gate_lease("b" * 40):
            descriptor = _descriptor(lease_path)
            identity = lease_path.stat()
            program = (
                "import os,sys; fd=int(sys.argv[1]); s=os.fstat(fd); "
                "assert (s.st_dev,s.st_ino)==(int(sys.argv[2]),int(sys.argv[3])); "
                "print('ready',flush=True); sys.stdin.buffer.read()"
            )
            child = subprocess.Popen(
                [sys.executable, "-I", "-c", program, str(descriptor),
                 str(identity.st_dev), str(identity.st_ino)],
                pass_fds=(descriptor,), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            assert child.stdout is not None
            assert select.select([child.stdout], [], [], 5)[0], "holder startup failed"
            assert child.stdout.readline() == b"ready\n"
            assert child.poll() is None
        assert child.poll() is None, "real inherited holder must still be alive"
        assert _busy(lease_path), "lease became free while its inherited descriptor was live"
    finally:
        if child is not None:
            try:
                child.communicate(input=b"stop", timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
    assert child is not None and child.returncode == 0
    assert not _busy(lease_path)


def test_native_command_supervisor_holds_actual_lease(lease_path: Path) -> None:
    from bcf_governance.tooling.evidence_process_supervisor import run_owned_command

    # Inspect the real kernel guardian from its command, before any cancellation.
    # A command inheriting the descriptor accidentally is insufficient custody.
    program = """
import os
from pathlib import Path
import sys
expected = (int(sys.argv[1]), int(sys.argv[2]))
found = False
for entry in Path('/proc', str(os.getppid()), 'fd').iterdir():
    try:
        value = entry.stat()
    except FileNotFoundError:
        continue
    found |= (value.st_dev, value.st_ino) == expected
print('guardian-owns-lease' if found else 'guardian-missing-lease', flush=True)
sys.exit(0 if found else 23)
"""
    with local_gate_lease("c" * 40):
        identity = lease_path.stat()
        result = run_owned_command(
            [sys.executable, "-I", "-c", program,
             str(identity.st_dev), str(identity.st_ino)],
            cwd=lease_path.parent, env=os.environ.copy(),
            timeout_seconds=5, cleanup_seconds=2,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout == "guardian-owns-lease\n"
        assert _busy(lease_path)
    assert not _busy(lease_path)


def _wait_for(predicate, seconds: float = 5) -> None:
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "real-process fixture readiness timed out"
        time.sleep(0.01)


@pytest.mark.parametrize("interruption", [signal.SIGINT, signal.SIGTERM, signal.SIGKILL])
def test_native_guardian_retains_lease_after_parent_interruption(
    lease_path: Path, tmp_path: Path, interruption: int,
) -> None:
    from bcf_governance.tooling import local_execution_admission

    marker = tmp_path / "command-ready.json"
    runtime_root = Path(local_execution_admission.__file__).resolve().parents[2]
    command = (
        "import json,os,sys,time; "
        "from pathlib import Path; "
        "target=Path(sys.argv[1]); staged=target.with_suffix('.new'); "
        "staged.write_text(json.dumps([os.getppid(),os.getpid()])); staged.replace(target); "
        "time.sleep(15)"
    )
    worker = """
import sys
sys.path.insert(0, sys.argv[1])
from bcf_governance.tooling.local_execution_admission import local_gate_lease
from bcf_governance.tooling.evidence_process_supervisor import run_owned_command
import os
with local_gate_lease('d' * 40):
    run_owned_command([sys.executable, '-I', '-c', sys.argv[3], sys.argv[2]],
                      cwd=os.getcwd(), env=os.environ.copy(),
                      timeout_seconds=10, cleanup_seconds=2)
"""
    owner = subprocess.Popen(
        [sys.executable, "-I", "-c", worker, str(runtime_root), str(marker), command],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    guardian = None
    try:
        _wait_for(marker.exists)
        guardian, child = json.loads(marker.read_text())
        assert Path('/proc', str(child)).exists(), "command must be live before interruption"
        assert _busy(lease_path), "worker must actually hold its acquired lease"
        # Freeze the known guardian to make parent death precede child cleanup.
        # This does not alter the lease or grant another native allocation.
        os.kill(guardian, signal.SIGSTOP)
        _wait_for(lambda: Path('/proc', str(guardian), 'stat').read_text().split()[2] == 'T')
        owner.send_signal(interruption)
        _wait_for(lambda: owner.poll() is not None)
        assert Path('/proc', str(child)).exists(), "live child is the custody subject"
        assert _busy(lease_path), "parent interruption released capacity before child cleanup"
    finally:
        if guardian is not None:
            os.kill(guardian, signal.SIGCONT)
        if owner.poll() is None:
            owner.kill()
        owner.communicate(timeout=5)
        # Resumed guardian observes the dead parent's channel and owns cleanup.
        # Do not kill or unlock it to make this assertion pass.
        _wait_for(lambda: not _busy(lease_path))


def test_expired_cleanup_retains_lease_without_late_kill(
    lease_path: Path, tmp_path: Path,
) -> None:
    from bcf_governance.tooling import local_execution_admission

    marker = tmp_path / "expired-ready.json"
    runtime_root = Path(local_execution_admission.__file__).resolve().parents[2]
    command = (
        "import json,os,sys,time; from pathlib import Path; "
        "target=Path(sys.argv[1]); staged=target.with_suffix('.new'); "
        "staged.write_text(json.dumps([os.getppid(),os.getpid()])); staged.replace(target); "
        "time.sleep(15)"
    )
    worker = """
import os,sys
sys.path.insert(0, sys.argv[1])
from bcf_governance.tooling.local_execution_admission import local_gate_lease
from bcf_governance.tooling.evidence_process_supervisor import run_owned_command
with local_gate_lease('e' * 40):
    run_owned_command([sys.executable, '-I', '-c', sys.argv[3], sys.argv[2]],
                      cwd=os.getcwd(), env=os.environ.copy(),
                      timeout_seconds=1, cleanup_seconds=1)
"""
    owner = subprocess.Popen(
        [sys.executable, "-I", "-c", worker, str(runtime_root), str(marker), command],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    guardian = child = None
    child_start = None
    try:
        _wait_for(marker.exists)
        guardian, child = json.loads(marker.read_text())
        child_stat = Path('/proc', str(child), 'stat')
        child_start = child_stat.read_text().rsplit(')', 1)[1].split()[19]
        os.kill(guardian, signal.SIGSTOP)
        _wait_for(lambda: Path('/proc', str(guardian), 'stat').read_text().split()[2] == 'T')
        owner.kill()
        owner.communicate(timeout=5)
        time.sleep(2.1)  # Both declared body and cleanup boundaries now expired.
        os.kill(guardian, signal.SIGCONT)
        time.sleep(0.1)
        assert child_stat.read_text().split()[2] != 'Z', "late cleanup killed the live child"
        assert _busy(lease_path), "expired cleanup released unresolved native custody"
    finally:
        if guardian is not None:
            try:
                os.kill(guardian, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if owner.poll() is None:
            owner.kill()
        owner.communicate(timeout=5)
        if child is not None and Path('/proc', str(child), 'stat').exists():
            current = Path('/proc', str(child), 'stat').read_text().rsplit(')', 1)[1].split()
            assert current[19] == child_start, "fixture cannot signal a recycled identity"
            os.kill(child, signal.SIGKILL)  # Explicit reconciliation of this fixture's child.
        _wait_for(lambda: not _busy(lease_path))


@pytest.mark.parametrize("consumer", ["submission-runner", "reconciliation-runner"])
def test_native_runner_allocates_through_kernel_guardian(
    lease_path: Path, consumer: str,
) -> None:
    from bcf_governance.tooling import evidence_process_supervisor, local_pr_context
    from bcf_governance.tooling import scaffold_governance_artifacts

    helper = Path(evidence_process_supervisor.__file__).resolve()
    program = """
import os,sys
from pathlib import Path
parent = Path('/proc', str(os.getppid()))
arguments = (parent / 'cmdline').read_bytes().split(bytes([0]))
owned = os.fsencode(sys.argv[1]) in arguments
expected = (int(sys.argv[2]), int(sys.argv[3]))
found = False
for entry in (parent / 'fd').iterdir():
    try:
        value = entry.stat()
    except FileNotFoundError:
        continue
    found |= (value.st_dev, value.st_ino) == expected
print('qualified-native-owner' if owned and found else 'native-owner-bypassed', flush=True)
sys.exit(0 if owned and found else 23)
"""
    with local_gate_lease("f" * 40):
        identity = lease_path.stat()
        command = [sys.executable, "-I", "-c", program, str(helper),
                   str(identity.st_dev), str(identity.st_ino)]
        if consumer == "submission-runner":
            result = local_pr_context._run(command, cwd=lease_path.parent)
            assert result.returncode == 0, result.stdout + result.stderr
        else:
            scaffold_governance_artifacts._run_reconcile_command(
                command, repo_root=lease_path.parent, step_id="native-custody-control",
            )
    assert not _busy(lease_path)


def test_bound_native_runner_preserves_failed_exec_exception(lease_path: Path) -> None:
    from bcf_governance.tooling.local_pr_context import _run

    with local_gate_lease("1" * 40):
        with pytest.raises(FileNotFoundError):
            _run([str(lease_path.parent / "absent-native-custody-executable")],
                 cwd=lease_path.parent)
    assert not _busy(lease_path)


def test_bound_native_runner_preserves_binary_output(lease_path: Path) -> None:
    from bcf_governance.tooling.evidence_process_supervisor import run_admitted_command

    with local_gate_lease("2" * 40):
        result = run_admitted_command(
            [sys.executable, "-I", "-c", "import os; os.write(1, bytes([255,0,13,10]))"],
            capture_output=True, check=False,
        )
        assert result.returncode == 0
        assert result.stdout == bytes([255, 0, 13, 10])
        assert result.stderr == b""
    assert not _busy(lease_path)


def test_bound_native_runner_preserves_timeout_exception(lease_path: Path) -> None:
    from bcf_governance.tooling.local_pr_context import _run

    with local_gate_lease("3" * 40):
        with pytest.raises(subprocess.TimeoutExpired):
            _run([sys.executable, "-I", "-c", "import time; time.sleep(5)"],
                 cwd=lease_path.parent, timeout=0.1)
        assert _busy(lease_path)
    assert not _busy(lease_path)


def test_native_supervisor_retains_every_enclosing_lease(
    lease_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bcf_governance.tooling.evidence_process_supervisor import run_owned_command

    second = allocate_execution_state(
        tmp_path, _runtime_contract(), session_id=tmp_path.name + "-nested",
        workload_id="native-custody-control", execution_id="nested", invocation={},
    )
    inner = Path(f"/tmp/bcf-local-gate-{os.getuid()}-{second.namespace}.lock")
    program = """
import json,os,sys
from pathlib import Path
expected = {tuple(row) for row in json.loads(sys.argv[1])}
observed = set()
for entry in Path('/proc', str(os.getppid()), 'fd').iterdir():
    try:
        value = entry.stat()
    except FileNotFoundError:
        continue
    observed.add((value.st_dev, value.st_ino))
assert expected.issubset(observed), 'guardian omitted an enclosing acquired lease'
for entry in Path('/proc/self/fd').iterdir():
    try:
        value = entry.stat()
    except FileNotFoundError:
        continue
    assert (value.st_dev, value.st_ino) not in expected, 'command leaked the guardian lease'
"""
    try:
        with local_gate_lease("4" * 40):
            for name, value in second.environment().items():
                monkeypatch.setenv(name, value)
            with local_gate_lease("5" * 40):
                identities = [[p.stat().st_dev, p.stat().st_ino] for p in [lease_path, inner]]
                result = run_owned_command(
                    [sys.executable, "-I", "-c", program, json.dumps(identities)],
                    cwd=tmp_path, env=os.environ.copy(), timeout_seconds=5, cleanup_seconds=2,
                )
                assert result.returncode == 0, result.stdout + result.stderr
            assert not _busy(inner)
            assert _busy(lease_path)
        assert not _busy(lease_path)
    finally:
        retire_execution_state(second)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), float("-inf"), True, 0, -1])
def test_invalid_native_timeout_rejects_before_command_allocation(
    lease_path: Path, tmp_path: Path, timeout,
) -> None:
    from bcf_governance.tooling.evidence_process_supervisor import (
        OwnedProcessError, run_admitted_command,
    )

    marker = tmp_path / "invalid-timeout-allocated-command"
    program = "from pathlib import Path; import sys; Path(sys.argv[1]).touch()"
    with local_gate_lease("6" * 40):
        with pytest.raises(OwnedProcessError, match="timeout"):
            run_admitted_command(
                [sys.executable, "-I", "-c", program, str(marker)],
                cwd=tmp_path, capture_output=True, text=True, timeout=timeout,
            )
        assert not marker.exists(), "invalid native deadline allocated its command"
    assert not _busy(lease_path)


@pytest.mark.parametrize("consumer", ["shell-syntax", "interpreter-identity"])
def test_preflight_children_observe_native_guardian(
    lease_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, consumer: str,
) -> None:
    from bcf_governance.tooling import evidence_process_supervisor, preflight

    # An actual executable fixture observes its kernel parent and descriptor table.
    # It produces valid syntax/identity output only after proving custody.
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    binary = tmp_path / ("bash" if consumer == "shell-syntax" else "identity-python")
    with local_gate_lease("9" * 40):
        identity = lease_path.stat()
        program = f"""#!{sys.executable}
import json,os,sys
from pathlib import Path
parent=Path('/proc',str(os.getppid()))
expected=({identity.st_dev},{identity.st_ino})
def descriptors(root):
    found=False
    for entry in (root/'fd').iterdir():
        try: value=entry.stat()
        except FileNotFoundError: continue
        found |= (value.st_dev,value.st_ino)==expected
    return found
owned={str(Path(evidence_process_supervisor.__file__).resolve())!r}.encode() in (parent/'cmdline').read_bytes().split(bytes([0]))
if not owned or not descriptors(parent) or descriptors(Path('/proc/self')):
    print('preflight-native-owner-bypassed',file=sys.stderr)
    sys.exit(23)
if {consumer!r}=='interpreter-identity':
    print(json.dumps(dict(executable={str(binary)!r},prefix=sys.prefix,base_prefix=sys.base_prefix,python_version='3.12.0')))
"""
        binary.write_text(program)
        binary.chmod(0o700)
        if consumer == "shell-syntax":
            shell = tmp_path / "fixture.sh"
            shell.write_text("true\n")
            monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
            monkeypatch.setattr(preflight, "_tracked_files", lambda _: [shell])
            assert preflight._syntax_checks(tmp_path) == {"python": 0, "yaml": 0, "json": 0, "shell": 1}
        else:
            assert preflight._interpreter_identity(binary)["executable"] == str(binary)
    assert not _busy(lease_path)
