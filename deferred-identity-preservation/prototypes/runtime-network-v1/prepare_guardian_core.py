"""Mechanical typed backport plus explicit inherited native-lease custody."""
from pathlib import Path
import ast,hashlib,json
base=Path(__file__).resolve().parent
source=Path('/docker/.agentbus-private-retention/rc9-reboot-20261020T235034Z/helpers/owned_tree.py')
raw=source.read_bytes();assert hashlib.sha256(raw).hexdigest()=='71fd1f0627f2556feeaf7cd9c39f7a8c36d2089d3ac4956446abaee78d9b796f'
s=raw.decode().replace('import ctypes\n','import ctypes\nimport fcntl\nimport re\nimport stat\n').replace('import time\n','import time\nfrom typing import Any\n',1)
replacements={
'def _send(connection, value):':'def _send(connection: socket.socket, value: dict[str, Any]) -> None:',
'def _receive(connection, deadline):':'def _receive(connection: socket.socket, deadline: float) -> dict[str, Any]:',
'def _terminal_result(value, supervisor_pid):':'def _terminal_result(value: Any, supervisor_pid: int) -> dict[str, Any]:',
'def _observe(process, connection, selector, buffers, deadline):':'def _observe(process: subprocess.Popen[bytes], connection: socket.socket, selector: selectors.BaseSelector, buffers: dict[str, list[bytes]], deadline: float) -> dict[str, Any]:',
'def run_owned_command(command, *, cwd, env, timeout_seconds, cleanup_seconds):':'def run_owned_command(command: list[str], *, cwd: Path, env: dict[str, str] | None, timeout_seconds: float, cleanup_seconds: float, lease_descriptors: tuple[int, ...] = ()) -> subprocess.CompletedProcess[str]:',
'def _subreaper():':'def _subreaper() -> None:',
'def _reap(command):':'def _reap(command: subprocess.Popen[bytes]) -> bool:',
'def _kill_owned_children():':'def _kill_owned_children() -> None:',
'def _supervise(connection, body_deadline, cleanup_seconds):':'def _supervise(connection: socket.socket, body_deadline: float, cleanup_seconds: float, native_leases: tuple[tuple[int, int, int], ...] = ()) -> None:',
}
for before,after in replacements.items():assert s.count(before)==1,before;s=s.replace(before,after)
s=s.replace('    return json.loads(line)','    value = json.loads(line)\n    if not isinstance(value, dict):\n        raise OwnedProcessError("supervisor frame must be an object")\n    return value',1)
s=s.replace('    start = time.monotonic()\n    body_deadline', '''    leases: list[list[int]] = []
    for descriptor in lease_descriptors:
        if type(descriptor) is not int or descriptor <= 2:
            raise OwnedProcessError("native lease descriptor is invalid")
        identity = os.fstat(descriptor)
        if not stat.S_ISREG(identity.st_mode):
            raise OwnedProcessError("native lease is not a regular locked descriptor")
        leases.append([descriptor, identity.st_dev, identity.st_ino])
    if len(set(lease_descriptors)) != len(lease_descriptors):
        raise OwnedProcessError("native lease descriptors are duplicated")
    lease_arguments = [str(value) for lease in leases for value in lease]
    start = time.monotonic()
    body_deadline''',1)
s=s.replace('str(body_deadline), str(cleanup_seconds)],','str(body_deadline), str(cleanup_seconds), *lease_arguments],',1)
s=s.replace('pass_fds=(inherited.fileno(),),','pass_fds=(inherited.fileno(), *lease_descriptors),',1)
s=s.replace("        if (not isinstance(ready, dict) or type(ready.get('supervisor_pid')) is not int\n                or ready != {'type': 'ready', 'supervisor_pid': process.pid}):", "        expected_ready: dict[str, Any] = {'type': 'ready', 'supervisor_pid': process.pid}\n        if leases:\n            expected_ready['native_leases'] = leases\n        if (not isinstance(ready, dict) or type(ready.get('supervisor_pid')) is not int\n                or ready != expected_ready):",1)
s=s.replace("                stream.close()","                if stream is not None:\n                    stream.close()",1)
needle="    _send(connection, {'type': 'ready', 'supervisor_pid': os.getpid()})"
assert needle in s
s=s.replace(needle,'''    ready: dict[str, Any] = {'type': 'ready', 'supervisor_pid': os.getpid()}
    for descriptor, device, inode in native_leases:
        identity = os.fstat(descriptor)
        if (descriptor <= 2 or descriptor == connection.fileno()
                or not stat.S_ISREG(identity.st_mode)
                or (identity.st_dev, identity.st_ino) != (device, inode)
                or not re.search(r"\\bFLOCK\\s+ADVISORY\\s+WRITE\\b",
                                 Path(f"/proc/self/fdinfo/{descriptor}").read_text())):
            raise OwnedProcessError("inherited original native lease is not authenticated")
    if native_leases:
        ready['native_leases'] = [list(row) for row in native_leases]
    _send(connection, ready)''',1)
a=s.index("if __name__ == '__main__':")
s=s[:a]+'''def _retain_native_custody() -> None:
    """Observe only after the cleanup budget; never extend signalling authority."""
    while True:
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            return
        except OSError:
            pass
        time.sleep(0.05)


if __name__ == '__main__':
    with socket.socket(fileno=int(sys.argv[1])) as _connection:
        try:
            if (len(sys.argv) - 4) % 3:
                raise OwnedProcessError('inherited native lease binding is incomplete')
            _leases = tuple(tuple(int(value) for value in sys.argv[offset:offset + 3])
                            for offset in range(4, len(sys.argv), 3))
            _supervise(_connection, float(sys.argv[2]), float(sys.argv[3]), _leases)
        except BaseException:
            if len(sys.argv) > 4:
                _retain_native_custody()
            sys.exit(126)
'''
# No code import or execution: source preparation only while full suite owns CPU.
ast.parse(s)
target=base/'evidence_process_supervisor.py';target.write_text(s)
(base/'guardian-core-source.json').write_text(json.dumps({'owner':'home:bcf-governance:closure-engine','base_sha256':hashlib.sha256(raw).hexdigest(),'candidate_sha256':hashlib.sha256(s.encode()).hexdigest(),'status':'SOURCE_PREPARED_UNRUN','changes':['explicit type annotations','explicit inherited original native lease identity and FLOCK handshake','candidate commands close inherited control and lease FDs','observe-only retention until kernel ECHILD if supervisor completion fails'],'qualification':'Original kernel/EOF/reap behavior and lease inheritance require execution after current full suite closes; no custody success inferred'},indent=2)+'\n')
print('Guardian core source prepared; unrun')
