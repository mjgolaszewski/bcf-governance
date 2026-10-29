from pathlib import Path
import ast,json,hashlib
base=Path(__file__).resolve().parent;p=base/'evidence_process_supervisor.py';s=p.read_text()
s=s.replace('import locale\n','import locale\nimport math\n').replace('import time\n','import time\nfrom threading import Event\n')
s=s.replace('class OwnedProcessError(RuntimeError):','class _CancellationRequested(RuntimeError):\n    """A trusted controller requested bounded cancellation."""\n\n\nclass OwnedProcessError(RuntimeError):',1)
s=s.replace('buffers: dict[str, list[bytes]], deadline: float) -> dict[str, Any]:','buffers: dict[str, list[bytes]], deadline: float, cancel_event: Event | None = None) -> dict[str, Any]:',1)
s=s.replace("    while True:\n        ended = os.waitid", "    while True:\n        if cancel_event is not None and cancel_event.is_set():\n            raise _CancellationRequested()\n        ended = os.waitid",1)
s=s.replace('lease_descriptors: tuple[int, ...] = ()) -> subprocess.CompletedProcess[str]:','lease_descriptors: tuple[int, ...] = (), cancel_event: Event | None = None) -> subprocess.CompletedProcess[str]:',1)
s=s.replace('    leases: list[list[int]] = []','''    for value in (timeout_seconds, cleanup_seconds):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise OwnedProcessError("command and cleanup deadlines must be finite positive seconds")
    leases: list[list[int]] = []''',1)
s=s.replace("    buffers = {'stdout': [], 'stderr': []}","    buffers: dict[str, list[bytes]] = {'stdout': [], 'stderr': []}",1)
s=s.replace('body_deadline + cleanup_seconds)\n                quiescent = True','body_deadline + cleanup_seconds, cancel_event)\n                quiescent = True',1)
needle='''            except BaseException:
                # Cancellation uses the same owner; never kill an unknown child tree.'''
replacement='''            except _CancellationRequested:
                recovery_deadline = min(body_deadline + cleanup_seconds,
                                        time.monotonic() + cleanup_seconds)
                remaining = recovery_deadline - time.monotonic()
                if remaining <= 0:
                    raise OwnedProcessError('no declared cleanup budget remains') from None
                connection.settimeout(remaining)
                _send(connection, {'cancel': True})
                connection.setblocking(False)
                result = _observe(process, connection, selector, buffers, recovery_deadline)
                quiescent = True
            except BaseException:
                # Cancellation uses the same owner; never kill an unknown child tree.'''
assert needle in s;s=s.replace(needle,replacement,1)
s=s.replace("_leases = tuple(tuple(int(value) for value in sys.argv[offset:offset + 3])\n                            for offset in range(4, len(sys.argv), 3))","_leases = tuple((int(sys.argv[offset]), int(sys.argv[offset + 1]), int(sys.argv[offset + 2]))\n                            for offset in range(4, len(sys.argv), 3))")
ast.parse(s);p.write_text(s)
f=base/'guardian-core-source.json';d=json.loads(f.read_text());d['candidate_sha256']=hashlib.sha256(s.encode()).hexdigest();d['changes'].extend(['finite positive command and cleanup budgets checked before allocation','explicit trusted cancellation event uses original bounded cancel/reap/EOF path']);f.write_text(json.dumps(d,indent=2)+'\n')
print('Trusted cancellation source prepared; execution remains pending')
