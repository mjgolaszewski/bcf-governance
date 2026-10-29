"""Original outside-launcher registry for one real held invocation.

Only the installed outside launcher constructs this object from its original
plan, keeper and process observations. No RPC registers a PID, path or owner.
Admission metadata identifies that retained allocation; it grants nothing by
itself. The registry never releases a native lease or asserts provider cleanup.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import time
from threading import get_ident
from typing import Any
from uuid import uuid4

from .evidence_closed_held import ClosedHeldPythonPlan
from .evidence_execution_owner import OwnerAdmissionError, ProcessIdentity
from .evidence_execution_view import WorkingView, _digest, context_manifest
from .evidence_external_custody import require_external_custodian
from .evidence_held_peer import inspect_held_process
from .evidence_lease_keeper import ExecutionLeaseKeeper


def lifetime(identity: ProcessIdentity) -> str:
    """Public identifier for an original kernel observation, never authority."""
    return hashlib.sha256(json.dumps(asdict(identity), sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def _original_exited(identity: ProcessIdentity) -> bool:
    try:
        fields = (Path('/proc') / str(identity.pid) / 'stat').read_bytes().rsplit(b')', 1)[1].split()
    except FileNotFoundError:
        return True
    except OSError as error:
        raise OwnerAdmissionError('original process exit is unobservable') from error
    # A PID reused by another birth is not the original lifetime. Exec or a
    # namespace change within the same birth never counts as process exit.
    return int(fields[19]) != identity.start_ticks


@dataclass(frozen=True)
class RegistryAdmission:
    context: str
    coordinator_lifetime: str
    consuming_controller_lifetime: str
    held_peer_lifetime: str
    tenant: str
    access_deadline: float
    cleanup_deadline: float


class ActualInvocationRegistry:
    """Trusted Root API; expose only authenticated read/recheck RPCs to owners."""

    def __init__(self, *, root: Path, plan: ClosedHeldPythonPlan,
                 keeper: ExecutionLeaseKeeper, consuming_controller: ProcessIdentity,
                 protected_budget_owner: ProcessIdentity, tenant: str,
                 listeners: dict[str, socket.socket],
                 producer: str, profile: str, control: str) -> None:
        coordinator = ProcessIdentity.observe(os.getpid())
        if (type(plan) is not ClosedHeldPythonPlan or plan.observation is None
                or plan.release_attempted or type(keeper) is not ExecutionLeaseKeeper
                or not keeper.started or keeper.released or keeper.context_digest is not None
                or type(tenant) is not str or tenant == 'default'
                or re.fullmatch('[a-z][a-z0-9-]{1,62}', tenant) is None
                or type(consuming_controller) is not ProcessIdentity
                or type(protected_budget_owner) is not ProcessIdentity):
            raise OwnerAdmissionError('original pending invocation allocation is required')
        pending = {role: (device, inode, uid) for role, device, inode, uid in plan.source.workload_sockets}
        if len(plan.source.workload_sockets) != 2 or set(pending) != {'issuer', 'custody'} or set(listeners) != set(pending):
            raise OwnerAdmissionError('both original pending owner listeners are required')
        listener_keys: dict[str, tuple[int, int]] = {}
        for role, listener in listeners.items():
            if (type(listener) is not socket.socket or listener.family != socket.AF_UNIX
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
                raise OwnerAdmissionError('original owner listener is not active')
            address = listener.getsockname()
            if type(address) is not str or not address.startswith('/'):
                raise OwnerAdmissionError('original owner listener is not a filesystem endpoint')
            info = Path(address).lstat()
            if ((info.st_dev, info.st_ino, info.st_uid) != pending[role]
                    or not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600):
                raise OwnerAdmissionError('owner listener is not its original frozen endpoint')
            fdinfo = os.fstat(listener.fileno())
            listener_keys[role] = (fdinfo.st_dev, fdinfo.st_ino)
        if len(set(listener_keys.values())) != 2:
            raise OwnerAdmissionError('original pending listeners share an OFD')
        observation = plan.observation
        if len({(p.pid, p.start_ticks) for p in
                (coordinator, consuming_controller, observation.identity)}) != 3:
            raise OwnerAdmissionError('coordinator, controller and held lifetime must differ')
        if ProcessIdentity.observe(consuming_controller.pid) != consuming_controller:
            raise OwnerAdmissionError('original consuming controller changed')
        require_external_custodian(coordinator, protected_budget_owner)
        keeper_identity = ProcessIdentity.observe(keeper.process.pid)
        require_external_custodian(keeper_identity, protected_budget_owner)
        state = keeper.status()
        if (state.get('state') != 'pending'
                or state.get('native_supervisor_pid') != observation.supervisor.pid):
            raise OwnerAdmissionError('held peer is outside the original native guardian')
        if (not root.is_absolute() or root.resolve() != root or root.is_symlink()
                or stat.S_IMODE(root.stat().st_mode) != 0o700 or root.stat().st_uid != os.getuid()):
            raise OwnerAdmissionError('registry requires its original private evidence directory')
        if not time.monotonic() < keeper.access_deadline < keeper.deadline:
            raise OwnerAdmissionError('original keeper allocation is no longer live')
        rows = tuple((name[5:], mode, size, digest) for name, mode, size, digest
                     in plan.source.view.manifest if name.startswith('work/'))
        view = WorkingView(plan.source.view.root / 'work', rows, _digest(rows))
        actual = inspect_held_process(observation.identity, expected_view=view,
            supervisor=observation.supervisor,
            deadline=min(keeper.access_deadline, time.monotonic() + 5))
        if actual != observation:
            raise OwnerAdmissionError('held source differs from the original allocation')
        plan._verify_runtime(actual.identity, deadline=min(keeper.access_deadline, time.monotonic() + 5))
        nonce = uuid4().hex
        raw = context_manifest(view, runtime={
            'source_digest': plan.inventory.source_digest,
            'runtime_digest': plan.inventory.runtime_digest,
            'image_digest': plan.source.view.digest,
            'executable': plan.inventory.executable,
            'coordinator': asdict(coordinator),
            'budget_owner': asdict(protected_budget_owner),
            'native_guardian': asdict(observation.supervisor),
            'keeper': asdict(keeper_identity), 'tenant': tenant,
            'pending_owner_sockets': plan.source.workload_sockets,
            'cleanup_deadline_ns': int(keeper.deadline * 1e9)},
            producer=producer, profile=profile, control=control,
            deadline_ns=int(keeper.access_deadline * 1e9), invocation_nonce=nonce,
            controller=asdict(consuming_controller), held_peer=asdict(actual.identity))
        if len(raw) > 8 * 1024 * 1024:
            raise OwnerAdmissionError('original context manifest exceeds its byte bound')
        manifest = root / (nonce + '.json')
        with os.fdopen(os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400), 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        descriptor = os.open(manifest, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        context = hashlib.sha256(raw).hexdigest()
        try:
            keeper.bind_actual_context(context)
        except BaseException:
            os.close(descriptor)
            raise
        self.admission = RegistryAdmission(context, lifetime(coordinator),
            lifetime(consuming_controller), lifetime(actual.identity), tenant,
            keeper.access_deadline, keeper.deadline)
        self.manifest_path = manifest
        self._manifest_fd = descriptor
        self._manifest_key = (info.st_dev, info.st_ino, info.st_uid)
        self._coordinator = coordinator
        self._thread = get_ident()
        self._registry_channels: dict[str, tuple[int, int]] = {}
        self._controller = consuming_controller
        self._budget = protected_budget_owner
        self._keeper_identity = keeper_identity
        self._keeper = keeper
        self._plan = plan
        self._observation = actual
        self._view = view
        self._listener_keys = listener_keys
        self._hold = False
        self._owners: dict[str, ProcessIdentity] = {}
        self._executions: dict[str, str] = {}
        self._admitted: set[str] = set()
        self._native_seen: set[str] = set()
        self._closed = False
        self._journal = root / (nonce + '.registry.jsonl')
        self._journal_fd = os.open(self._journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self._record('allocated', {'admission': asdict(self.admission), 'manifest_path': str(manifest)})
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, event: str, fields: dict[str, Any]) -> None:
        raw = json.dumps({'event': event, 'context': self.admission.context,
                          **fields}, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(raw) > 16384:
            raise OwnerAdmissionError('registry journal event exceeds its bound')
        position = 0
        while position < len(raw):
            position += os.write(self._journal_fd, raw[position:])
        os.fsync(self._journal_fd)

    @property
    def held(self) -> bool:
        return self._hold

    def _root(self, *, cleanup: bool) -> None:
        if get_ident() != self._thread:
            raise OwnerAdmissionError('registry requires its original serial Root dispatcher')
        if self._hold and not cleanup:
            raise OwnerAdmissionError('original registry access is in HOLD')
        previous_hold = self._hold
        self._hold = True  # Uncertain source/lifetime checks never silently reopen access.
        if (self._closed or type(cleanup) is not bool
                or ProcessIdentity.observe(os.getpid()) != self._coordinator
                or ProcessIdentity.observe(self._keeper_identity.pid) != self._keeper_identity
                or self._keeper.context_digest != self.admission.context):
            raise OwnerAdmissionError('original coordinator or keeper lifetime changed')
        deadline = self.admission.cleanup_deadline if cleanup else self.admission.access_deadline
        if not math.isfinite(deadline) or time.monotonic() >= deadline:
            raise OwnerAdmissionError('original registry deadline exhausted')
        info = os.fstat(self._manifest_fd)
        path = self.manifest_path.lstat()
        if (not stat.S_ISREG(info.st_mode) or not stat.S_ISREG(path.st_mode)
                or stat.S_IMODE(path.st_mode) != 0o400
                or (info.st_dev, info.st_ino, info.st_uid) != self._manifest_key
                or (path.st_dev, path.st_ino, path.st_uid) != self._manifest_key
                or hashlib.sha256(os.pread(self._manifest_fd, 8 * 1024 * 1024 + 1, 0)).hexdigest() != self.admission.context):
            raise OwnerAdmissionError('original registry manifest changed')
        if not cleanup:
            if (ProcessIdentity.observe(self._controller.pid) != self._controller
                    or ProcessIdentity.observe(self._budget.pid) != self._budget):
                raise OwnerAdmissionError('consuming controller or original budget changed')
            actual = inspect_held_process(self._observation.identity, expected_view=self._view,
                supervisor=self._observation.supervisor,
                deadline=min(deadline, time.monotonic() + 5))
            if actual != self._observation:
                raise OwnerAdmissionError('actual held source context changed')
            self._plan._verify_runtime(actual.identity, deadline=min(deadline, time.monotonic() + 5))

        if time.monotonic() >= deadline:
            raise OwnerAdmissionError('original registry deadline expired during observation')
        self._hold = previous_hold

    def _listener_custody(self, role: str, identity: ProcessIdentity) -> None:
        directory = Path('/proc') / str(identity.pid) / 'fd'
        names = tuple(directory.iterdir())
        if len(names) > 128:
            raise OwnerAdmissionError('independent owner FD population exceeds its bound')
        keys: set[tuple[int, int]] = set()
        for path in names:
            try:
                info = path.stat()
            except FileNotFoundError:
                continue
            keys.add((info.st_dev, info.st_ino))
        if (self._listener_keys[role] not in keys
                or any(key in keys for other, key in self._listener_keys.items() if other != role)):
            raise OwnerAdmissionError('owner does not hold only its original pending listener')

    def bind_owners(self, owners: dict[str, ProcessIdentity]) -> None:
        self._root(cleanup=False)
        if self._owners or set(owners) != {'issuer', 'custody'}:
            raise OwnerAdmissionError('original independent owner allocation cannot be replaced')
        lifetimes = [self._coordinator, self._controller, self._observation.identity,
                     self._keeper_identity, *owners.values()]
        if len({(p.pid, p.start_ticks) for p in lifetimes}) != len(lifetimes):
            raise OwnerAdmissionError('independent owner lifetime was reused')
        for identity in owners.values():
            if type(identity) is not ProcessIdentity or ProcessIdentity.observe(identity.pid) != identity:
                raise OwnerAdmissionError('original independent owner changed')
            require_external_custodian(identity, self._budget)
            require_external_custodian(identity, self._observation.supervisor)
        for role, identity in owners.items():
            self._listener_custody(role, identity)
        self._owners = dict(owners)
        self._record('owners_bound', {'owners': {role: asdict(value) for role, value in owners.items()}})

    def _owner(self, role: str, *, cleanup: bool) -> None:
        self._root(cleanup=cleanup)
        identity = self._owners.get(role)
        if identity is None:
            raise OwnerAdmissionError('original independent owner is unavailable')
        try:
            if ProcessIdentity.observe(identity.pid) != identity:
                raise OwnerAdmissionError('original independent owner changed')
            if not cleanup and not self._plan.release_attempted:
                self._listener_custody(role, identity)
        except BaseException:
            self._hold = True
            raise

    def admit(self, role: str, *, context: str, manifest_path: str, held_pid: int) -> RegistryAdmission:
        self._owner(role, cleanup=False)
        if (context != self.admission.context or type(manifest_path) is not str
                or manifest_path != str(self.manifest_path) or type(held_pid) is not int
                or held_pid != self._observation.identity.pid):
            raise OwnerAdmissionError('owner request differs from the original invocation')
        if role not in self._admitted:
            self._record('owner_admitted', {'role': role})
            self._admitted.add(role)
        return self.admission

    def recheck(self, role: str, admission: RegistryAdmission, *, cleanup: bool) -> None:
        self._owner(role, cleanup=cleanup)
        if role not in self._admitted or type(admission) is not RegistryAdmission or admission != self.admission:
            raise OwnerAdmissionError('owner admission is not the original allocation')

    def bind_execution(self, role: str, execution_id: str) -> None:
        """Root records its authenticated prepare response; never a workload RPC."""
        self._owner(role, cleanup=False)
        if (role not in self._admitted or type(execution_id) is not str
                or re.fullmatch('[A-Za-z0-9._:-]{1,128}', execution_id) is None
                or role in self._executions):
            raise OwnerAdmissionError('owner execution binding is invalid or already consumed')
        self._record('execution_bound', {'role': role, 'execution_id': execution_id})
        self._executions[role] = execution_id

    def recover(self, role: str, *, context: str, coordinator_lifetime: str,
                execution_id: str) -> RegistryAdmission:
        self._owner(role, cleanup=True)
        if (context != self.admission.context or coordinator_lifetime != self.admission.coordinator_lifetime
                or role not in self._executions or self._executions[role] != execution_id):
            raise OwnerAdmissionError('cleanup has no original registered owner execution')
        return self.admission

    def native_closed(self, role: str, admission: RegistryAdmission) -> None:
        self.recheck(role, admission, cleanup=True)
        state = self._keeper.status()
        if (state.get('state') != 'native_closed'
                or state.get('native_supervisor_pid') != self._observation.supervisor.pid
                or not _original_exited(self._observation.identity)
                or not _original_exited(self._observation.supervisor)):
            raise OwnerAdmissionError('original native Q, both EOFs and reap remain unproven')
        if role not in self._native_seen:
            self._record('native_closed_observed', {'role': role,
                'returncode': state.get('returncode'),
                'held_peer': asdict(self._observation.identity),
                'native_guardian': asdict(self._observation.supervisor),
                'keeper': asdict(self._keeper_identity)})
            self._native_seen.add(role)

    def close(self) -> None:
        """Close metadata descriptors only; native/owner lease custody is unchanged."""
        if not self._closed:
            self._closed = True
            os.close(self._manifest_fd)
            os.close(self._journal_fd)
