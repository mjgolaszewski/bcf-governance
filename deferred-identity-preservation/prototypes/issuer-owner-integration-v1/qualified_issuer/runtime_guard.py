"""Real read-only Docker generation checks behind the original issuer admission.

The nominated handoff selects a previously acknowledged dev generation. JSON
does not admit a workload: the original Root channel and actual daemon/socket,
configuration bytes and all four running service lifetimes are rechecked.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
from typing import Any

from .coordinator import OriginalCoordinator
from .delivery import OriginalDeliveryRegistry
from .docker_native import NativeExec
from .issuer.contracts import Admission, Refused

HANDOFF_SHA256 = '2384836bb0bf2bd3a7d68bcd915d3de261628aae648c7e96b78a432a59c70647'
DAEMON = '0466eb93-a385-4d4a-9cf8-0faf4e871f51'


class OriginalIssuerRuntimeGuard:
    def __init__(self, *, coordinator: OriginalCoordinator,
                 delivery: OriginalDeliveryRegistry, admission: Admission, handoff: Path) -> None:
        if (type(coordinator) is not OriginalCoordinator or type(delivery) is not OriginalDeliveryRegistry
                or type(admission) is not Admission or delivery._coordinator is not coordinator
                or not handoff.is_absolute() or handoff.resolve() != handoff
                or not stat.S_ISREG(handoff.lstat().st_mode)):
            raise Refused()
        raw = handoff.read_bytes()
        if hashlib.sha256(raw).hexdigest() != HANDOFF_SHA256:
            raise Refused()
        pin = json.loads(raw)
        if type(pin) is not dict or set(pin['services']) != {'app', 'postgres', 'redis', 'bao'}:
            raise Refused()
        self._handoff: dict[str, Any] = pin
        self._pin: dict[str, Any] = {
            'issuer': 'https://identity.west.golaszewski.net',
            'source': '126a2f3929ca99d51508c7f60ef1cd5bd58e9caa',
            'image': pin['services']['app']['image'],
        }
        self._admission = admission
        self._coordinator = coordinator
        self._delivery = delivery
        self._native = NativeExec(socket_path='/var/run/docker.sock', daemon_id=DAEMON,
                                  deadline=admission.cleanup_deadline)
        if self._native.identity != (58, 4506067, 1001):
            raise Refused()
        self.runtime_check(self.pin)

    @property
    def pin(self) -> dict[str, Any]:
        return dict(json.loads(json.dumps(self._pin, allow_nan=False)))

    def runtime_check(self, pin: dict[str, Any]) -> None:
        if type(pin) is not dict or pin != self._pin:
            raise Refused()
        cleanup = self._delivery._retired
        self._coordinator.recheck(self._admission, cleanup=cleanup)
        configuration = Path(self._handoff['runtime_config_locator'])
        if (configuration.resolve() != configuration or not stat.S_ISREG(configuration.lstat().st_mode)
                or hashlib.sha256(configuration.read_bytes()).hexdigest() != self._handoff['configuration_sha256']):
            raise Refused()
        if self._native.request('GET', '/info').get('ID') != DAEMON:
            raise Refused()
        for service in self._handoff['services'].values():
            current = self._native.request('GET', '/containers/' + service['id'] + '/json')
            state = current.get('State'); labels = current.get('Config', {}).get('Labels', {})
            if (current.get('Id') != service['id'] or current.get('Image') != service['image']
                    or type(state) is not dict or state.get('Running') is not True
                    or state.get('StartedAt') != service['started_at'] or state.get('Pid') != service['pid']
                    or labels.get('com.docker.compose.project') != 'chrysalis-identity'):
                raise Refused()
        self._coordinator.recheck(self._admission, cleanup=cleanup)
