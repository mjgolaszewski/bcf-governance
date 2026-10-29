"""Original operator-nominated sandbox/profile guards for Cocoon's real ports.

The retained registration selects the acknowledged qualification surface. Every
use also checks the actual Root admission and current service generations; a
candidate tenant assertion or app environment never supplies sandbox authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from .issuer.contracts import Admission, Refused
from .issuer.workload import WorkloadConfig
from .runtime_guard import HANDOFF_SHA256, OriginalIssuerRuntimeGuard

REGISTRATION_SHA256 = '97267305c4e3ed1da81475de9869c2896f9e87eaaf315911f1491322fa88ae09'


class OriginalSandboxProfile:
    def __init__(self, *, runtime: OriginalIssuerRuntimeGuard, admission: Admission,
                 config: WorkloadConfig, registration: Path) -> None:
        if (type(runtime) is not OriginalIssuerRuntimeGuard or type(admission) is not Admission
                or type(config) is not WorkloadConfig or runtime._admission != admission
                or not registration.is_absolute() or registration.resolve() != registration):
            raise Refused()
        descriptor = os.open(registration, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
                raise Refused()
            raw = os.read(descriptor, 16385)
        finally:
            os.close(descriptor)
        if hashlib.sha256(raw).hexdigest() != REGISTRATION_SHA256:
            raise Refused()
        surface = json.loads(raw)
        if (surface['owner'] != 'home:bcf-governance:closure-engine'
                or surface['runtime_handoff_sha256'] != HANDOFF_SHA256
                or surface['tenant'] != admission.tenant
                or surface['wrong_tenant'] != config.wrong_tenant
                or surface['tenant'] == surface['wrong_tenant']):
            raise Refused()
        config.validate(admission)  # Actual canonical tenant routing remains the owner.
        self._runtime = runtime
        self._admission = admission
        self._config = config
        self._registration = registration
        self._registration_key = (info.st_dev, info.st_ino, info.st_uid)
        self.attest_profile(admission, config)

    def _current(self, admission: Admission) -> None:
        if type(admission) is not Admission or admission != self._admission:
            raise Refused()
        info = self._registration.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino, info.st_uid) != self._registration_key
                or hashlib.sha256(self._registration.read_bytes()).hexdigest() != REGISTRATION_SHA256):
            raise Refused()
        self._runtime.runtime_check(self._runtime.pin)

    def attest_profile(self, admission: Admission, config: WorkloadConfig) -> None:
        if type(config) is not WorkloadConfig or config != self._config:
            raise Refused()
        self._current(admission)
        config.validate(admission)

    def attest_sandbox(self, admission: Admission, pin: dict[str, Any], tenant: str) -> None:
        if tenant != self._admission.tenant or type(pin) is not dict or pin != self._runtime.pin:
            raise Refused()
        self._current(admission)
