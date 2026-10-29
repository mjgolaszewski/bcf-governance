"""Private bootstrap material only; real factory always authenticates JWT and API."""
from dataclasses import dataclass, field
import json
import math
import os
import stat
import time

import pytest


@dataclass(frozen=True)
class FactoryAdminMaterial:
    token: str = field(repr=False)
    subject: str
    valid_until: float
    access: float
    cleanup: float


def pytest_addoption(parser):
    parser.addoption('--factory-credential-fd', type=int, default=None)


@pytest.fixture
def factory_admin_material(request):
    descriptor = request.config.getoption('--factory-credential-fd')
    if descriptor is None:
        return None
    metadata = os.fstat(descriptor)
    if not stat.S_ISFIFO(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise RuntimeError('original private factory bootstrap pipe required')
    try:
        raw = os.read(descriptor, 4097)
        if len(raw) > 4096 or os.read(descriptor, 1):
            raise RuntimeError('factory bootstrap frame is not bounded')
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    if (type(value) is not dict or set(value) != {'token', 'subject', 'valid_until', 'access', 'cleanup'}
            or type(value['token']) is not str or not value['token']
            or value['subject'] != 'principal:c5f54cc0-d300-4e84-95f8-91334c3f32b8'
            or any(type(value[key]) not in (int, float) or not math.isfinite(value[key])
                   for key in ('valid_until', 'access', 'cleanup'))
            or not time.monotonic() < value['access'] < value['cleanup'] < value['valid_until']):
        raise RuntimeError('factory bootstrap metadata refused')
    return FactoryAdminMaterial(**value)
