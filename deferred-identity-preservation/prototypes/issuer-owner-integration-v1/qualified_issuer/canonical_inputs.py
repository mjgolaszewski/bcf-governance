"""Load the already image-corresponded canonical issuer from a frozen source view."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

from .issuer.contracts import Refused
from .runtime.evidence_execution_view import inspect_view
from .runtime.evidence_immutable_source import ImmutableSource, freeze_source

BASE = Path('/docker/.bcf-235-maintenance-tools/release-239-completion-v1')
SOURCE_PROOF_SHA256 = 'ec5bd57bfe156744d4a210dd0d20d8caa37eb8f84c25c6d5b70f2f5267890c52'


def open_canonical_issuer(*, deadline: float) -> ImmutableSource:
    if 'chrysalis_identity' in sys.modules:
        raise Refused()
    proof = BASE / 'evidence/issuer-bytecode-correspondence-1/issuer-code-inputs.json'
    raw = proof.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_PROOF_SHA256:
        raise Refused()
    actual = json.loads(raw)['actual']
    source = inspect_view(BASE / 'evidence/issuer-normal-loader-1/loader-view', tuple(sorted(actual)))
    for name, _mode, size, digest in source.manifest:
        original = base64.b64decode(actual[name]['bytes'], validate=True)
        if len(original) != size or hashlib.sha256(original).hexdigest() != digest:
            raise Refused()
    frozen = freeze_source(source, deadline=min(deadline, time.monotonic() + 30))
    try:
        specification = importlib.util.spec_from_file_location('chrysalis_identity',
            frozen.view.root / '__init__.py', submodule_search_locations=[str(frozen.view.root)])
        if specification is None or specification.loader is None:
            raise Refused()
        module = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = module
        specification.loader.exec_module(module)
        return frozen
    except BaseException:
        frozen.close()
        raise
