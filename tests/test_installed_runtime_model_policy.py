"""Installed operation captures bind native-model policy without runtime credit."""
import copy
import json
import subprocess

import pytest

from tests.test_installed_evidence_storage import (
    _environment, installed_consumer as installed_consumer, isolated_python as isolated_python,
)
from tests.test_installed_public_entrypoint_bindings import _encode
from tests.test_installed_separate_policy_source import PROBE
from tests.test_runtime_model_policy import declare
from tests.test_separate_policy_source import arguments, roots as roots, subject


@pytest.mark.parametrize('mode', ['valid', 'capture', 'metadata'])
def test_installed_runtime_model_claim_binding(roots, installed_consumer, isolated_python, mode):
    protected, candidate = roots
    declare(protected)
    args = dict(arguments(candidate, subject(protected)), policy_repo_root=protected)
    source = PROBE.replace('if mode=="policy":', '''assert len(captured.metadata["runtime_claims_sha256"])==64
if mode=="capture":captured=captured._replace(runtime_claims_sha256="0"*64)
elif mode=="metadata":captured.metadata["runtime_claims_sha256"]="0"*64
if mode=="policy":''')
    result = subprocess.run([str(isolated_python), '-I', '-B', '-c', source, mode],
        cwd=installed_consumer, env=_environment(), input=json.dumps(_encode(copy.deepcopy(args))),
        capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'installed-separate-policy-source-qualified'
