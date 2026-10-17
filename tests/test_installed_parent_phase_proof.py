"""Actual installed parent verification from exact recorded provider facts."""

import hashlib
import json
import subprocess

import pytest

from bcf_governance.tooling.trusted_inputs import verify_phase_closure_input
from installed_phase_provider_trace import PARENT_PROBE, RecordingProvider
from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)
from tests.test_phase_closure_input import SHA_A, TREE, phase_input  # noqa: F401


@pytest.mark.parametrize('mode', ['valid', 'substituted'])
def test_installed_parent_phase_proof_consumes_exact_provider_facts(
    installed_consumer, isolated_python, phase_input, mode,
):
    provider, _ = phase_input
    recording = RecordingProvider(provider)
    coordinates = dict(repository='owner/repo', phase_id='P01',
                       source_commit=SHA_A, source_tree=TREE)
    _, verified, raw = verify_phase_closure_input(recording, **coordinates)
    assert verified.computed_state == 'certified'
    transcript = installed_consumer / 'provider-trace.json'
    transcript.write_text(json.dumps({
        'coordinates': coordinates, 'rows': recording.rows,
        'archive_sha256': hashlib.sha256(raw).hexdigest(),
    }))
    for schema in (installed_consumer / 'schemas').glob('*.json'):
        schema.write_text('{}')
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', PARENT_PROBE, str(transcript), mode],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    outcome = json.loads(result.stdout)
    assert outcome['outcome'] == ('certified' if mode == 'valid' else 'rejected')
