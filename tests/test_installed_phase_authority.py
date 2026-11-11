"""Fresh and upgrade consumers retain phase query authority without the SDK."""

import json
import subprocess

from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)
from test_private_phase_authority_resources import PROBE


def test_installed_phase_query_uses_runtime_schema_authority(
    installed_consumer, isolated_python,
):
    # Deliberately replace the checkout schema; it is never verifier authority.
    (installed_consumer / 'schemas/ci-authority.schema.json').write_text('{}')
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', PROBE,
         str(installed_consumer / 'scripts'), 'require-sdk-absent'],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    assert json.loads(result.stdout) == {
        'runtime_owned_schemas': True,
        'candidate_schema_rejected': True,
        'protected_empty_population_verified': True,
        'protected_policy_blob_custody_controls': 9,
    }
