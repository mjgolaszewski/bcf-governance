"""SDK-absent pairing and independent omitted-population detector parity."""
import inspect
import subprocess

import test_installed_evidence_storage as fixtures
import test_matched_timing_cohort as cases

installed_consumer = fixtures.installed_consumer
isolated_python = fixtures.isolated_python
PROBE = '''import hashlib,json,sys
from copy import deepcopy
from pathlib import Path
assert __import__("importlib.util").util.find_spec("bcf_governance") is None
ROOT=Path.cwd()
sys.path.insert(0,str(ROOT/"scripts"))
from _bcf_runtime import operational_observations as owner
''' + inspect.getsource(cases.Case) + '''
case=Case()
result=case.invoke()
assert len(result["pairs"])==2 and result["authority"] is result["execution_qualified"] is False
owner.validate_operational_observation(ROOT,result)
args=case.arguments()
protocol=json.loads(args["protocol_bytes"])
protocol["pairs"].pop()
args["protocol_bytes"]=case.raw(protocol)
args["expected_protocol_sha256"]=case.sha(args["protocol_bytes"])
try:case.invoke(args)
except owner.OperationalObservationError:pass
else:raise AssertionError("installed omitted population was accepted")
print("installed-matched-timing-qualified")
'''


def invoke(installed_consumer, isolated_python):
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=fixtures._environment(), capture_output=True, text=True)


def test_installed_exact_and_missing_pairs(installed_consumer, isolated_python):
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-matched-timing-qualified"


def test_installed_missing_population_control_detects_guard_removal(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/operational_observations.py"
    source = path.read_text()
    guard = "if used != expected_capture_sha256:"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "if False:"))
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 1
    assert "installed omitted population was accepted" in result.stderr
