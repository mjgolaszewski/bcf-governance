"""Timing capture binding preserves scalar types, not Python numeric equality."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
import pytest
from bcf_governance.tooling.operational_observations import OperationalObservationError,pipeline_timing_observation,validate_timing_capture
ROOT=Path(__file__).resolve().parents[1]
def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def capture(span=1):
    empty=hashlib.sha256(b"").hexdigest()
    source={"authority":False,"repository":"owner/repo","repository_id":17,"commit_sha":"a"*40,"tree_sha":"b"*40,
            "clock_id":"controlled-local-clock","elapsed_ms":span,"stdout_sha256":empty,"stderr_sha256":empty}
    observation=pipeline_timing_observation(repository="owner/repo",repository_id=17,source_snapshot_sha256=digest(source),
        commit_sha="a"*40,tree_sha="b"*40,pipeline="pr",clock_id=source["clock_id"],clock_basis="monotonic_ms",start_ms=0,end_ms=span,
        intervals=[{"id":"one","clock_id":source["clock_id"],"kind":"execution","status":"passed","start_ms":0,"end_ms":span,"cpu_ms":0}])
    return {"authority":False,"source_snapshot":source,"producer":deepcopy(source),"observation":observation,"retained_stdout":"","retained_stderr":""}
@pytest.mark.parametrize("placement",("source","producer","both"))
@pytest.mark.parametrize("value,span",[(False,0),(True,1),(0.0,0),(1.0,1)],ids=("false","true","float-zero","float-one"))
def test_duration_declarations_cannot_coerce_scalar_identity(placement,value,span):
    value_capture=capture(span)
    if placement in {"source","both"}:value_capture["source_snapshot"]["elapsed_ms"]=value
    if placement in {"producer","both"}:value_capture["producer"]["elapsed_ms"]=value
    value_capture["observation"]["source_snapshot_sha256"]=digest(value_capture["source_snapshot"])
    with pytest.raises(OperationalObservationError,match="milliseconds|duration"):
        validate_timing_capture(ROOT,json.dumps(value_capture))
@pytest.mark.parametrize("origin",("local","provider"))
@pytest.mark.parametrize("field",("elapsed_ms","execution_union_ms","execution_sum_ms","external_wait_union_ms","uncovered_ms"))
def test_derived_milliseconds_are_not_silently_normalized_from_float(origin,field):
    value_capture=(capture() if origin=="local" else json.loads((ROOT/"audits/issue-394/observations/pr-426-attempt-1.json").read_text()))
    value_capture["observation"][field]=float(value_capture["observation"][field])
    with pytest.raises(OperationalObservationError,match="milliseconds"):
        validate_timing_capture(ROOT,json.dumps(value_capture))
def test_cpu_milliseconds_are_not_coerced_from_float():
    value_capture=capture()
    value_capture["observation"]["cpu_ms"]=0.0
    with pytest.raises(OperationalObservationError,match="milliseconds"):
        validate_timing_capture(ROOT,json.dumps(value_capture))
def test_declared_producer_duration_cannot_disagree_without_its_clock():
    value_capture=capture()
    value_capture["producer"].pop("clock_id")
    value_capture["producer"]["elapsed_ms"]=2
    with pytest.raises(OperationalObservationError,match="producer duration"):
        validate_timing_capture(ROOT,json.dumps(value_capture))
@pytest.mark.parametrize("span",(0,1))
def test_exact_integer_durations_remain_observations(span):
    value_capture=capture(span);raw=json.dumps(value_capture,sort_keys=True)
    assert validate_timing_capture(ROOT,raw)==value_capture["observation"]
    assert json.dumps(value_capture,sort_keys=True)==raw
@pytest.mark.parametrize("name",("pr-421-attempt-1.json","pr-426-attempt-1.json","reconcile-b976db49-attempt-1.json","reconcile-0e99bece-attempt-1.json"))
def test_retained_provider_and_local_capture_bytes_remain_valid_and_unchanged(name):
    path=ROOT/"audits/issue-394/observations"/name;raw=path.read_bytes()
    result=validate_timing_capture(ROOT,raw)
    assert result==json.loads(raw)["observation"] and result["authority"] is False
    assert path.read_bytes()==raw
