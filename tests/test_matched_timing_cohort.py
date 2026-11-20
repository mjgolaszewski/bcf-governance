"""Independent complete inputs survive candidate pair/context omissions."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
from bcf_governance.tooling import operational_observations as owner

ROOT = Path(__file__).resolve().parents[1]


class Case:
    @staticmethod
    def raw(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def sha(raw):
        return hashlib.sha256(raw).hexdigest()

    def __init__(self, count=2, pipeline="pr"):
        self.context = {key: "c" * 64 for key in (
            "workload_sha256", "required_work_sha256", "toolchain_sha256", "environment_sha256",
            "resource_envelope_sha256", "policy_sha256", "evaluator_sha256")}
        self.context.update(profile="standard-v3", cache_state="cold", adopter_source="not_applicable")
        if pipeline == "adopter":
            self.context["adopter_source"] = {"repository_id": 21, "commit_sha": "e" * 40, "tree_sha": "f" * 40}
        self.protocol = {"schema_version": "1.0", "authority": False, "scope": "controlled_pairs",
            "repository": "owner/repo", "repository_id": 17, "pipeline": pipeline,
            "baseline_subject": {"commit_sha": "a" * 40, "tree_sha": "b" * 40},
            "optimized_subject": {"commit_sha": "d" * 40, "tree_sha": "e" * 40}, "pairs": []}
        self.captures = []
        for index in range(count):
            self.protocol["pairs"].append({"id": str(index), "context_sha256": self.sha(self.raw(self.context))})
            for role in ("baseline", "optimized"):
                subject = self.protocol[role + "_subject"]
                source = {"authority": False, "repository": "owner/repo", "repository_id": 17,
                    **subject, "clock_id": str(index) + role, "elapsed_ms": 10 + index,
                    "stdout_sha256": self.sha(b""), "stderr_sha256": self.sha(b"")}
                observation = owner.pipeline_timing_observation(repository="owner/repo", repository_id=17,
                    source_snapshot_sha256=self.sha(self.raw(source)), **subject, pipeline=pipeline,
                    clock_id=source["clock_id"], clock_basis="monotonic_ms", start_ms=0, end_ms=10 + index,
                    intervals=[{"id": "execute", "clock_id": source["clock_id"], "kind": "execution",
                                "status": "passed", "start_ms": 0, "end_ms": 10 + index}])
                self.captures.append({"authority": False, "source_snapshot": source, "observation": observation,
                    "retained_stdout": "", "retained_stderr": "", "measurement_context": deepcopy(self.context)})

    def arguments(self):
        values = [self.raw(value) for value in self.captures]
        for index, pair in enumerate(self.protocol["pairs"]):
            for offset, role in enumerate(("baseline", "optimized")):
                pair[role + "_sha256"] = self.sha(values[index * 2 + offset])
        protocol = self.raw(self.protocol)
        return {"protocol_bytes": protocol, "expected_protocol_sha256": self.sha(protocol),
                "expected_capture_sha256": frozenset(self.sha(raw) for raw in values), "captures": values}

    def invoke(self, arguments=None):
        return owner.matched_timing_cohort_observation(ROOT, **(self.arguments() if arguments is None else arguments))


def test_exact_pairs_are_deterministic_detached_and_never_certifying():
    case = Case()
    inputs = case.arguments()
    result = case.invoke(inputs)
    permuted = {**inputs, "captures": list(reversed(inputs["captures"]))}
    assert result == case.invoke(permuted)
    assert result["authority"] is result["execution_qualified"] is result["percentile_certification"] is False
    assert [row["id"] for row in result["pairs"]] == ["0", "1"]
    owner.validate_operational_observation(ROOT, result)
    result["pairs"][0]["baseline"]["observation"]["elapsed_ms"] = 0
    assert case.invoke()["pairs"][0]["baseline"]["observation"]["elapsed_ms"] == 10


@pytest.mark.parametrize("pipeline", sorted(owner.PIPELINE_CLOCKS))
def test_each_explicit_pipeline_stays_separate(pipeline):
    case = Case(pipeline=pipeline)
    assert case.invoke()["pipeline"] == pipeline


@pytest.mark.parametrize("field", ["workload_sha256", "required_work_sha256", "profile", "toolchain_sha256",
    "environment_sha256", "resource_envelope_sha256", "policy_sha256", "evaluator_sha256", "cache_state", "adopter_source"])
def test_changed_matching_context_rejects_even_with_rebound_capture_digest(field):
    case = Case()
    case.captures[1]["measurement_context"][field] = "changed"
    with pytest.raises(owner.OperationalObservationError, match="context|nonadopter"):
        case.invoke()


@pytest.mark.parametrize("cause", ["missing", "extra", "duplicate", "omitted-pair", "overlap", "wrong-protocol-pin",
    "mutable-capture", "mutable-protocol", "empty-inventory", "same-subject", "wrong-pipeline", "wrong-repository",
    "wrong-subject", "missing-context", "unknown-cache", "wrong-clock-basis", "bool-repository", "extra-protocol-field",
    "empty-pairs", "duplicate-pair-id", "nonfinite", "duplicate-json-key", "invalid-capture-arithmetic"])
def test_invalid_or_incomplete_population_cannot_be_matched(cause):
    case = Case()
    if cause == "same-subject":
        case.protocol["optimized_subject"] = deepcopy(case.protocol["baseline_subject"])
    elif cause == "wrong-pipeline":
        case.protocol["pipeline"] = "release"
    elif cause == "wrong-repository":
        case.protocol["repository"] = "other/repo"
    elif cause == "wrong-subject":
        case.protocol["baseline_subject"]["tree_sha"] = "f" * 40
    elif cause == "missing-context":
        del case.captures[0]["measurement_context"]
    elif cause == "unknown-cache":
        case.captures[0]["measurement_context"]["cache_state"] = "unknown"
    elif cause == "wrong-clock-basis":
        case.captures[1]["observation"]["clock_basis"] = "provider_utc_ms"
    elif cause == "bool-repository":
        case.protocol["repository_id"] = True
    elif cause == "extra-protocol-field":
        case.protocol["approved"] = True
    elif cause == "duplicate-pair-id":
        case.protocol["pairs"][1]["id"] = "0"
    elif cause == "invalid-capture-arithmetic":
        case.captures[0]["observation"]["elapsed_ms"] = 0
    args = case.arguments()
    if cause in {"omitted-pair", "overlap", "empty-pairs"}:
        protocol = json.loads(args["protocol_bytes"])
        if cause == "omitted-pair":
            protocol["pairs"].pop()
        elif cause == "empty-pairs":
            protocol["pairs"] = []
        else:
            protocol["pairs"][1]["baseline_sha256"] = protocol["pairs"][0]["baseline_sha256"]
        args["protocol_bytes"] = case.raw(protocol)
        args["expected_protocol_sha256"] = case.sha(args["protocol_bytes"])
    elif cause == "missing":
        args["captures"].pop()
    elif cause == "extra":
        args["captures"].append(b"{}")
    elif cause == "duplicate":
        args["captures"].append(args["captures"][0])
    elif cause == "wrong-protocol-pin":
        args["expected_protocol_sha256"] = "0" * 64
    elif cause == "mutable-capture":
        args["captures"][0] = bytearray(args["captures"][0])
    elif cause == "mutable-protocol":
        args["protocol_bytes"] = bytearray(args["protocol_bytes"])
    elif cause == "empty-inventory":
        args["expected_capture_sha256"] = frozenset()
    elif cause in {"nonfinite", "duplicate-json-key"}:
        raw = args["protocol_bytes"]
        raw = raw[:-1] + (b',"bad":1e999}' if cause == "nonfinite" else b',"authority":false}')
        args["protocol_bytes"] = raw
        args["expected_protocol_sha256"] = case.sha(raw)
    with pytest.raises(owner.OperationalObservationError):
        case.invoke(args)


def test_failed_cancelled_superseded_and_slow_work_are_retained():
    case = Case()
    statuses = ["failed", "cancelled", "superseded", "skipped"]
    for capture, status in zip(case.captures, statuses):
        capture["observation"]["intervals"][0]["status"] = status
    report = case.invoke()
    retained = [row[role]["observation"] for row in report["pairs"] for role in ("baseline", "optimized")]
    assert [value["intervals"][0]["status"] for value in retained] == statuses
    assert [value["elapsed_ms"] for value in retained] == [10, 10, 11, 11]


def test_pair_order_does_not_change_deterministic_output():
    case = Case()
    args = case.arguments()
    expected = case.invoke(args)
    protocol = json.loads(args["protocol_bytes"])
    protocol["pairs"].reverse()
    args["protocol_bytes"] = case.raw(protocol)
    args["expected_protocol_sha256"] = case.sha(args["protocol_bytes"])
    result = case.invoke(args)
    assert result["pairs"] == expected["pairs"]
    assert result["protocol_sha256"] != expected["protocol_sha256"]


def test_shared_clock_domain_does_not_mean_same_execution():
    case = Case()
    for capture in case.captures:
        source = capture["source_snapshot"]
        source["clock_id"] = "same-observed-monotonic-domain"
        observation = capture["observation"]
        observation["clock_id"] = source["clock_id"]
        observation["intervals"][0]["clock_id"] = source["clock_id"]
        observation["source_snapshot_sha256"] = case.sha(case.raw(source))
    assert len(case.invoke()["pairs"]) == 2
