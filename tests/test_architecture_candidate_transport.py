"""Native candidate transport and scoped exception cleanup; authored UNRUN."""
import json

import pytest

from bcf_governance.tooling.architecture_candidate_transport import KEY, decode_candidate_inputs, encode_candidate_inputs
from bcf_governance.tooling.architecture_source_components import SourceComponentError
from bcf_governance.tooling.bootstrap.environment import comparison_settings, scoped_execution_environment
from bcf_governance.tooling.local_pr_context import LocalPRContext, LocalValidationLane, _pr_environment_values
from test_architecture_candidate_membership import installed_candidate


def test_closed_transport_roundtrips_inputs_without_authentication_fields(installed_candidate):
    _, inputs = installed_candidate
    raw = encode_candidate_inputs(inputs)
    assert decode_candidate_inputs(raw, isolated_candidate=True) == inputs
    assert set(json.loads(raw)) == {"source_root", "assets_root", "build_manifest", "template_root",
                                    "adopter_commit", "adopter_tree"}
    with pytest.raises(SourceComponentError, match="released execution domain"):
        decode_candidate_inputs(raw, isolated_candidate=False)


@pytest.mark.parametrize("mutation", ["duplicate", "extra-authority", "missing-build", "oversized", "relative"])
def test_transport_refuses_nonclosed_or_unbounded_context(installed_candidate, mutation):
    _, inputs = installed_candidate
    raw = encode_candidate_inputs(inputs)
    value = json.loads(raw)
    if mutation == "duplicate": raw = '{"source_root":"duplicate",' + raw[1:]
    elif mutation == "extra-authority": value["authority"] = True
    elif mutation == "missing-build": del value["build_manifest"]
    elif mutation == "oversized": raw = " " * 8193
    elif mutation == "relative": value["source_root"] = "relative/source"
    if mutation not in {"duplicate", "oversized"}: raw = json.dumps(value)
    with pytest.raises(SourceComponentError, match="candidate transport") as failure:
        decode_candidate_inputs(raw, isolated_candidate=True)
    assert any(entry.name in {"decode_candidate_inputs", "unique"} for entry in failure.traceback)


@pytest.mark.parametrize("previous", [None, "previous-owner-data"])
def test_existing_scoped_port_restores_candidate_transport_on_exception(installed_candidate, previous):
    _, inputs = installed_candidate
    values = {} if previous is None else {KEY: previous}
    original = dict(values)
    port = scoped_execution_environment(values)
    class ExpectedExit(Exception):
        pass
    with pytest.raises(ExpectedExit):
        with port.comparison({KEY: encode_candidate_inputs(inputs)}):
            assert comparison_settings(values).candidate_membership_inputs() == encode_candidate_inputs(inputs)
            raise ExpectedExit("qualification interrupted")
    assert values == original


def test_default_comparison_clears_candidate_data_while_isolated_owner_preserves_scoped_input():
    context = LocalPRContext("origin", "main", "a" * 40, "b" * 40, "qualification")
    default = _pr_environment_values(context)
    isolated = _pr_environment_values(context, validation_lane=LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION)
    assert default[KEY] == "" and KEY not in isolated
