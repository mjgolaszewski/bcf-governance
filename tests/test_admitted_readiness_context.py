"""Existing readiness consumes admitted policy without substituting current main."""

import pytest
import yaml

from bcf_governance.tooling import evidence_workitem_lifecycle as lifecycle
from tests.test_phase_policy_subject import advanced_admitted_population, protected_population, phase_input  # noqa: F401
from tests.test_workitem_phase_consumption import _repo, _phase_log


@pytest.mark.parametrize("boundary", ["bounded", "phase", "evaluation_bounded", "evaluation_phase"])
def test_existing_readiness_consumes_authenticated_admitted_policy(
    tmp_path, advanced_admitted_population, boundary,
):
    api, subject, calls = advanced_admitted_population
    entries = _repo(tmp_path)
    if boundary in {"phase", "evaluation_phase"}:
        _phase_log(tmp_path)
        for entry in entries:
            entry["status"] = "DONE"
        (tmp_path / "plans/items.yml").write_text(yaml.safe_dump({"workitems": entries}))
    context = {"provider_api": api, "repository": "owner/repo", "policy_subject": subject}
    if boundary == "bounded":
        lifecycle.validate_bounded_target_authored_ready(tmp_path, "P02-W01", **context)
    elif boundary == "phase":
        lifecycle.validate_phase_closure_authored_ready(tmp_path, **context)
    else:
        lifecycle.validate_evaluation_authored_ready(
            tmp_path, intent="closure" if boundary == "evaluation_phase" else "workitem",
            target="P02" if boundary == "evaluation_phase" else "P02-W01", **context,
        )
    assert api.reads == 1
    assert {ref for _, ref in calls} == {subject.checkout_sha}
    assert api.main != subject.checkout_sha


def test_explicit_admitted_context_cannot_fall_back_to_unbound_success(tmp_path, advanced_admitted_population):
    _, subject, _ = advanced_admitted_population
    _repo(tmp_path, predicate=None)
    with pytest.raises(lifecycle.WorkitemContractError, match="unverified"):
        lifecycle.validate_bounded_target_authored_ready(tmp_path, "P02-W01", policy_subject=subject)
