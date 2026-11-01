"""Fresh real Git subjects; authored source, not an execution result."""
from dataclasses import replace
import hashlib
import json
import sys

import pytest

from bcf_governance.tooling import architecture_membership_compilation as compiler
from bcf_governance.tooling.architecture_source_components import SourceComponentError
from test_architecture_native_inventory import subject as subject, commit, config, write_config


def _declare(root):
    document = config(root)
    path = "src/domain/orders/rules.py"
    digest = hashlib.sha256((root / path).read_bytes()).hexdigest()
    document["architecture"]["source_component_ownership"] = {
        "version": "1.0", "components": [{
            "id": "order-rules", "layer": "domain", "context": "orders",
            "rationale": "Exact independently observed source ownership",
            "members": {path: digest}, "managed_pack": None,
            "context_authority": {"kind": "independently_inferred_inventory",
                                  "version": "1.0", "selector": "orders"},
        }],
    }
    write_config(root, document)
    commit(root)


def test_absence_retains_legacy_native_observations_without_projection(subject):
    result = compiler.build_effective_inventory(subject)
    assert result.projection is result.release is None
    assert len(result.native.members) == 3
    assert any(row.rule == "layer_membership" and row.path == "src/loose.py"
               for row in result.native.observation.violations)


def test_project_requests_use_fresh_native_context_and_keep_unknown_raw_rows(subject):
    _declare(subject)
    result = compiler.build_effective_inventory(subject)
    assert result.release is None and result.projection is not None
    assert result.projection.raw_observation is result.native.observation
    assert len(result.projection.members) == len(result.native.members) == 3
    assigned = [row for row in result.projection.members if row.component_id is not None]
    assert len(assigned) == 1 and assigned[0].path == "src/domain/orders/rules.py"
    compiler.reauthenticate_effective_inventory(subject, result)


@pytest.mark.parametrize("footprint", [
    "governance/bcf-runtime-lock.json", "governance/bcf-candidate-qualification.json",
    "scripts/_bcf_runtime/__init__.py", "scripts/install_governance_pack.py",
    "governance-profile.yml",
])
def test_missing_release_context_cannot_classify_installed_footprint_as_project(subject, footprint):
    _declare(subject)
    path = subject / footprint
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n" if path.suffix == ".json" else '"""Footprint."""\n')
    commit(subject)
    with pytest.raises(SourceComponentError, match="installed footprint requires explicit native release authentication") as failure:
        compiler.build_effective_inventory(subject)
    assert any(entry.name == "_project_classifications" for entry in failure.traceback)


@pytest.mark.parametrize("mutation", ["members", "observation", "projection", "context", "subject"])
def test_forged_cache_is_only_compared_with_fresh_native_result(subject, mutation):
    _declare(subject)
    result = compiler.build_effective_inventory(subject)
    if mutation == "members":
        result = replace(result, native=replace(result.native, members=()))
    elif mutation == "observation":
        result = replace(result, native=replace(result.native,
            observation=replace(result.native.observation, violations=())))
    elif mutation == "projection": result = replace(result, projection=None)
    elif mutation == "context":
        result = replace(result, native=replace(result.native, contexts=()))
    else: result = replace(result, native=replace(result.native, subject=()))
    with pytest.raises(SourceComponentError, match="cached ownership differs from fresh native compilation") as failure:
        compiler.reauthenticate_effective_inventory(subject, result)
    assert any(entry.name == "reauthenticate_effective_inventory" for entry in failure.traceback)


@pytest.mark.parametrize("mutation,diagnostic", [
    ("null", "exact fields required"), ("empty", "nonempty components required"),
    ("managed-null-lock", "installed footprint requires explicit native release authentication"),
])
def test_present_invalid_or_missing_authority_stays_refused(subject, mutation, diagnostic):
    _declare(subject)
    document = config(subject)
    if mutation == "null": document["architecture"]["source_component_ownership"] = None
    elif mutation == "empty": document["architecture"]["source_component_ownership"]["components"] = []
    else:
        (subject / "scripts/_bcf_runtime").mkdir(parents=True)
        (subject / "scripts/_bcf_runtime/__init__.py").write_text('"""Runtime footprint."""\n')
    write_config(subject, document)
    commit(subject)
    # The native schema may reject invalid declaration shape before the parser;
    # either layer must refuse. These cases deliberately name their exact owner.
    if mutation in {"null", "empty"}:
        from jsonschema import ValidationError
        with pytest.raises(ValidationError) as failure:
            compiler.build_effective_inventory(subject)
        assert list(failure.value.absolute_path)[:2] == ["architecture", "source_component_ownership"]
    else:
        with pytest.raises(SourceComponentError, match=diagnostic) as failure:
            compiler.build_effective_inventory(subject)
        assert any(entry.name == "_project_classifications" for entry in failure.traceback)


def test_transient_actual_config_substitution_cannot_supply_consumed_declarations(subject):
    _declare(subject)
    path = subject / "architecture-boundaries.yml"
    original = path.read_bytes()
    forged = json.loads(original)
    forged["architecture"]["source_component_ownership"]["components"][0]["id"] = "forged-order-owner"
    substituted = (json.dumps(forged, indent=2) + "\n").encode()
    loader_code = compiler.load_architecture_mapping.__code__
    state = {"active": True, "writing": False, "substituted": False, "restored": False}

    def write_actual(raw):
        state["writing"] = True
        try:
            path.write_bytes(raw)
        finally:
            state["writing"] = False

    def filesystem_control(event, arguments):
        if (event != "open" or not state["active"] or state["writing"]
                or arguments[0] != str(path)):
            return
        frame = sys._getframe(1)
        in_loader = False
        while frame is not None:
            in_loader = in_loader or frame.f_code is loader_code
            frame = frame.f_back
        if in_loader and not state["substituted"]:
            state["substituted"] = True
            write_actual(substituted)
        elif state["substituted"] and not in_loader and not state["restored"]:
            # The former final-read-only guard sees original bytes again. The
            # actual bytes consumed by the loader must already have been bound.
            state["restored"] = True
            write_actual(original)

    sys.addaudithook(filesystem_control)
    try:
        with pytest.raises(ValueError, match="policy input does not match its admitted SHA256") as failure:
            compiler.build_effective_inventory(subject)
        assert state["substituted"]
        assert any(entry.name == "load_architecture_mapping" for entry in failure.traceback)
    finally:
        state["active"] = False
        path.write_bytes(original)
    assert path.read_bytes() == original
    assert compiler.build_effective_inventory(subject).projection.members
