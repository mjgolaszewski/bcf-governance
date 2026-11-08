"""Real installed native gate, explicit candidate owner scope; authored UNRUN."""
import hashlib
import importlib.util
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.architecture_candidate_transport import KEY, encode_candidate_inputs
from bcf_governance.tooling.bootstrap.environment import scoped_execution_environment
from bcf_governance.tooling.local_pr_context import LocalValidationLane
from test_architecture_candidate_membership import installed_candidate
from test_architecture_native_inventory import commit


@pytest.mark.parametrize("binding", ["exact", "stale", "release-domain", "null"])
def test_actual_native_gate_uses_exact_candidate_domain_and_restores_default(installed_candidate, binding):
    root, inputs = installed_candidate
    config_path = root / "architecture-boundaries.yml"
    original = config_path.read_bytes()
    document = yaml.safe_load(original)
    architecture = document["architecture"]
    architecture["bounded_contexts"]["context_root_tokens"].append("scripts")
    architecture["layers"]["tooling"] = {
        "path_tokens": ["tools"], "required": False, "forbidden_import_prefixes": [],
        "forbidden_layer_imports": [], "forbidden_import_names": [],
    }
    member = "scripts/_bcf_runtime/__init__.py"
    marker = root / "governance/bcf-candidate-qualification.json"
    managed = {"kind": "candidate_qualification", "path": marker.relative_to(root).as_posix(),
               "sha256": hashlib.sha256(marker.read_bytes()).hexdigest()}
    if binding == "stale": managed["sha256"] = "0" * 64
    elif binding == "release-domain":
        managed.update(kind="authenticated_release", path="governance/bcf-runtime-lock.json")
    elif binding == "null": managed = None
    architecture["source_component_ownership"] = {"version": "1.1", "components": [{
        "id": "candidate-runtime", "layer": "tooling", "context": "_bcf_runtime",
        "rationale": "Exact non-authoritative candidate installed source",
        "members": {member: hashlib.sha256((root / member).read_bytes()).hexdigest()},
        "managed_pack": managed,
        "context_authority": {"kind": "independently_inferred_inventory", "version": "1.0",
                              "selector": "_bcf_runtime"},
    }]}
    config_path.write_text(yaml.safe_dump(document))
    commit(root)
    path = root / "backend/tests/architecture/test_boundaries_ast.py"
    spec = importlib.util.spec_from_file_location("candidate_native_gate_under_test", path)
    assert spec is not None and spec.loader is not None
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    try:
        with scoped_execution_environment().comparison({KEY: encode_candidate_inputs(inputs),
                "BCF_VALIDATION_LANE": LocalValidationLane.PROVIDER_PR.value}):
            with pytest.raises(ValueError, match="candidate transport in released/default domain") as failure:
                gate._architecture_config()
            assert any(entry.name == "compile_gate_ownership" for entry in failure.traceback)
        with scoped_execution_environment().comparison({KEY: encode_candidate_inputs(inputs),
                "BCF_VALIDATION_LANE": LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION.value}):
            if binding == "exact":
                assert gate._architecture_config()["source_component_ownership"]["version"] == "1.1"
                result = gate._ownership()
                assert result.release is None
                assert result.candidate.authority is False and result.candidate.publication_authority is False
                assert result.projection.raw_observation is result.native.observation
                assert gate._layer_names_for_file(root / member) == {"tooling"}
                assert gate._context_names_for_file(root / member) == {"_bcf_runtime"}
            else:
                with pytest.raises(ValueError, match="managed declaration differs from native candidate") as failure:
                    gate._architecture_config()
                assert type(failure.value).__name__ == "SourceComponentError"
                assert any(entry.name == "_reduce_membership" for entry in failure.traceback)
    finally:
        config_path.write_bytes(original)
        commit(root)
