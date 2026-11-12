"""The legacy facade and both real consumers share one protocol implementation."""
from bcf_governance.tooling import semantic_python_method_identity as facade
from bcf_governance.tooling import semantic_python_calls as calls
from bcf_governance.tooling import semantic_operation_effects as effects
def test_protocol_consumers_and_legacy_facade_share_one_owner():
    assert calls._native_literal_value is facade._native_literal_value
    assert calls.implicit_runtime_protocols is facade.implicit_runtime_protocols
    assert calls.IMPLICIT_PROTOCOL_KIND_VERSIONS is facade.IMPLICIT_PROTOCOL_KIND_VERSIONS
    assert effects.IMPLICIT_PROTOCOL_KIND_VERSIONS is facade.IMPLICIT_PROTOCOL_KIND_VERSIONS
