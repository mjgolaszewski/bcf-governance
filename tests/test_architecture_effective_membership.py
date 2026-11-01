"""Private reducer contracts. Synthetic inputs prove reduction, never authority."""
from dataclasses import replace
import hashlib
from pathlib import Path

import pytest

from bcf_governance.tooling import architecture_effective_membership as reducer
from bcf_governance.tooling.architecture_native_inventory import (
    ContextBinding, NativeSourceInventory, SourceMember,
)
from bcf_governance.tooling.architecture_source_components import (
    ContextSelector, ManagedPackBinding, SourceComponent, SourceComponentError,
)
from bcf_governance.tooling.architecture_source_observation import Observation, Policy, Violation


@pytest.fixture
def data():
    raw = b"VALUE = 1\n"
    digest = hashlib.sha256(raw).hexdigest()
    member = SourceMember("src/orders/value.py", digest, raw, (), ("orders",))
    unknown = SourceMember("src/unknown.py", digest, raw, (), ())
    policy = Policy(("src",), (), (), (("domain", ("domain",)),), ("src",), (),
                    0, 0, ("delegate",), 6)
    observation = Observation(((member.path, digest), (unknown.path, digest)), (), (
        Violation("layer_membership", member.path, 1, "[]"),
        Violation("duplication", member.path, 1, "raw duplicate window"),
        Violation("context_membership", unknown.path, 1, "[]"),
    ))
    subject = (("commit_sha", "a" * 40), ("tracked_clean", True))
    binding = ContextBinding("independently_inferred_inventory", "1.0", "orders", "orders",
                             reducer._object_sha(dict(subject)), "b" * 64,
                             reducer._object_sha(((member.path, digest, ("orders",)),)))
    inventory = NativeSourceInventory(Path("/synthetic/not-authority"), subject, "b" * 64,
                                      "c" * 64, policy, (member, unknown), (binding,), observation)
    component = SourceComponent("orders-values", "domain", "orders", "Exact source grouping",
                                ((member.path, digest),), None,
                                ContextSelector(binding.kind, binding.version, binding.selector))
    classifications = tuple(reducer.MemberClassification(row.path, row.sha256, "project")
                            for row in inventory.members)
    return inventory, component, classifications


def test_fill_missing_layer_preserves_all_raw_rows_and_unknown_population(data):
    inventory, component, classifications = data
    result = reducer._reduce_membership(inventory, (component,), classifications)
    assert result.raw_observation is inventory.observation
    assert result.members[0].effective_layers == ("domain",)
    assert result.members[0].inferred_layers == ()
    assert result.members[0].context_witness_sha256 == inventory.contexts[0].member_sha256
    assert result.members[1].path == "src/unknown.py"
    assert result.members[1].effective_layers == result.members[1].effective_contexts == ()
    assert result.members[1].component_id is None
    assert len(result.raw_observation.violations) == 3


def test_matching_inference_is_one_corroborated_assignment(data):
    inventory, component, classifications = data
    inventory = replace(inventory, members=(replace(inventory.members[0], inferred_layers=("domain",)),
                                             inventory.members[1]))
    result = reducer._reduce_membership(inventory, (component,), classifications)
    assert result.members[0].effective_layers == ("domain",)
    assert result.members[0].component_id == component.id


def test_absent_declarations_preserve_every_inference_and_raw_finding(data):
    inventory, _, classifications = data
    result = reducer._reduce_membership(inventory, (), classifications)
    assert result.raw_observation is inventory.observation
    assert tuple(row.path for row in result.members) == tuple(row.path for row in inventory.members)
    assert all(row.component_id is None and row.context_witness_sha256 is None
               and row.inferred_layers == row.effective_layers
               and row.inferred_contexts == row.effective_contexts for row in result.members)


@pytest.mark.parametrize("mutation", ["healthy", "borrow-other-file", "executable", "owner-layer"])
def test_metadata_context_is_exact_docstring_member_only(data, mutation):
    inventory, component, _ = data
    raw = b'"""Package metadata."""\n'
    if mutation == "executable": raw += b"import os\n"
    digest = hashlib.sha256(raw).hexdigest()
    member = SourceMember("src/orders/__init__.py", digest, raw, (), ())
    metadata = (member.path, "domain", "orders", ("__doc__",))
    policy = replace(inventory.policy, metadata_ownership=(metadata,))
    binding = ContextBinding("qualified_package_metadata_context", "1.0", member.path, "orders",
                             reducer._object_sha(dict(inventory.subject)), inventory.config_sha256,
                             reducer._object_sha((member.path, digest, "domain", "orders", ("__doc__",))))
    component = replace(component, members=((member.path, digest),),
                        context_authority=ContextSelector(binding.kind, "1.0", member.path))
    inventory = replace(inventory, members=(member,), policy=policy, contexts=(binding,),
                        observation=replace(inventory.observation, source_sha256=((member.path, digest),)))
    if mutation == "borrow-other-file":
        component = replace(component, context_authority=replace(component.context_authority,
                                                                 selector="src/other/__init__.py"))
        inventory = replace(inventory, contexts=(replace(binding, selector="src/other/__init__.py"),))
    elif mutation == "owner-layer":
        inventory = replace(inventory, policy=replace(policy, metadata_ownership=(
            (member.path, "other", "orders", ("__doc__",)),)))
    classifications = (reducer.MemberClassification(member.path, digest, "project"),)
    if mutation == "healthy":
        result = reducer._reduce_membership(inventory, (component,), classifications)
        assert result.members[0].effective_contexts == ("orders",)
        assert result.members[0].effective_layers == ("domain",)
    else:
        expected = {
            "borrow-other-file": "metadata context cannot authorize another member",
            "executable": "metadata source must contain only its package docstring",
            "owner-layer": "metadata declaration differs from native metadata owner",
        }[mutation]
        with pytest.raises(SourceComponentError, match=expected) as failure:
            reducer._reduce_membership(inventory, (component,), classifications)
        assert any(entry.name == "_context_witness" for entry in failure.traceback)


@pytest.mark.parametrize("mutation,diagnostic", [
    ("empty", "nonempty unique native population required"),
    ("duplicate", "nonempty unique native population required"),
    ("ambiguous-context", "component conflicts with inferred contexts"),
])
def test_native_population_and_ambiguous_context_boundaries(data, mutation, diagnostic):
    inventory, component, classifications = data
    if mutation == "empty":
        inventory = replace(inventory, members=())
    elif mutation == "duplicate":
        inventory = replace(inventory, members=inventory.members + inventory.members[:1])
    else:
        inventory = replace(inventory, members=(replace(inventory.members[0],
            inferred_contexts=("orders", "other")), inventory.members[1]))
    with pytest.raises(SourceComponentError, match=diagnostic) as failure:
        reducer._reduce_membership(inventory, (component,), classifications)
    assert any(entry.name == "_reduce_membership" for entry in failure.traceback)


@pytest.mark.parametrize("binding_state", ["exact", "missing", "stale", "foreign-path"])
def test_private_managed_data_requires_exact_native_lock_join(data, binding_state):
    inventory, component, classifications = data
    digest = "d" * 64
    binding = ManagedPackBinding("governance/bcf-runtime-lock.json", digest)
    if binding_state == "missing": binding = None
    elif binding_state == "stale": binding = replace(binding, runtime_lock_sha256="e" * 64)
    elif binding_state == "foreign-path": binding = replace(binding, runtime_lock_path="another.json")
    component = replace(component, managed_pack=binding)
    classifications = (replace(classifications[0], ownership="managed"), classifications[1])
    if binding_state == "exact":
        result = reducer._reduce_membership(inventory, (component,), classifications,
                                             managed_lock_sha256=digest)
        assert result.members[0].component_id == component.id
        assert result.raw_observation is inventory.observation
    else:
        with pytest.raises(SourceComponentError, match="managed declaration differs") as failure:
            reducer._reduce_membership(inventory, (component,), classifications,
                                        managed_lock_sha256=digest)
        assert any(entry.name == "_reduce_membership" for entry in failure.traceback)


@pytest.mark.parametrize("mutation,diagnostic", [
    ("missing-classification", "complete and unique"),
    ("extra-classification", "complete and unique"),
    ("duplicate-classification", "complete and unique"),
    ("stale-classification", "stale independent managedness"),
    ("unknown-classification", "unresolved or stale"),
    ("managed-with-null", "pending custody adapter"),
    ("project-with-lock", "project member cannot claim managed release membership"),
    ("duplicate-owner", "multiple components"),
    ("duplicate-id", "duplicate component"),
    ("unobserved-member", "unobserved or stale"),
    ("stale-member", "unobserved or stale"),
    ("foreign-layer", "unknown layer"),
    ("conflicting-layer", "conflicts with inferred layers"),
    ("ambiguous-layer", "conflicts with inferred layers"),
    ("conflicting-context", "conflicts with inferred contexts"),
    ("borrowed-context", "cannot be borrowed"),
    ("unsupported-contract", "not implemented"),
    ("stale-subject", "subject differs"),
    ("stale-config", "configuration differs"),
    ("stale-witness", "witness differs"),
    ("duplicate-context", "resolve uniquely"),
    ("observer-population", "observer population differs"),
    ("source-bytes", "source bytes differ"),
])
def test_refuse_unresolved_or_conflicting_data(data, mutation, diagnostic):
    inventory, component, classifications = data
    components = (component,)
    if mutation == "missing-classification": classifications = classifications[:-1]
    elif mutation == "extra-classification":
        classifications += (replace(classifications[0], path="src/extra.py"),)
    elif mutation == "duplicate-classification": classifications += classifications[:1]
    elif mutation == "stale-classification":
        classifications = (replace(classifications[0], sha256="0" * 64), classifications[1])
    elif mutation == "unknown-classification":
        classifications = (replace(classifications[0], ownership="unresolved"), classifications[1])
    elif mutation == "managed-with-null":
        classifications = (replace(classifications[0], ownership="managed"), classifications[1])
    elif mutation == "project-with-lock":
        components = (replace(component, managed_pack=ManagedPackBinding(
            "governance/bcf-runtime-lock.json", "0" * 64)),)
    elif mutation == "duplicate-owner": components += (replace(component, id="second"),)
    elif mutation == "duplicate-id": components += components
    elif mutation == "unobserved-member":
        components = (replace(component, members=(("src/extra.py", component.members[0][1]),)),)
    elif mutation == "stale-member":
        components = (replace(component, members=((component.members[0][0], "0" * 64),)),)
    elif mutation == "foreign-layer": components = (replace(component, layer="unconfigured"),)
    elif mutation in {"conflicting-layer", "ambiguous-layer"}:
        layers = ("other",) if mutation == "conflicting-layer" else ("domain", "other")
        inventory = replace(inventory, members=(replace(inventory.members[0], inferred_layers=layers),
                                                 inventory.members[1]))
    elif mutation in {"conflicting-context", "borrowed-context"}:
        contexts = ("other",) if mutation == "conflicting-context" else ()
        inventory = replace(inventory, members=(replace(inventory.members[0], inferred_contexts=contexts),
                                                 inventory.members[1]))
    elif mutation == "unsupported-contract":
        components = (replace(component, context_authority=ContextSelector(
            "maintained_native_context_contract", "1.0", "requested")),)
    elif mutation in {"stale-subject", "stale-config", "stale-witness"}:
        field = {"stale-subject": "subject_sha256", "stale-config": "config_sha256",
                 "stale-witness": "member_sha256"}[mutation]
        inventory = replace(inventory, contexts=(replace(inventory.contexts[0], **{field: "0" * 64}),))
    elif mutation == "duplicate-context": inventory = replace(inventory, contexts=inventory.contexts * 2)
    elif mutation == "observer-population":
        inventory = replace(inventory, observation=replace(inventory.observation, source_sha256=()))
    elif mutation == "source-bytes":
        inventory = replace(inventory, members=(replace(inventory.members[0], raw=b"changed\n"),
                                                 inventory.members[1]))
    else: raise AssertionError(mutation)
    with pytest.raises(SourceComponentError, match=diagnostic):
        reducer._reduce_membership(inventory, components, classifications)


@pytest.mark.parametrize("domain,binding_kind,digest", [
    ("candidate", "candidate", "a" * 64),
    ("candidate", "release", "a" * 64),
    ("release", "candidate", "a" * 64),
    ("release", "release", "a" * 64),
    ("candidate", "candidate", "0" * 64),
    ("release", "release", "0" * 64),
])
def test_exact_custody_domains_cannot_cross_or_reuse_stale_binding(data, domain, binding_kind, digest):
    from bcf_governance.tooling.architecture_source_components import CandidatePackBinding
    inventory, component, classifications = data
    binding = (CandidatePackBinding("governance/bcf-candidate-qualification.json", digest)
               if binding_kind == "candidate" else
               ManagedPackBinding("governance/bcf-runtime-lock.json", digest))
    component = replace(component, managed_pack=binding)
    classifications = (replace(classifications[0], ownership="managed"), classifications[1])
    kwargs = ({"candidate_qualification_sha256": "a" * 64} if domain == "candidate"
              else {"managed_lock_sha256": "a" * 64})
    if domain == binding_kind and digest == "a" * 64:
        result = reducer._reduce_membership(inventory, (component,), classifications, **kwargs)
        assert result.raw_observation is inventory.observation
        assert result.members[0].component_id == component.id
    else:
        with pytest.raises(SourceComponentError, match="managed declaration differs") as failure:
            reducer._reduce_membership(inventory, (component,), classifications, **kwargs)
        assert any(entry.name == "_reduce_membership" for entry in failure.traceback)


def test_two_custody_domains_cannot_be_combined_even_without_components(data):
    inventory, _, classifications = data
    with pytest.raises(SourceComponentError, match="domains cannot be combined") as failure:
        reducer._reduce_membership(inventory, (), classifications,
                                  managed_lock_sha256="a" * 64,
                                  candidate_qualification_sha256="a" * 64)
    assert any(entry.name == "_reduce_membership" for entry in failure.traceback)
