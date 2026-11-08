"""Fresh native gate bridge; candidate inputs never become release authority."""
from __future__ import annotations

from pathlib import Path

from .architecture_candidate_transport import decode_candidate_inputs
from .architecture_membership_compilation import (
    EffectiveSourceInventory,
    NativeReleaseInputs,
    build_effective_inventory,
    qualify_candidate_effective_inventory,
)
from .architecture_release_context import decode_release_inputs
from .architecture_source_components import SourceComponentError
from .architecture_source_observation import duplication_blocks as duplication_blocks
from .bootstrap.environment import comparison_settings
from .local_pr_context import LocalValidationLane


def compile_gate_ownership(root: Path, *, release_inputs: NativeReleaseInputs | None = None) -> EffectiveSourceInventory:
    settings = comparison_settings()
    raw = settings.candidate_membership_inputs()
    released = settings.release_membership_inputs()
    lane = settings.validation_lane(LocalValidationLane.PROVIDER_PR.value)
    if lane == LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION.value:
        if release_inputs is not None or released:
            raise SourceComponentError("native gate: release inputs in candidate domain")
        inputs = decode_candidate_inputs(raw, isolated_candidate=True)
        return qualify_candidate_effective_inventory(root, inputs=inputs)
    if raw:
        raise SourceComponentError("native gate: candidate transport in released/default domain")
    if released:
        transported = decode_release_inputs(released)
        if release_inputs is not None:
            if (release_inputs.assets_root != transported.assets_root
                    or release_inputs.template_root != transported.template_root):
                raise SourceComponentError("native gate: ambiguous explicit release inputs")
        else:
            release_inputs = transported
    return build_effective_inventory(root, release_inputs=release_inputs)


def reauthenticate_gate_ownership(root: Path, previous: EffectiveSourceInventory, *,
                                 release_inputs: NativeReleaseInputs | None = None) -> None:
    fresh = compile_gate_ownership(root, release_inputs=release_inputs)
    if type(previous) is not type(fresh) or previous != fresh:
        raise SourceComponentError("native gate: current source or ownership context changed")
