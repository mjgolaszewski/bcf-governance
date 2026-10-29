from __future__ import annotations

from chrysalis_identity_client.claims import IdentityClaims


class CapabilityDenied(PermissionError):
    pass


def require_capability(claims: IdentityClaims, capability: str) -> IdentityClaims:
    if not claims.has_capability(capability):
        raise CapabilityDenied(f"missing required capability: {capability}")
    return claims


def require_all_capabilities(
    claims: IdentityClaims,
    capabilities: list[str] | tuple[str, ...],
) -> IdentityClaims:
    missing = [capability for capability in capabilities if not claims.has_capability(capability)]
    if missing:
        raise CapabilityDenied("missing required capabilities: " + ", ".join(missing))
    return claims
