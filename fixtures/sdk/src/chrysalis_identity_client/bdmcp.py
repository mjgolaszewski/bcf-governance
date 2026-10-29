"""Compatibility import path for the BDMCP client adapter."""

from chrysalis_identity_client.adapters.bdmcp import (
    BDMCP_AUDIENCE,
    BDMCP_SESSION_READ,
    BDMCPIdentityConfig,
    create_bdmcp_authenticator,
    require_bdmcp_capability,
)

__all__ = [
    "BDMCP_AUDIENCE",
    "BDMCP_SESSION_READ",
    "BDMCPIdentityConfig",
    "create_bdmcp_authenticator",
    "require_bdmcp_capability",
]
