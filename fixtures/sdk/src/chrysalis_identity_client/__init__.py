"""Shared client helpers for Chrysalis Identity consumers."""

from chrysalis_identity_client.claims import IdentityClaims, OIDCIdTokenClaims
from chrysalis_identity_client.config import IdentityClientConfig
from chrysalis_identity_client.permissions import require_capability
from chrysalis_identity_client.validation import decode_access_token, decode_id_token

__all__ = [
    "IdentityClaims",
    "IdentityClientConfig",
    "OIDCIdTokenClaims",
    "decode_access_token",
    "decode_id_token",
    "require_capability",
]

__version__ = "0.2.0"
