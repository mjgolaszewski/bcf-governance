"""Registered JOSE signing-key preparation shared by assertions and DPoP."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import jwt


@dataclass(frozen=True)
class RegisteredSigningKey:
    key: Any = field(repr=False)
    algorithm: str
    public_jwk: dict[str, str]


def registered_signing_key(private_jwk: Mapping[str, str]) -> RegisteredSigningKey:
    """Only the producer's explicit asymmetric key profiles; no algorithm fallback."""
    kind = private_jwk.get("kty")
    members: tuple[str, ...]
    if kind == "RSA":
        algorithm, members = "PS256", ("e", "kty", "n")
    elif kind == "EC" and private_jwk.get("crv") == "P-256":
        algorithm, members = "ES256", ("crv", "kty", "x", "y")
    elif kind == "OKP" and private_jwk.get("crv") == "Ed25519":
        algorithm, members = "EdDSA", ("crv", "kty", "x")
    else:
        raise ValueError("unsupported registered signing-key profile")
    if (
        not private_jwk.get("d")
        or private_jwk.get("alg", algorithm) != algorithm
        or private_jwk.get("use", "sig") != "sig"
        or ("key_ops" in private_jwk and private_jwk["key_ops"] != ["sign"])
    ):
        raise ValueError("private signing key and matching algorithm are required")
    try:
        key = jwt.PyJWK.from_dict(dict(private_jwk), algorithm=algorithm).key
        public = {member: private_jwk[member] for member in members}
        if kind == "RSA" and key.key_size < 2048:
            raise ValueError("RSA key too small")
    except (ValueError, KeyError, TypeError, jwt.PyJWTError):
        raise ValueError("invalid registered signing key") from None
    return RegisteredSigningKey(key, algorithm, public)


def fapi_verification_key_set(token: str, key_set: Mapping[str, Any]) -> dict[str, Any]:
    """Select a supported issuer key; callers still verify all claims and authority.

    Shared by FAPI access-token and ID-token validation. Duplicate identifiers are
    narrowed by public JWK attributes and signature rather than changing default
    bearer validation's duplicate-key policy.
    """
    from chrysalis_identity_client.validation import UnknownJWKSKeyError

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid or header.get("alg") != "EdDSA":
        raise ValueError("unsupported FAPI issuer token header")
    keys = key_set.get("keys")
    if not isinstance(keys, list):
        raise ValueError("invalid FAPI issuer key set")
    matching = [key for key in keys if isinstance(key, Mapping) and key.get("kid") == kid]
    if not matching:
        raise UnknownJWKSKeyError(kid)
    for candidate in matching:
        operations = candidate.get("key_ops")
        if (
            candidate.get("kty") != "OKP"
            or candidate.get("crv") != "Ed25519"
            or candidate.get("alg") not in {None, "EdDSA"}
            or candidate.get("use") not in {None, "sig"}
            or any(member in candidate for member in {"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
            or (
                operations is not None
                and (
                    not isinstance(operations, list)
                    or not all(isinstance(operation, str) for operation in operations)
                    or "verify" not in operations
                )
            )
        ):
            continue
        try:
            public_key = jwt.PyJWK.from_dict(dict(candidate), algorithm="EdDSA").key
            jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                options={
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                    "verify_jti": False,
                },
            )
        except (ValueError, TypeError, KeyError, jwt.PyJWTError):
            continue
        return {"keys": [dict(candidate)]}
    raise ValueError("no usable FAPI issuer verification key")
