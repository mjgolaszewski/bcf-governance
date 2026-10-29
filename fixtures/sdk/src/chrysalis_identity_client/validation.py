from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import jwt

from chrysalis_identity_client.claims import IdentityClaims, OIDCIdTokenClaims


class UnknownJWKSKeyError(ValueError):
    def __init__(self, kid: str) -> None:
        super().__init__("no JWKS key found for token kid")
        self.kid = kid


def select_jwk_for_token(token: str, key_set: Mapping[str, Any]) -> Mapping[str, Any]:
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    algorithm = header.get("alg")
    keys = key_set.get("keys")
    if not kid or not isinstance(keys, list):
        raise ValueError("token header and key set must include kid and keys")
    if not isinstance(algorithm, str):
        raise jwt.InvalidAlgorithmError("token header must include alg")

    matches = [key for key in keys if isinstance(key, Mapping) and key.get("kid") == kid]
    if not matches:
        raise UnknownJWKSKeyError(str(kid))
    if len(matches) > 1:
        raise ValueError("JWKS contains duplicate kid")
    key = matches[0]
    _validate_jwk_shape(key, kid=str(kid), algorithm=algorithm)
    return key


def decode_access_token(
    token: str,
    key_set: Mapping[str, Any],
    *,
    issuer: str,
    audience: str | Sequence[str],
    algorithms: Sequence[str] = ("RS256", "EdDSA"),
) -> IdentityClaims:
    payload = _decode_access_token_payload(
        token, key_set, issuer=issuer, audience=audience, algorithms=algorithms
    )
    if payload.get("cnf") is not None:
        raise ValueError(
            "sender-constrained access tokens require proof validation or introspection"
        )
    return IdentityClaims.from_mapping(payload)


def _decode_access_token_payload(
    token: str,
    key_set: Mapping[str, Any],
    *,
    issuer: str,
    audience: str | Sequence[str],
    algorithms: Sequence[str] = ("RS256", "EdDSA"),
) -> dict[str, Any]:
    _ensure_allowed_token_algorithm(token, algorithms)
    _ensure_access_token_type(token)
    jwk = select_jwk_for_token(token, key_set)
    key = jwt.PyJWK.from_dict(dict(jwk)).key
    payload = jwt.decode(
        token,
        key=key,
        issuer=issuer,
        audience=audience,
        algorithms=list(algorithms),
        options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]},
    )
    if not isinstance(payload, dict):
        raise ValueError("JWT payload must be an object")
    if payload.get("type") != "access":
        raise ValueError("expected access token")
    if not isinstance(payload.get("jti"), str) or not str(payload["jti"]).strip():
        raise ValueError("access token jti is required")
    if not isinstance(payload.get("permissions_version"), str) or not str(
        payload["permissions_version"]
    ).strip():
        raise ValueError("access token permissions_version is required")
    return payload


def decode_id_token(
    token: str,
    key_set: Mapping[str, Any],
    *,
    issuer: str,
    audience: str | Sequence[str],
    algorithms: Sequence[str] = ("RS256", "EdDSA"),
    nonce: str | None = None,
    allow_missing_nonce: bool = False,
) -> OIDCIdTokenClaims:
    _ensure_allowed_token_algorithm(token, algorithms)
    jwk = select_jwk_for_token(token, key_set)
    key = jwt.PyJWK.from_dict(dict(jwk)).key
    payload = jwt.decode(
        token,
        key=key,
        issuer=issuer,
        audience=audience,  # client_id audience for ID tokens
        algorithms=list(algorithms),
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    if not isinstance(payload, dict):
        raise ValueError("JWT payload must be an object")
    if payload.get("type") == "access":
        raise ValueError("expected ID token")
    if not isinstance(payload.get("sub"), str) or not str(payload["sub"]).strip():
        raise ValueError("ID token subject is required")
    if nonce is None:
        if not allow_missing_nonce:
            raise ValueError("ID token nonce is required")
    elif payload.get("nonce") != nonce:
        raise ValueError("ID token nonce mismatch")
    return OIDCIdTokenClaims.from_mapping(payload)


def _ensure_allowed_token_algorithm(token: str, algorithms: Sequence[str]) -> None:
    header = jwt.get_unverified_header(token)
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in set(algorithms):
        raise jwt.InvalidAlgorithmError("unsupported token algorithm")


def _ensure_access_token_type(token: str) -> None:
    header = jwt.get_unverified_header(token)
    if header.get("typ") != "at+jwt":
        raise ValueError("access token JWT typ must be at+jwt")


def _validate_jwk_shape(jwk: Mapping[str, Any], *, kid: str, algorithm: str) -> None:
    if jwk.get("kid") != kid:
        raise ValueError("JWKS key kid does not match token kid")
    if jwk.get("alg") not in {None, algorithm}:
        raise ValueError("JWKS key alg does not match token algorithm")
    if jwk.get("use") not in {None, "sig"}:
        raise ValueError("JWKS key use must be sig")

    key_ops = jwk.get("key_ops")
    if key_ops is not None:
        if isinstance(key_ops, str | bytes) or not isinstance(key_ops, Sequence):
            raise ValueError("JWKS key_ops must be a list when present")
        if "verify" not in key_ops:
            raise ValueError("JWKS key_ops must include verify")

    if algorithm == "RS256":
        if jwk.get("kty") != "RSA":
            raise ValueError("RS256 JWKS keys must be RSA")
        return

    if algorithm == "EdDSA":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError("EdDSA JWKS keys must be Ed25519 OKP keys")
        return

    raise jwt.InvalidAlgorithmError("unsupported token algorithm")
