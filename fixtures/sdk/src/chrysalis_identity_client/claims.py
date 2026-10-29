from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


def _tuple_from_claim(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part for part in value.split() if part)
    if isinstance(value, Sequence) and not isinstance(value, bytes):
        return tuple(str(item) for item in value)
    return (str(value),)


@dataclass(frozen=True)
class IdentityClaims:
    subject: str
    issuer: str | None = None
    audience: tuple[str, ...] = ()
    tenant_id: str | None = None
    email: str | None = None
    roles: tuple[str, ...] = ()
    entitlements: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    permissions_version: str | None = None
    amr: tuple[str, ...] = ()
    acr: str | None = None
    auth_time: int | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, claims: Mapping[str, Any]) -> "IdentityClaims":
        scopes = set(_tuple_from_claim(claims.get("scope")))
        scopes.update(_tuple_from_claim(claims.get("scp")))
        scopes.update(_tuple_from_claim(claims.get("scopes")))
        capabilities = _tuple_from_claim(claims.get("capabilities"))
        entitlements = _tuple_from_claim(claims.get("entitlements")) or capabilities
        auth_time = claims.get("auth_time")

        return cls(
            subject=str(claims["sub"]),
            issuer=str(claims["iss"]) if claims.get("iss") else None,
            audience=_tuple_from_claim(claims.get("aud")),
            tenant_id=str(claims["tenant_id"]) if claims.get("tenant_id") else None,
            email=str(claims["email"]) if claims.get("email") else None,
            roles=_tuple_from_claim(claims.get("roles")),
            entitlements=entitlements,
            scopes=tuple(sorted(scopes)),
            capabilities=capabilities,
            permissions_version=(
                str(claims["permissions_version"])
                if claims.get("permissions_version") is not None
                else None
            ),
            amr=_tuple_from_claim(claims.get("amr")),
            acr=str(claims["acr"]) if claims.get("acr") else None,
            auth_time=int(auth_time) if auth_time is not None else None,
            raw=dict(claims),
        )

    @property
    def authentication_methods(self) -> tuple[str, ...]:
        return self.amr

    def has_audience(self, audience: str) -> bool:
        return audience in self.audience

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_entitlement(self, entitlement: str) -> bool:
        return entitlement in self.entitlements

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def has_authentication_method(self, method: str) -> bool:
        return method in self.amr


@dataclass(frozen=True)
class OIDCIdTokenClaims:
    subject: str
    issuer: str
    audience: tuple[str, ...]
    nonce: str | None = None
    auth_time: int | None = None
    email: str | None = None
    amr: tuple[str, ...] = ()
    acr: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, claims: Mapping[str, Any]) -> "OIDCIdTokenClaims":
        auth_time = claims.get("auth_time")
        return cls(
            subject=str(claims["sub"]),
            issuer=str(claims["iss"]),
            audience=_tuple_from_claim(claims.get("aud")),
            nonce=str(claims["nonce"]) if claims.get("nonce") is not None else None,
            auth_time=int(auth_time) if auth_time is not None else None,
            email=str(claims["email"]) if claims.get("email") else None,
            amr=_tuple_from_claim(claims.get("amr")),
            acr=str(claims["acr"]) if claims.get("acr") else None,
            raw=dict(claims),
        )

    @property
    def authentication_methods(self) -> tuple[str, ...]:
        return self.amr
