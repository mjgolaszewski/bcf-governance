from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request, status

from chrysalis_identity_client.auth import IdentityAuthenticator
from chrysalis_identity_client.claims import IdentityClaims
from chrysalis_identity_client.permissions import CapabilityDenied, require_capability


IDENTITY_CLAIMS_STATE_KEY = "chrysalis_identity_claims"
IDENTITY_AUTH_RESULT_STATE_KEY = "chrysalis_identity_auth_result"

IdentityClaimsDependency = Callable[[Request], Awaitable[IdentityClaims]]


def extract_bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.strip()


async def identity_claims_from_request(request: Request) -> IdentityClaims:
    claims = getattr(request.state, IDENTITY_CLAIMS_STATE_KEY, None)
    if not isinstance(claims, IdentityClaims):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing identity claims",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return claims


def bearer_claims_dependency(authenticator: IdentityAuthenticator) -> IdentityClaimsDependency:
    async def dependency(request: Request) -> IdentityClaims:
        token = extract_bearer_token(request)
        try:
            result = await authenticator.validate_access_token(token)
        except Exception as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from error
        setattr(request.state, IDENTITY_CLAIMS_STATE_KEY, result.claims)
        setattr(request.state, IDENTITY_AUTH_RESULT_STATE_KEY, result)
        return result.claims

    return dependency


def require_capability_dependency(
    capability: str,
    *,
    authenticator: IdentityAuthenticator | None = None,
    claims_dependency: IdentityClaimsDependency | None = None,
) -> IdentityClaimsDependency:
    if authenticator is not None and claims_dependency is not None:
        raise ValueError("provide either authenticator or claims_dependency, not both")

    if claims_dependency is None:
        claims_dependency = (
            bearer_claims_dependency(authenticator)
            if authenticator is not None
            else identity_claims_from_request
        )

    async def dependency(request: Request) -> IdentityClaims:
        claims = await claims_dependency(request)
        try:
            return require_capability(claims, capability)
        except CapabilityDenied as error:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="missing required capability",
            ) from error

    return dependency
