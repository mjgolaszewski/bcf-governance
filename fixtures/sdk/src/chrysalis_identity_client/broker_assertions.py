"""Explicit registered private_key_jwt authentication, never an automatic fallback."""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from urllib.parse import urlsplit

import jwt

from chrysalis_identity_client.broker_keys import registered_signing_key


class PrivateKeyJWT:
    def __init__(self, private_jwk: Mapping[str, str], *, lifetime_seconds: int = 60) -> None:
        kid = private_jwk.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            raise ValueError("registered assertion kid is required")
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 60:
            raise ValueError("assertion lifetime must be between 1 and 60 seconds")
        self._signing = registered_signing_key(private_jwk)
        self._kid, self._lifetime = kid, lifetime_seconds

    @property
    def algorithm(self) -> str:
        return self._signing.algorithm

    def form(self, client_id: str, issuer: str) -> dict[str, str]:
        parsed = urlsplit(issuer)
        if (
            not client_id
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("registered client and HTTPS issuer are required")
        now = int(time.time())
        assertion = jwt.encode(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": issuer,
                "iat": now,
                "nbf": now,
                "exp": now + self._lifetime,
                "jti": str(uuid.uuid4()),
            },
            self._signing.key,
            algorithm=self._signing.algorithm,
            headers={"kid": self._kid, "typ": "JWT"},
        )
        return {
            "client_id": client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        }
