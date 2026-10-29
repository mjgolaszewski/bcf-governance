"""Registered confidential broker's persistent DPoP sender key; no inbound proof bypass."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit

import jwt

from chrysalis_identity_client.broker_keys import registered_signing_key


class DPoPSender:
    """Explicit registered PS256, ES256 or EdDSA broker profile. Caller persists and protects the private JWK."""

    def __init__(self, private_jwk: Mapping[str, str]) -> None:
        signing = registered_signing_key(private_jwk)
        self._key, self._algorithm, self._public = (
            signing.key,
            signing.algorithm,
            signing.public_jwk,
        )
        canonical = json.dumps(self._public, sort_keys=True, separators=(",", ":")).encode()
        self._thumbprint = (
            base64.urlsafe_b64encode(hashlib.sha256(canonical).digest())
            .rstrip(b"=")
            .decode("ascii")
        )

    @property
    def thumbprint(self) -> str:
        return self._thumbprint

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def proof(self, method: str, url: str, *, nonce: str | None = None) -> str:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("broker endpoint requires HTTPS without embedded credentials")
        target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": target,
            "iat": int(time.time()),
        }
        if nonce:
            payload["nonce"] = nonce
        return jwt.encode(
            payload,
            self._key,
            algorithm=self._algorithm,
            headers={"typ": "dpop+jwt", "jwk": self._public},
        )
