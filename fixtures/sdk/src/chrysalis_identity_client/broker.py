"""Explicit confidential DPoP broker edge; no persistence and no ordinary bearer bypass."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Literal
from urllib.parse import quote_plus, urlencode, urlsplit

import httpx
import jwt

from chrysalis_identity_client.broker_keys import fapi_verification_key_set
from chrysalis_identity_client.broker_assertions import PrivateKeyJWT
from chrysalis_identity_client.broker_authorization import (
    AuthorizationRequest,
    authorization_scopes,
    authorization_code,
    new_authorization_secrets,
    validate_redirect_uri,
)
from chrysalis_identity_client.broker_models import (
    BrokerCredentials,
    BrokerGrantError,
    BrokerOutcome,
    FreshAuthority,
    GrantExchangeResult,
    GrantOwner,
)
from chrysalis_identity_client.broker_sender import DPoPSender
from chrysalis_identity_client.claims import IdentityClaims
from chrysalis_identity_client.jwks import JWKSClient
from chrysalis_identity_client.validation import (
    UnknownJWKSKeyError,
    _decode_access_token_payload,
    decode_id_token,
)


def _oauth_basic_auth(client_id: str, client_secret: str) -> httpx.BasicAuth:
    """RFC 6749 client authentication for broker and separate introspector."""
    return httpx.BasicAuth(quote_plus(client_id, safe=""), quote_plus(client_secret, safe=""))


class OAuthBrokerClient:
    """Only the registered broker that owns the sender key may use this interface.

    This validates tokens held by that broker, not DPoP requests arriving at a resource server.
    Callers serialize refresh and persist the received successor before using renewed authority.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        tenant_id: str,
        client_id: str,
        client_secret: str | None = None,
        client_authentication: PrivateKeyJWT | None = None,
        security_profile: Literal["baseline", "fapi"] = "baseline",
        introspection_client_id: str,
        introspection_client_secret: str,
        sender: DPoPSender,
        http_client: httpx.AsyncClient,
        timeout_seconds: float = 5.0,
    ) -> None:
        parsed = urlsplit(issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("broker issuer must be an HTTPS origin")
        if not all(
            isinstance(v, str) and v.strip()
            for v in (
                audience,
                tenant_id,
                client_id,
                introspection_client_id,
                introspection_client_secret,
            )
        ):
            raise ValueError("broker registration and tenant are required")
        if (client_authentication is None) == (client_secret is None):
            raise ValueError("exactly one registered client authentication method is required")
        if client_secret is not None and not client_secret.strip():
            raise ValueError("registered client secret must be nonempty")
        if security_profile not in {"baseline", "fapi"} or (
            security_profile == "fapi" and client_authentication is None
        ):
            raise ValueError("FAPI broker requires explicit registered private-key authentication")
        self._profile = security_profile
        if timeout_seconds <= 0:
            raise ValueError("broker timeout must be positive")
        if http_client.follow_redirects:
            raise ValueError("broker transport must disable redirects")
        if "authorization" in http_client.headers or http_client.auth is not None:
            raise ValueError("broker transport must not carry a default Authorization header")
        self._issuer = issuer.rstrip("/")
        self._audience, self._tenant, self._client_id = audience, tenant_id, client_id
        self._auth = (
            _oauth_basic_auth(client_id, client_secret)
            if client_secret is not None
            else httpx.Auth()
        )
        self._assertion_auth = client_authentication
        self._metadata: dict | None = None
        self._endpoints: dict[str, str] = {}
        self._introspection_auth = _oauth_basic_auth(
            introspection_client_id, introspection_client_secret
        )
        self._sender, self._http, self._timeout = sender, http_client, timeout_seconds
        self._jwks = JWKSClient(
            self._issuer + "/api/v1/auth/.well-known/jwks.json",
            http_client=http_client,
            timeout_seconds=timeout_seconds,
        )

    async def _discover(self) -> dict:
        if self._metadata is not None:
            return self._metadata
        try:
            response = await self._http.get(
                self._issuer + "/.well-known/openid-configuration",
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError:
            raise BrokerGrantError("retryable_provider") from None
        if response.status_code >= 500 or response.status_code == 429:
            raise BrokerGrantError("retryable_provider")
        try:
            metadata = response.json()
            if (
                response.status_code != 200
                or not isinstance(metadata, dict)
                or metadata.get("issuer") != self._issuer
            ):
                raise ValueError()
            names = {
                "authorize": "authorization_endpoint",
                "par": "pushed_authorization_request_endpoint",
                "token": "token_endpoint",
                "revoke": "revocation_endpoint",
                "introspect": "introspection_endpoint",
                "jwks": "jwks_uri",
            }
            endpoints = {}
            for name, field in names.items():
                value = metadata[field]
                parsed = urlsplit(value)
                if (
                    not isinstance(value, str)
                    or parsed.scheme != "https"
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.fragment
                    or parsed.query
                ):
                    raise ValueError()
                endpoints[name] = value
            method = (
                "private_key_jwt" if self._assertion_auth is not None else "client_secret_basic"
            )
            for field in (
                "token_endpoint_auth_methods_supported",
                "code_challenge_methods_supported",
                "dpop_signing_alg_values_supported",
            ):
                if not isinstance(metadata.get(field), list) or not all(
                    isinstance(v, str) for v in metadata[field]
                ):
                    raise ValueError()
            if (
                method not in metadata["token_endpoint_auth_methods_supported"]
                or "S256" not in metadata["code_challenge_methods_supported"]
                or metadata.get("authorization_response_iss_parameter_supported") is not True
                or self._sender.algorithm not in metadata["dpop_signing_alg_values_supported"]
            ):
                raise ValueError()
            if self._assertion_auth is not None:
                algorithms = metadata.get("token_endpoint_auth_signing_alg_values_supported")
                if (
                    not isinstance(algorithms, list)
                    or self._assertion_auth.algorithm not in algorithms
                ):
                    raise ValueError()
        except (ValueError, TypeError, KeyError, AttributeError):
            raise BrokerGrantError("invalid_response") from None
        self._endpoints = endpoints
        self._jwks = JWKSClient(
            endpoints["jwks"], http_client=self._http, timeout_seconds=self._timeout
        )
        self._metadata = metadata
        return metadata

    async def begin_authorization(
        self, *, redirect_uri: str, scopes: tuple[str, ...]
    ) -> AuthorizationRequest:
        """Caller binds initiation to its browser session and stores context encrypted server-side."""
        validate_redirect_uri(redirect_uri)
        scopes = authorization_scopes(scopes)
        await self._discover()
        state, nonce, verifier, challenge = new_authorization_secrets()
        started = int(time.time())
        pushed = await self._post(
            "par",
            {
                "response_type": "code",
                "client_id": self._client_id,
                "redirect_uri": redirect_uri,
                "scope": " ".join(scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "dpop_jkt": self._sender.thumbprint,
            },
            sender_proof=True,
        )
        uri, lifetime = pushed.get("request_uri"), pushed.get("expires_in")
        try:
            valid_uri = (
                isinstance(uri, str)
                and bool(urlsplit(uri).scheme)
                and all(32 < ord(character) < 127 for character in uri)
            )
        except ValueError:
            valid_uri = False
        if (
            not valid_uri
            or type(lifetime) is not int
            or lifetime <= 0
            or (self._profile == "fapi" and lifetime >= 600)
        ):
            raise BrokerGrantError("invalid_response")
        return AuthorizationRequest(
            issuer=self._issuer,
            client_id=self._client_id,
            audience=self._audience,
            tenant_id=self._tenant,
            sender_thumbprint=self._sender.thumbprint,
            authentication_method="private_key_jwt"
            if self._assertion_auth is not None
            else "client_secret_basic",
            security_profile=self._profile,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            authorization_url=self._endpoints["authorize"]
            + "?"
            + urlencode({"client_id": self._client_id, "request_uri": uri}),
            expires_at=started + lifetime,
        )

    async def complete_authorization(
        self, callback_url: str, *, request: AuthorizationRequest
    ) -> GrantExchangeResult:
        """Caller must atomically consume its browser-bound context before dispatch."""
        request = AuthorizationRequest.from_custody_dict(request.to_custody_dict())
        if request.security_profile != self._profile:
            raise BrokerGrantError("reauth_required")
        if (
            request.issuer,
            request.client_id,
            request.audience,
            request.tenant_id,
            request.sender_thumbprint,
            request.authentication_method,
        ) != (
            self._issuer,
            self._client_id,
            self._audience,
            self._tenant,
            self._sender.thumbprint,
            "private_key_jwt" if self._assertion_auth is not None else "client_secret_basic",
        ):
            raise BrokerGrantError("reauth_required")
        code = authorization_code(callback_url, request)
        return await self._exchange(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": request.redirect_uri,
                "code_verifier": request.code_verifier,
            },
            expected_owner=None,
            nonce=request.nonce,
            expected_scopes=request.scopes,
        )

    async def exchange_code(
        self, code: str, *, redirect_uri: str, code_verifier: str, nonce: str
    ) -> GrantExchangeResult:
        """Callback state/nonce and redirect ownership remain the consuming application's duty."""
        if not code or not redirect_uri or not nonce or not 43 <= len(code_verifier) <= 128:
            raise ValueError("authorization code, exact redirect and PKCE verifier are required")
        return await self._exchange(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            expected_owner=None,
            nonce=nonce,
        )

    async def refresh(
        self, refresh_token: str, *, expected_owner: GrantOwner
    ) -> GrantExchangeResult:
        if (
            not refresh_token
            or expected_owner.tenant_id != self._tenant
            or not expected_owner.subject
        ):
            raise ValueError("refresh requires the pinned grant owner and credential")
        return await self._exchange(
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
            expected_owner=expected_owner,
        )

    async def revoke(self, refresh_token: str) -> None:
        """A successful revocation response is not proof that an unknown token ever existed."""
        if not refresh_token:
            raise ValueError("refresh credential is required")
        await self._post(
            "revoke",
            {"token": refresh_token, "token_type_hint": "refresh_token"},
            sender_proof=True,
            require_json=False,
        )

    async def _exchange(
        self,
        form: dict[str, str],
        *,
        expected_owner: GrantOwner | None,
        nonce: str | None = None,
        expected_scopes: tuple[str, ...] | None = None,
    ) -> GrantExchangeResult:
        payload = await self._post("token", form, sender_proof=True)
        token, refresh = payload.get("access_token"), payload.get("refresh_token")
        if "refresh_token" not in payload and form.get("grant_type") == "refresh_token":
            refresh = form["refresh_token"]
        scope = payload.get("scope")
        if not isinstance(refresh, str) or not refresh:
            raise BrokerGrantError("invalid_response")
        credentials = BrokerCredentials(
            token if isinstance(token, str) else "",
            refresh,
            scope if isinstance(scope, str) else "",
        )
        if (
            not credentials.access_token
            or not isinstance(scope, str)
            or "offline_access" not in scope.split()
            or payload.get("token_type") != "DPoP"
        ):
            return GrantExchangeResult(credentials, None, BrokerGrantError("invalid_response"))
        try:
            authority = await self.validate_authority(
                credentials.access_token, expected_owner=expected_owner
            )
            if set(authority.claims.scopes) != set(scope.split()):
                raise BrokerGrantError("invalid_response")
            if expected_scopes is not None and not set(scope.split()).issubset(expected_scopes):
                raise BrokerGrantError("invalid_response")
            if nonce is not None:
                try:
                    identity = decode_id_token(
                        payload["id_token"],
                        fapi_verification_key_set(
                            payload["id_token"], await self._jwks.get_key_set()
                        )
                        if self._profile == "fapi"
                        else await self._jwks.get_key_set(),
                        issuer=self._issuer,
                        audience=self._client_id,
                        nonce=nonce,
                        algorithms=("EdDSA",) if self._profile == "fapi" else ("RS256", "EdDSA"),
                    )
                    if identity.subject != authority.owner.subject:
                        raise ValueError("identity mismatch")
                except (ValueError, jwt.PyJWTError, KeyError, TypeError):
                    raise BrokerGrantError("invalid_response") from None
        except BrokerGrantError as error:
            # The provider may have consumed the parent. Never discard a received successor.
            return GrantExchangeResult(credentials, None, error)
        return GrantExchangeResult(credentials, authority)

    async def validate_authority(
        self, access_token: str, *, expected_owner: GrantOwner | None = None
    ) -> FreshAuthority:
        """Uncached live authority for a locally held, cryptographically sender-bound token."""
        if self._assertion_auth is not None:
            await self._discover()
        try:
            keys = await self._jwks.get_key_set()
            try:
                claims = self._decode(access_token, keys)
            except UnknownJWKSKeyError:
                claims = self._decode(access_token, await self._jwks.refresh_key_set())
        except jwt.ExpiredSignatureError:
            raise BrokerGrantError("reauth_required") from None
        except httpx.HTTPError:
            raise BrokerGrantError("retryable_provider") from None
        except (ValueError, jwt.PyJWTError, KeyError, TypeError):
            raise BrokerGrantError("invalid_response") from None
        if (
            claims.get("cnf") != {"jkt": self._sender.thumbprint}
            or claims.get("client_id") != self._client_id
            or claims.get("tenant_id") != self._tenant
            or not isinstance(claims.get("sub"), str)
            or not claims["sub"].strip()
        ):
            raise BrokerGrantError("reauth_required")
        owner = GrantOwner(self._tenant, claims["sub"])
        if expected_owner is not None and owner != expected_owner:
            raise BrokerGrantError("reauth_required")
        result = await self._post("introspect", {"token": access_token, "audience": self._audience})
        if result.get("active") is not True:
            raise BrokerGrantError("reauth_required")
        for key in ("iss", "sub", "jti", "exp", "client_id", "cnf"):
            if result.get(key) != claims.get(key):
                raise BrokerGrantError("invalid_response")
        audiences = result.get("aud")
        if audiences != claims.get("aud"):
            raise BrokerGrantError("invalid_response")
        absolute = result.get("session_absolute_expires_at")
        if type(absolute) is not int or absolute <= time.time():
            raise BrokerGrantError("invalid_response")
        if type(claims["exp"]) is not int or claims["exp"] <= time.time():
            raise BrokerGrantError("reauth_required")
        return FreshAuthority(
            owner, IdentityClaims.from_mapping(claims), int(claims["exp"]), absolute
        )

    def _decode(self, token: str, keys: Mapping) -> dict:
        return _decode_access_token_payload(
            token,
            fapi_verification_key_set(token, keys) if self._profile == "fapi" else keys,
            issuer=self._issuer,
            audience=self._audience,
            algorithms=("EdDSA",) if self._profile == "fapi" else ("RS256", "EdDSA"),
        )

    async def _post(
        self,
        endpoint: str,
        form: dict[str, str],
        *,
        sender_proof: bool = False,
        require_json: bool = True,
    ) -> dict:
        if self._assertion_auth is not None:
            await self._discover()
        url = self._endpoints.get(endpoint, self._issuer + "/api/v1/auth/" + endpoint)
        nonce = None
        for attempt in range(2):
            headers = {"Accept": "application/json", "x-chrysalis-tenant": self._tenant}
            if sender_proof:
                headers["DPoP"] = self._sender.proof("POST", url, nonce=nonce)
            request_form = dict(form)
            if endpoint != "introspect" and self._assertion_auth is not None:
                request_form.update(
                    self._assertion_auth.form(
                        self._client_id,
                        self._issuer if self._profile == "fapi" or endpoint == "par" else url,
                    )
                )
            try:
                response = await self._http.post(
                    url,
                    data=request_form,
                    auth=self._introspection_auth if endpoint == "introspect" else self._auth,
                    headers=headers,
                    timeout=self._timeout,
                    follow_redirects=False,
                )
            except httpx.HTTPError:
                # Ambiguous dispatch: no automatic replay. Caller may retry SAME parent in grace.
                raise BrokerGrantError("retryable_transport") from None
            if response.status_code >= 500 or response.status_code == 429:
                raise BrokerGrantError("retryable_provider")
            if not require_json and 200 <= response.status_code < 300:
                if response.status_code != 200:
                    raise BrokerGrantError("invalid_response")
                # RFC 7009 section 2.2: only the status conveys revocation success.
                return {}
            try:
                payload = response.json() if response.content else {}
            except ValueError:
                raise BrokerGrantError("invalid_response") from None
            if not isinstance(payload, dict):
                raise BrokerGrantError("invalid_response")
            if (
                sender_proof
                and attempt == 0
                and response.status_code in {400, 401}
                and payload.get("error") == "use_dpop_nonce"
                and response.headers.get("DPoP-Nonce")
            ):
                nonce = response.headers["DPoP-Nonce"]
                continue
            if response.status_code in {400, 401, 403}:
                outcome: BrokerOutcome = "client_rejected"
                if (
                    payload.get("error") == "invalid_grant"
                    or payload.get("detail") == "Invalid token"
                ):
                    outcome = "reauth_required"
                raise BrokerGrantError(outcome)
            if not 200 <= response.status_code < 300:
                raise BrokerGrantError("invalid_response")
            if response.status_code != (201 if endpoint == "par" else 200):
                raise BrokerGrantError("invalid_response")
            if require_json and not payload:
                raise BrokerGrantError("invalid_response")
            return payload
        raise BrokerGrantError("client_rejected")
