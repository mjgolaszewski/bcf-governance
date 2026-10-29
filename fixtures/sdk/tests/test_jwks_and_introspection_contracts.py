from __future__ import annotations

import base64
from urllib.parse import parse_qs

import pytest

from chrysalis_identity_client.introspection import IntrospectionClient
from chrysalis_identity_client.jwks import JWKSClient
from http_fakes import MockIdentityHttp


@pytest.mark.anyio
async def test_jwks_client_caches_until_clear_cache() -> None:
    key_set = {"keys": [{"kty": "RSA", "kid": "test-key"}]}
    server = MockIdentityHttp()
    server.add_json("/jwks.json", key_set)

    async with server.client() as client:
        jwks_client = JWKSClient(
            "https://identity.example/jwks.json",
            http_client=client,
            ttl_seconds=300,
        )

        assert await jwks_client.get_key_set() == key_set
        assert await jwks_client.get_key_set() == key_set
        assert [request.path for request in server.requests].count("/jwks.json") == 1

        jwks_client.clear_cache()
        assert await jwks_client.get_key_set() == key_set
        assert [request.path for request in server.requests].count("/jwks.json") == 2


@pytest.mark.anyio
async def test_introspection_sends_basic_auth_accept_header_and_audience() -> None:
    server = MockIdentityHttp()
    server.add_json("/introspect", {"active": True, "sub": "principal:123"}, capture_form=True)

    async with server.client() as client:
        introspection_client = IntrospectionClient(
            endpoint="https://identity.example/introspect",
            client_id="bdmcp-http",
            client_secret="secret",
            http_client=client,
        )
        result = await introspection_client.introspect("opaque-token", audience="bdmcp")

    assert result is not None
    assert result.active is True
    request = server.requests[-1]
    assert request.method == "POST"
    assert request.path == "/introspect"
    assert request.headers["accept"] == "application/json"
    assert base64.b64decode(request.headers["authorization"].removeprefix("Basic ")).decode(
        "utf-8"
    ) == "bdmcp-http:secret"
    assert parse_qs(request.body) == {
        "token": ["opaque-token"],
        "audience": ["bdmcp"],
    }


@pytest.mark.anyio
async def test_introspection_invalid_json_fails_closed() -> None:
    server = MockIdentityHttp()
    server.add_text("/introspect", "not-json")

    async with server.client() as client:
        introspection_client = IntrospectionClient(
            endpoint="https://identity.example/introspect",
            client_id="bdmcp-http",
            client_secret="secret",
            http_client=client,
        )

        assert await introspection_client.introspect("opaque-token") is None
