from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class IntrospectionResult:
    active: bool
    payload: dict[str, Any]


class IntrospectionClient:
    def __init__(
        self,
        *,
        endpoint: str,
        client_id: str,
        client_secret: str,
        timeout_seconds: float = 5.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout_seconds = timeout_seconds
        self._http_client = http_client

    async def introspect(self, token: str, *, audience: str | None = None) -> IntrospectionResult | None:
        form_data = {"token": token}
        if audience:
            form_data["audience"] = audience
        try:
            if self._http_client is None:
                async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                    response = await client.post(
                        self._endpoint,
                        data=form_data,
                        auth=(self._client_id, self._client_secret),
                        headers={"Accept": "application/json"},
                    )
            else:
                response = await self._http_client.post(
                    self._endpoint,
                    data=form_data,
                    auth=(self._client_id, self._client_secret),
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError:
            return None
        if response.status_code >= 400:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        return IntrospectionResult(active=payload.get("active") is True, payload=payload)
