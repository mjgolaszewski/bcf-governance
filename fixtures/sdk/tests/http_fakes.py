from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class JsonRoute:
    status_code: int
    payload: object
    capture_form: bool = False
    text: str | None = None


@dataclass(frozen=True)
class CapturedRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: str


class MockIdentityHttp:
    def __init__(self) -> None:
        self._routes: dict[str, JsonRoute] = {}
        self.form_bodies: dict[str, list[str]] = {}
        self.requests: list[CapturedRequest] = []

    def add_json(
        self,
        path: str,
        payload: object,
        *,
        status_code: int = 200,
        capture_form: bool = False,
    ) -> None:
        self._routes[path] = JsonRoute(
            status_code=status_code,
            payload=payload,
            capture_form=capture_form,
        )

    def add_text(
        self,
        path: str,
        text: str,
        *,
        status_code: int = 200,
        capture_form: bool = False,
    ) -> None:
        self._routes[path] = JsonRoute(
            status_code=status_code,
            payload=None,
            capture_form=capture_form,
            text=text,
        )

    @asynccontextmanager
    async def client(self) -> AsyncIterator[httpx.AsyncClient]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(self._handle)) as client:
            yield client

    def _handle(self, request: httpx.Request) -> httpx.Response:
        route = self._routes.get(request.url.path)
        if route is None:
            return httpx.Response(404)
        body = request.content.decode("utf-8")
        self.requests.append(
            CapturedRequest(
                method=request.method,
                path=request.url.path,
                headers=dict(request.headers),
                body=body,
            )
        )
        if route.capture_form:
            self.form_bodies.setdefault(request.url.path, []).append(body)
        if route.text is not None:
            return httpx.Response(
                route.status_code,
                text=route.text,
                headers={"content-type": "application/json"},
            )
        return httpx.Response(route.status_code, json=route.payload)
