# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Credential middleware: 401 on missing headers, optional region, isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from avanan_mcp.__main__ import build_http_app
from avanan_mcp.server import (
    GatewayCredentialsMiddleware,
    _credentials_var,
    create_mcp_server,
    get_client_from_context,
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
CREDS = {"X-Checkpoint-Client-Id": "your-client-id", "X-Checkpoint-Client-Secret": "your-client-secret"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize("drop", list(CREDS))
def test_missing_header_returns_401(drop):
    headers = MCP_HEADERS | {k: v for k, v in CREDS.items() if k != drop}
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["required_headers"] == list(CREDS)


def test_unknown_region_returns_400():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS | {"X-Checkpoint-Region": "mars"})
    assert resp.status_code == 400
    assert "uk" in resp.json()["allowed_values"]


def test_tools_list_over_http():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS)
    assert resp.status_code == 200
    assert "hec_query_events" in resp.text


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


BASE = [(b"x-checkpoint-client-id", b"cid"), (b"x-checkpoint-client-secret", b"sec")]


@pytest.mark.parametrize(
    "value,region,gateway",
    [
        (None, None, "https://cloudinfra-gw.portal.checkpoint.com"),
        (b"US", "us", "https://cloudinfra-gw-us.portal.checkpoint.com"),
        (b"ap", "au", "https://cloudinfra-gw.ap.portal.checkpoint.com"),
        (b"uk", "uk", "https://cloudinfra-gw.uk.portal.checkpoint.com"),
    ],
)
def test_region_header(value, region, gateway):
    headers = BASE + ([(b"x-checkpoint-region", value)] if value is not None else [])
    seen = _run_middleware(headers)
    assert seen["credentials"].region == region
    assert seen["client"].gateway == gateway
    assert _credentials_var.get() is None


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().client_id
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().client_id))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(cid: bytes) -> dict:
        return {"type": "http", "path": "/mcp", "headers": [(b"x-checkpoint-client-id", cid), (b"x-checkpoint-client-secret", b"s")]}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), receive, send), middleware(scope(b"tenant-b"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_secrets():
    seen = _run_middleware([(b"x-checkpoint-client-id", b"secret-app"), (b"x-checkpoint-client-secret", b"secret-value")])
    text = repr(seen["credentials"])
    assert "secret-app" not in text and "secret-value" not in text
