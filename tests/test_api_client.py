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
"""Token flow, region detection, scopes and tool routing against a mocked API."""

import base64
import json

import httpx
import pytest

from avanan_mcp import api_client
from avanan_mcp.api_client import HecClient, HecCredentials, token_region
from avanan_mcp.server import _credentials_var, create_mcp_server

EU = "cloudinfra-gw.portal.checkpoint.com"
US = "cloudinfra-gw-us.portal.checkpoint.com"


def jwt(claims: dict) -> str:
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'none'})}.{seg(claims)}.sig"


def envelope(data, total=None, scroll=None):
    env = {"requestId": "r", "responseCode": 0, "responseText": "Success"}
    if total is not None:
        env["totalRecordsNumber"] = total
    if scroll is not None:
        env["scrollId"] = scroll
    return {"responseEnvelope": env, "responseData": data}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


class FakeApi:
    def __init__(self, reply=None, token_claims=None, auth_ok=True, scopes_by_host=None):
        self.requests: list[httpx.Request] = []
        self.reply = reply or (lambda r: httpx.Response(200, json=envelope([])))
        self.token = jwt(token_claims or {"region": "us"})
        self.auth_ok = auth_ok
        self.scopes_by_host = scopes_by_host or {US: ["farm-us:acme"]}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/auth/external":
            if not self.auth_ok:
                return httpx.Response(401, json={"success": False, "message": "Authentication required"})
            return httpx.Response(200, json={"success": True, "data": {"token": self.token, "expiresIn": 1800}})
        if request.url.path.endswith("/v1.0/scopes"):
            return httpx.Response(200, json=envelope(self.scopes_by_host.get(request.url.host, [])))
        return self.reply(request)

    def api(self) -> list[httpx.Request]:
        return [r for r in self.requests if not r.url.path.endswith(("/auth/external", "/v1.0/scopes"))]


async def _call(monkeypatch, fake: FakeApi, tool: str, args: dict, region: str | None = None):
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    mcp = create_mcp_server()
    ctx = _credentials_var.set(HecCredentials("cid-1", "secret-1", region))
    try:
        content, _ = await mcp.call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


def test_token_region_claim():
    assert token_region(jwt({"region": "us"})) == "us"
    assert token_region(jwt({"region": "ap"})) == "au"
    assert token_region(jwt({})) is None
    assert token_region("not-a-jwt") is None


async def test_auth_body_and_region_from_token(monkeypatch):
    fake = FakeApi(lambda r: httpx.Response(200, json=envelope({"eventId": "e1"})))
    result = await _call(monkeypatch, fake, "hec_get_event", {"eventId": "e1"})
    auth, req = fake.requests
    assert str(auth.url) == f"https://{EU}/auth/external"
    assert json.loads(auth.content) == {"clientId": "cid-1", "accessKey": "secret-1"}
    assert str(req.url) == f"https://{US}/app/hec-api/v1.0/event/e1"
    assert req.headers["authorization"] == f"Bearer {fake.token}"
    assert req.headers["x-av-req-id"]
    assert "secret-1" not in str(req.headers)
    assert result == {"eventId": "e1"}


async def test_explicit_region_authenticates_there(monkeypatch):
    fake = FakeApi(token_claims={"region": "eu"})
    await _call(monkeypatch, fake, "hec_list_exceptions", {"excType": "whitelist"}, region="uk")
    hosts = {r.url.host for r in fake.requests}
    assert hosts == {"cloudinfra-gw.uk.portal.checkpoint.com"}


async def test_bad_credentials_map_to_unauthorized(monkeypatch):
    result = await _call(monkeypatch, FakeApi(auth_ok=False), "hec_get_event", {"eventId": "e1"})
    assert result["error"]["code"] == "unauthorized"
    assert "secret-1" not in json.dumps(result)


async def test_single_scope_key_sends_no_scopes(monkeypatch):
    fake = FakeApi()
    await _call(monkeypatch, fake, "hec_query_events", {"eventTypes": ["phishing"], "startDate": "2026-10-01T00:00:00.000Z"})
    body = json.loads(fake.api()[0].content)["requestData"]
    assert "scopes" not in body and body["eventTypes"] == ["phishing"]


async def test_multi_scope_key_queries_all_scopes(monkeypatch):
    fake = FakeApi(scopes_by_host={US: ["farm:a", "farm:b"]})
    await _call(monkeypatch, fake, "hec_search_emails", {"saas": "office365_emails", "startDate": "2026-10-01T00:00:00.000Z"})
    body = json.loads(fake.api()[0].content)["requestData"]
    assert body["scopes"] == ["farm:a", "farm:b"]
    assert body["entityFilter"] == {"saas": "office365_emails", "startDate": "2026-10-01T00:00:00.000Z"}


async def test_scopes_probe_other_regions_when_token_region_is_empty(monkeypatch):
    fake = FakeApi(token_claims={}, scopes_by_host={US: ["farm-us:acme"]})
    await _call(monkeypatch, fake, "hec_query_events", {})
    assert fake.api()[0].url.host == US


async def test_multi_scope_action_requires_scope(monkeypatch):
    fake = FakeApi(scopes_by_host={US: ["farm:a", "farm:b"]})
    result = await _call(monkeypatch, fake, "hec_quarantine_events", {"eventIds": ["e1"]})
    assert result["error"]["code"] == "invalid_argument"
    assert "farm:a" in result["error"]["message"]
    assert fake.api() == []


@pytest.mark.parametrize(
    "tool,args,path,expected",
    [
        ("hec_quarantine_events", {"eventIds": ["e1"]}, "/app/hec-api/v1.0/action/event",
         {"eventIds": ["e1"], "eventActionName": "quarantine"}),
        ("hec_restore_events", {"eventIds": ["e1"], "scope": "farm:a"}, "/app/hec-api/v1.0/action/event",
         {"scope": "farm:a", "eventIds": ["e1"], "eventActionName": "restore"}),
        ("hec_quarantine_emails", {"entityIds": ["x1"]}, "/app/hec-api/v1.0/action/entity",
         {"entityIds": ["x1"], "entityType": "email", "entityActionName": "quarantine"}),
        ("hec_add_exception", {"excType": "blacklist", "senderDomain": "example.com"}, "/app/hec-api/v1.0/exceptions/blacklist",
         {"senderDomain": "example.com", "senderDomainMatching": "endswith"}),
    ],
)
async def test_write_bodies(monkeypatch, tool, args, path, expected):
    fake = FakeApi(lambda r: httpx.Response(200, json=envelope([{"taskId": "t1"}])))
    await _call(monkeypatch, fake, tool, args)
    req = fake.api()[0]
    assert (req.method, req.url.path) == ("POST", path)
    assert json.loads(req.content) == {"requestData": expected}


@pytest.mark.parametrize(
    "tool,args,method,path",
    [
        ("hec_get_email", {"entityId": "ent"}, "GET", "/app/hec-api/v1.0/search/entity/ent"),
        ("hec_get_task_status", {"taskId": "77"}, "GET", "/app/hec-api/v1.0/task/77"),
        ("hec_list_exceptions", {"excType": "whitelist"}, "GET", "/app/hec-api/v1.0/exceptions/whitelist"),
        ("hec_update_exception", {"excType": "whitelist", "excId": "9", "comment": "vendor"}, "PUT",
         "/app/hec-api/v1.0/exceptions/whitelist/9"),
        ("hec_delete_exception", {"excType": "whitelist", "excId": "9"}, "POST",
         "/app/hec-api/v1.0/exceptions/whitelist/delete/9"),
    ],
)
async def test_routing(monkeypatch, tool, args, method, path):
    fake = FakeApi()
    result = await _call(monkeypatch, fake, tool, args)
    req = fake.api()[0]
    assert (req.method, req.url.path) == (method, path)
    assert "error" not in result


async def test_scroll_pagination(monkeypatch):
    page = envelope([{"eventId": "e1"}], total=3, scroll="s2")
    result = await _call(monkeypatch, FakeApi(lambda r: httpx.Response(200, json=page)), "hec_query_events", {"scrollId": "s1"})
    assert result["has_more"] is True and result["scroll_id"] == "s2"


async def test_non_zero_response_code_is_an_error(monkeypatch):
    bad = {"responseEnvelope": {"responseCode": 3, "responseText": "Bad scope"}, "responseData": []}
    result = await _call(monkeypatch, FakeApi(lambda r: httpx.Response(200, json=bad)), "hec_get_event", {"eventId": "e"})
    assert result["error"]["code"] == "invalid_argument" and "Bad scope" in result["error"]["message"]


def test_token_is_per_client_instance():
    a = HecClient(HecCredentials("a", "s"))
    b = HecClient(HecCredentials("a", "s"))
    a._token = "only-a"
    assert b._token is None
