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
"""Async client for the Harmony Email & Collaboration API (Infinity Portal key)."""

import asyncio
import base64
import json
import logging
import time
import uuid
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any

import httpx

from ._json import error_envelope
from .config import AUTH_GATEWAY, REGION_GATEWAYS, resolve_region

logger = logging.getLogger("avanan_mcp.api")

API_PREFIX = "/app/hec-api"
_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 2
_MAX_BACKOFF_SECONDS = 20.0
_CALL_BUDGET_SECONDS = 100.0

# One connection pool for the process. It never holds credentials: every
# request carries the caller's own bearer token.
_shared_http_client: httpx.AsyncClient | None = None


class _RejectAllCookies(DefaultCookiePolicy):
    """Never store or send a cookie: the HTTP client is shared by every tenant."""

    def set_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False

    def return_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False


def _no_cookies() -> CookieJar:
    # A plain CookieJar: httpx uses it as is (an httpx.Cookies would be copied into a default jar).
    return CookieJar(policy=_RejectAllCookies())


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(cookies=_no_cookies(), timeout=_TIMEOUT)
    return _shared_http_client


_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class HecError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Harmony Email & Collaboration API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class HecCredentials:
    client_id: str
    client_secret: str
    region: str | None = None  # explicit region; otherwise taken from the token

    def __repr__(self) -> str:  # never leak secrets into logs or tracebacks
        return f"HecCredentials(client_id=<redacted>, client_secret=<redacted>, region={self.region!r})"


def token_region(token: str) -> str | None:
    """Region claim of the access token, if any (the token is not verified here)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError):
        return None
    value = claims.get("region") if isinstance(claims, dict) else None
    return resolve_region(value) if isinstance(value, str) else None


class HecClient:
    """API wrapper for one caller's Infinity Portal key.

    The token, region and scope list are resolved lazily and kept only on this
    instance, which lives for a single MCP request; nothing is cached across
    requests.
    """

    def __init__(self, credentials: HecCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self._token: str | None = None
        self._scopes: list[str] | None = None
        self.region: str | None = credentials.region

    @property
    def gateway(self) -> str:
        return REGION_GATEWAYS.get(self.region or "", AUTH_GATEWAY)

    def _client(self) -> httpx.AsyncClient:
        return self._http or _get_shared_http_client()

    async def _access_token(self) -> str:
        if self._token is not None:
            return self._token
        auth_base = REGION_GATEWAYS[self.region] if self.region else AUTH_GATEWAY
        body = {"clientId": self._credentials.client_id, "accessKey": self._credentials.client_secret}
        try:
            resp = await self._client().post(f"{auth_base}/auth/external", json=body, headers={"Accept": "application/json"})
        except httpx.RequestError as e:
            raise HecError(0, f"Network error requesting an access token: {type(e).__name__}") from e
        logger.info("hec_api method=POST path=/auth/external status=%s", resp.status_code)
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        data = payload.get("data") if isinstance(payload, dict) else None
        token = data.get("token") if isinstance(data, dict) else None
        if resp.status_code in (400, 401, 403) or (resp.status_code < 400 and not (payload.get("success") and token)):
            raise HecError(401, "Check Point rejected the client id / secret (token request failed)")
        if resp.status_code >= 400:
            raise HecError(resp.status_code, f"Check Point returned HTTP {resp.status_code} on token request")
        self._token = token
        if self.region is None:
            self.region = token_region(token)
        return token

    def _headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "x-av-req-id": str(uuid.uuid4()), "Accept": "application/json"}

    async def scopes(self) -> list[str]:
        """The farm:tenant scopes of this key; probes other regions if the token's region has none."""
        if self._scopes is not None:
            return self._scopes
        token = await self._access_token()
        scopes = await self._fetch_scopes(self.gateway, token)
        if not scopes and self._credentials.region is None:
            for region, gateway in REGION_GATEWAYS.items():
                if gateway == self.gateway:
                    continue
                found = await self._fetch_scopes(gateway, token)
                if found:
                    self.region, scopes = region, found
                    break
        self._scopes = scopes
        return scopes

    async def _fetch_scopes(self, gateway: str, token: str) -> list[str]:
        try:
            resp = await self._client().get(f"{gateway}{API_PREFIX}/v1.0/scopes", headers=self._headers(token))
        except httpx.RequestError:
            return []
        if resp.status_code >= 400:
            return []
        try:
            data = resp.json().get("responseData") or []
        except (ValueError, AttributeError):
            return []
        return [s for s in data if isinstance(s, str) and ":" in s]

    async def request(self, method: str, path: str, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        """Authenticated request; ``path`` is relative to /app/hec-api, e.g. ``/v1.0/event/query``."""
        token = await self._access_token()
        url = f"{self.gateway}{API_PREFIX}{path}"
        query = {k: v for k, v in (params or {}).items() if v is not None}
        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            resp = None
            error: HecError | None = None
            try:
                resp = await self._client().request(method, url, params=query, json=body, headers=self._headers(token))
                status = resp.status_code
            except httpx.TimeoutException:
                status, error = 0, HecError(0, f"Timed out calling Check Point ({method} {path})")
            except httpx.RequestError as e:
                status = 0
                error = HecError(0, f"Network error calling Check Point ({method} {path}): {type(e).__name__}")

            logger.info(
                "hec_api method=%s path=%s status=%s ms=%d attempt=%d",
                method, path, status, (time.monotonic() - t0) * 1000, attempt,
            )

            if (status == 0 or status in _RETRYABLE_STATUS) and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue

            if error is not None:
                raise error
            assert resp is not None
            payload = _parse_body(resp)
            if resp.status_code >= 400:
                raise HecError(resp.status_code, _error_message(resp.status_code, payload))
            _raise_for_envelope(payload)
            return payload


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _parse_body(resp: httpx.Response) -> Any:
    if not resp.content:
        return None
    try:
        return resp.json()
    except ValueError:
        return {"raw_response": resp.text[:2000]}


def _envelope(payload: Any) -> dict:
    if isinstance(payload, dict) and isinstance(payload.get("responseEnvelope"), dict):
        return payload["responseEnvelope"]
    return {}


def _error_message(status_code: int, payload: Any) -> str:
    fallback = f"Check Point returned HTTP {status_code}"
    env = _envelope(payload)
    text = " ".join(str(env.get(k)) for k in ("responseText", "additionalText") if env.get(k))
    if not text and isinstance(payload, dict):
        text = str(payload.get("message") or payload.get("detail") or "")
    return f"{fallback}: {text[:500]}" if text else fallback


def _raise_for_envelope(payload: Any) -> None:
    """HTTP 200 with a non-zero responseCode is still a failed request."""
    code = _envelope(payload).get("responseCode")
    if code not in (None, 0, "0", 200, "200"):
        env = _envelope(payload)
        text = " ".join(str(env.get(k)) for k in ("responseText", "additionalText") if env.get(k))
        raise HecError(400, f"responseCode {code}: {text[:500]}" if text else f"responseCode {code}")
