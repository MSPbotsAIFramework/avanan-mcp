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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import HecClient, HecCredentials
from .config import REGION_GATEWAYS, Settings, resolve_region

HEADER_CLIENT_ID = "X-Checkpoint-Client-Id"
HEADER_CLIENT_SECRET = "X-Checkpoint-Client-Secret"
HEADER_REGION = "X-Checkpoint-Region"
REQUIRED_HEADERS = [HEADER_CLIENT_ID, HEADER_CLIENT_SECRET]
OPTIONAL_HEADERS = [HEADER_REGION]

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[HecCredentials | None] = contextvars.ContextVar(
    "hec_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("hec_request_id", default="-")

INSTRUCTIONS = (
    "Check Point Harmony Email & Collaboration (formerly Avanan) protects "
    "Microsoft 365, Google Workspace and collaboration apps (Teams, Slack, "
    "OneDrive, SharePoint, Box, Dropbox) against phishing, malware and data "
    "leaks. Security events are detections; secured entities are the scanned "
    "items themselves (mostly emails); exceptions are allow (whitelist) and "
    "block (blacklist) rules.\n"
    "Typical flows:\n"
    "- Triage: hec_query_events(startDate, eventTypes, eventStates) -> "
    "hec_get_event.\n"
    "- Find mail: hec_search_emails(saas='office365_emails', startDate, filters) "
    "-> hec_get_email.\n"
    "- Remediate: hec_quarantine_events or hec_quarantine_emails, then "
    "hec_get_task_status(taskId); hec_restore_* undoes it.\n"
    "- Tuning: hec_list_exceptions -> hec_add_exception / hec_update_exception.\n"
    "Lists return {items, total, has_more, scroll_id}; pass scroll_id as "
    "scrollId. Quarantine, restore and exception changes affect users' "
    "mailboxes and filtering: use them only when the user explicitly asks."
)


def get_client_from_context() -> HecClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return HecClient(credentials)


class GatewayCredentialsMiddleware:
    """Reads X-Checkpoint-* headers on /mcp requests into the request context.

    Missing required headers -> 401 listing them; unknown region -> 400.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        client_id = (request.headers.get(HEADER_CLIENT_ID) or "").strip()
        client_secret = (request.headers.get(HEADER_CLIENT_SECRET) or "").strip()
        region_header = (request.headers.get(HEADER_REGION) or "").strip()
        region = resolve_region(region_header)

        missing = [h for h, v in ((HEADER_CLIENT_ID, client_id), (HEADER_CLIENT_SECRET, client_secret)) if not v]
        if missing:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": "Required header(s) missing: " + ", ".join(missing),
                    "required_headers": REQUIRED_HEADERS,
                    "optional_headers": OPTIONAL_HEADERS,
                },
                status_code=401,
            )(scope, receive, send)
            return

        if region_header and region is None:
            await JSONResponse(
                {
                    "error": "Invalid region",
                    "message": f"{HEADER_REGION} must be one of: {', '.join(REGION_GATEWAYS)}",
                    "allowed_values": list(REGION_GATEWAYS),
                },
                status_code=400,
            )(scope, receive, send)
            return

        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(HecCredentials(client_id, client_secret, region))
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = FastMCP(
        name="avanan-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], HecClient | None] = get_client_from_context

    from .tools import actions, events, exceptions, search

    for module in (events, search, actions, exceptions):
        module.register(mcp, client_factory)

    return mcp
