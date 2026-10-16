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
"""Security events."""

from typing import Annotated, Any, Literal
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import HecClient
from ._common import READ_ONLY, ClientFactory, ScrollId, list_result, query_scopes, request_data, run_tool, single_result

EventType = Literal[
    "phishing",
    "malware",
    "suspicious_malware",
    "suspicious_phishing",
    "dlp",
    "anomaly",
    "shadow_it",
    "malicious_url_click",
    "malicious_url",
    "alert",
]
EventState = Literal["new", "detected", "pending", "remediated", "dismissed", "exception"]
Saas = Literal[
    "email",
    "office365_emails",
    "office365_onedrive",
    "office365_sharepoint",
    "slack",
    "ms_teams",
    "google_mail",
    "box2",
    "dropbox2",
    "google_drive",
]
DateTime = Annotated[str | None, Field(description="ISO 8601 date-time, e.g. 2026-01-31T00:00:00.000Z.")]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def hec_query_events(
        eventTypes: Annotated[list[EventType] | None, Field(description="Event types.")] = None,
        eventStates: Annotated[list[EventState] | None, Field(description="Event states.")] = None,
        severities: Annotated[
            list[str] | None, Field(description="Severities, e.g. low, medium, high, critical.")
        ] = None,
        startDate: DateTime = None,
        endDate: DateTime = None,
        saas: Annotated[list[Saas] | None, Field(description="Protected apps.")] = None,
        eventIds: Annotated[list[str] | None, Field(description="Specific event ids.")] = None,
        scrollId: ScrollId = None,
    ) -> str:
        """Search security events by type, state, severity, app and time window.

        Set startDate to keep results focused. Use hec_get_event for one event's full detail.
        """

        async def action(client: HecClient) -> dict:
            body = request_data(
                {
                    "scopes": await query_scopes(client),
                    "eventTypes": eventTypes,
                    "eventStates": eventStates,
                    "severities": severities,
                    "startDate": startDate,
                    "endDate": endDate,
                    "saas": saas,
                    "eventIds": eventIds,
                    "scrollId": scrollId,
                }
            )
            return list_result(await client.request("POST", "/v1.0/event/query", body=body))

        return await run_tool("hec_query_events", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def hec_get_event(
        eventId: Annotated[str, Field(description="Event id from hec_query_events.")],
    ) -> str:
        """Get one security event: type, state, severity, affected entity, actions taken and available."""

        async def action(client: HecClient) -> Any:
            return single_result(await client.request("GET", f"/v1.0/event/{quote(eventId.strip(), safe='')}"))

        return await run_tool("hec_get_event", client_factory, action)
