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
"""Secured entities (emails, files, messages)."""

from typing import Annotated, Any, Literal
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from ..api_client import HecClient
from ._common import READ_ONLY, ClientFactory, ScrollId, list_result, query_scopes, request_data, run_tool, single_result


class AttributeFilter(BaseModel):
    saasAttrName: str = Field(description="Attribute path, e.g. entityPayload.subject or entityPayload.fromEmail.")
    saasAttrOp: Literal[
        "is", "isNot", "contains", "notContains", "startsWith", "isEmpty", "isNotEmpty", "greaterThan", "lessThan"
    ] = Field(description="Comparison operator.")
    saasAttrValue: Any = Field(default=None, description="Value to compare with (omit for isEmpty / isNotEmpty).")


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def hec_search_emails(
        saas: Annotated[str, Field(description="Protected app, e.g. office365_emails or google_mail.")],
        startDate: Annotated[str, Field(description="Start, ISO 8601, e.g. 2026-01-31T00:00:00.000Z.")],
        endDate: Annotated[str | None, Field(description="End, ISO 8601.")] = None,
        saasEntity: Annotated[str | None, Field(description="Entity type, e.g. office365_emails_email.")] = None,
        filters: Annotated[
            list[AttributeFilter] | None, Field(description="Attribute filters, all must match.")
        ] = None,
        scrollId: ScrollId = None,
    ) -> str:
        """Search secured entities (usually emails) in a time window, filtered by sender, subject, etc.

        Use hec_get_email for one entity's full detail and available actions.
        """

        async def action(client: HecClient) -> dict:
            entity_filter = {
                k: v
                for k, v in {"saas": saas, "saasEntity": saasEntity, "startDate": startDate, "endDate": endDate}.items()
                if v is not None
            }
            body = request_data(
                {
                    "scopes": await query_scopes(client),
                    "entityFilter": entity_filter,
                    "entityExtendedFilter": [f.model_dump(exclude_none=True) for f in filters] if filters else None,
                    "scrollId": scrollId,
                }
            )
            return list_result(await client.request("POST", "/v1.0/search/query", body=body))

        return await run_tool("hec_search_emails", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def hec_get_email(
        entityId: Annotated[str, Field(description="Entity id from hec_search_emails or an event.")],
    ) -> str:
        """Get one secured entity (email): sender, recipients, scan verdicts and available actions."""

        async def action(client: HecClient) -> Any:
            return single_result(await client.request("GET", f"/v1.0/search/entity/{quote(entityId.strip(), safe='')}"))

        return await run_tool("hec_get_email", client_factory, action)
