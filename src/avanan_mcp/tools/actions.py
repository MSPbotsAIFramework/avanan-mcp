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
"""Remediation: quarantine / restore by event or entity, and task status."""

from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..api_client import HecClient
from ._common import DESTRUCTIVE, READ_ONLY, ClientFactory, action_scope, data, request_data, run_tool, single_result

EventIds = Annotated[list[str], Field(description="Event ids.", min_length=1)]
EntityIds = Annotated[list[str], Field(description="Entity ids (emails).", min_length=1)]
EntityType = Annotated[str | None, Field(description="Entity type (default email).")]
Scope = Annotated[
    str | None,
    Field(description="Multi-tenant keys only: the farm:tenant scope the ids belong to."),
]
RESTORES = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    async def _event_action(client: HecClient, name: str, event_ids: list[str], scope: str | None) -> dict:
        body = request_data({"scope": await action_scope(client, scope), "eventIds": event_ids, "eventActionName": name})
        result = await client.request("POST", "/v1.0/action/event", body=body)
        return {"action": name, "requested": len(event_ids), "tasks": data(result)}

    async def _entity_action(
        client: HecClient, name: str, entity_ids: list[str], entity_type: str | None, scope: str | None
    ) -> dict:
        body = request_data(
            {
                "scope": await action_scope(client, scope),
                "entityIds": entity_ids,
                "entityType": entity_type or "email",
                "entityActionName": name,
            }
        )
        result = await client.request("POST", "/v1.0/action/entity", body=body)
        return {"action": name, "requested": len(entity_ids), "tasks": data(result)}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def hec_quarantine_events(eventIds: EventIds, scope: Scope = None) -> str:
        """Quarantine the emails behind security events; returns task ids.

        Reversible with hec_restore_events. High impact: only when the user explicitly asks.
        """

        async def action(client: HecClient) -> dict:
            return await _event_action(client, "quarantine", eventIds, scope)

        return await run_tool("hec_quarantine_events", client_factory, action)

    @mcp.tool(annotations=RESTORES)
    async def hec_restore_events(eventIds: EventIds, scope: Scope = None) -> str:
        """Restore emails previously quarantined for security events; returns task ids.

        Only when the user explicitly asks.
        """

        async def action(client: HecClient) -> dict:
            return await _event_action(client, "restore", eventIds, scope)

        return await run_tool("hec_restore_events", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def hec_quarantine_emails(entityIds: EntityIds, entityType: EntityType = None, scope: Scope = None) -> str:
        """Quarantine specific emails by entity id; returns task ids.

        Reversible with hec_restore_emails. High impact: only when the user explicitly asks.
        """

        async def action(client: HecClient) -> dict:
            return await _entity_action(client, "quarantine", entityIds, entityType, scope)

        return await run_tool("hec_quarantine_emails", client_factory, action)

    @mcp.tool(annotations=RESTORES)
    async def hec_restore_emails(entityIds: EntityIds, entityType: EntityType = None, scope: Scope = None) -> str:
        """Restore quarantined emails by entity id; returns task ids. Only when the user explicitly asks."""

        async def action(client: HecClient) -> dict:
            return await _entity_action(client, "restore", entityIds, entityType, scope)

        return await run_tool("hec_restore_emails", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def hec_get_task_status(
        taskId: Annotated[str, Field(description="Task id returned by a quarantine / restore tool.")],
        scope: Scope = None,
    ) -> str:
        """Check whether a quarantine or restore task is pending, running, done or failed."""

        async def action(client: HecClient) -> Any:
            path = f"/v1.0/task/{quote(taskId.strip(), safe='')}"
            return single_result(await client.request("GET", path, params={"scope": scope}))

        return await run_tool("hec_get_task_status", client_factory, action)
