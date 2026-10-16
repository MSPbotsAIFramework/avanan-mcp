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
"""Shared argument types, result shaping and the error-handling wrapper."""

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import HecClient, HecError

logger = logging.getLogger("avanan_mcp.tools")

ClientFactory = Callable[[], HecClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
WRITES = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured",
    "Check Point credentials are missing for this request (X-Checkpoint-Client-Id / X-Checkpoint-Client-Secret).",
    False,
)

ScrollId = Annotated[str | None, Field(description="scroll_id from a previous response, for the next page.")]


async def query_scopes(client: HecClient) -> list[str] | None:
    """Scopes to put on a query: all of them for a multi-tenant key, none otherwise."""
    scopes = await client.scopes()
    return scopes if len(scopes) > 1 else None


async def action_scope(client: HecClient, scope: str | None) -> str | None:
    """The single scope an action must name when the key covers several tenants."""
    if scope:
        return scope
    scopes = await client.scopes()
    if len(scopes) > 1:
        raise ValueError("This key covers several tenants; pass scope (one of: " + ", ".join(scopes[:20]) + ")")
    return None


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


def request_data(values: dict[str, Any]) -> dict[str, Any]:
    return {"requestData": compact(values)}


def data(payload: Any) -> Any:
    return payload.get("responseData") if isinstance(payload, dict) and "responseData" in payload else payload


def list_result(payload: Any) -> dict[str, Any]:
    """Shape ``{responseEnvelope, responseData}`` as ``{items, count, total, has_more, scroll_id}``."""
    items = data(payload)
    if items is None:
        items = []
    elif not isinstance(items, list):
        items = [items]
    env = payload.get("responseEnvelope", {}) if isinstance(payload, dict) else {}
    total = env.get("totalRecordsNumber")
    scroll = env.get("scrollId") or None
    has_more = bool(scroll) and (total is None or (isinstance(total, int) and total > len(items)))
    return {
        "items": items,
        "count": len(items),
        "total": total,
        "has_more": has_more,
        "scroll_id": scroll if has_more else None,
    }


def single_result(payload: Any) -> Any:
    """Single-object responses usually wrap the object in a one-element array."""
    value = data(payload)
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[HecClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        result = await action(client)
    except HecError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
