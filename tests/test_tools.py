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
"""tools/list snapshot and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from avanan_mcp.api_client import HecError
from avanan_mcp.server import INSTRUCTIONS, create_mcp_server

# Tool names are a public contract: existing agents and tenant connections
# depend on them. Changing this snapshot is a breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "hec_query_events": set(),
    "hec_get_event": {"eventId"},
    "hec_search_emails": {"saas", "startDate"},
    "hec_get_email": {"entityId"},
    "hec_quarantine_events": {"eventIds"},
    "hec_restore_events": {"eventIds"},
    "hec_quarantine_emails": {"entityIds"},
    "hec_restore_emails": {"entityIds"},
    "hec_get_task_status": {"taskId"},
    "hec_list_exceptions": {"excType"},
    "hec_add_exception": {"excType"},
    "hec_update_exception": {"excType", "excId"},
    "hec_delete_exception": {"excType", "excId"},
}

DESTRUCTIVE_TOOLS = {"hec_quarantine_events", "hec_quarantine_emails", "hec_delete_exception"}
WRITE_TOOLS = DESTRUCTIVE_TOOLS | {
    "hec_restore_events",
    "hec_restore_emails",
    "hec_add_exception",
    "hec_update_exception",
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_snapshot(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100
    assert "API:" not in description


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_every_param_is_documented(tools, name):
    for param, schema in tools[name].inputSchema.get("properties", {}).items():
        assert schema.get("description") or "enum" in json.dumps(schema), f"{name}.{param}"


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_annotations(tools, name):
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is (name not in WRITE_TOOLS)
    assert bool(annotations.destructiveHint) is (name in DESTRUCTIVE_TOOLS)
    if name in WRITE_TOOLS:
        assert "explicitly ask" in tools[name].description


def test_instructions_present_and_bounded():
    assert INSTRUCTIONS and len(INSTRUCTIONS) <= 1500
    for name in ("hec_query_events", "hec_search_emails", "hec_get_task_status"):
        assert name in INSTRUCTIONS


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (0, "upstream_error", True),
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_error_envelope_mapping(status_code, expected_code, expected_retryable):
    envelope = json.loads(HecError(status_code, "boom").to_envelope())
    assert envelope == {
        "error": {"code": expected_code, "message": "boom", "retryable": expected_retryable}
    }
