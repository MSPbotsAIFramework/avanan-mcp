# Check Point Avanan MCP Server

An [MCP](https://modelcontextprotocol.io) server for the **Check Point Harmony Email &
Collaboration** API (formerly Avanan), reached through the Check Point Infinity Portal. It lets
an AI agent triage security events, search scanned emails and files, quarantine or restore
them, and manage allow / block exception rules.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored; the access token, region and scopes are resolved per request and not cached
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

For the older SmartAPI (`smart-api-production-*.avanan.net`, MSP tenant management), use the
separate Avanan (legacy) server.

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Checkpoint-Client-Id` | Yes | string | none | - | Infinity Portal API key client id | `your-client-id` |
| `X-Checkpoint-Client-Secret` | Yes | string | none | - | Secret paired with the client id | `your-client-secret` |
| `X-Checkpoint-Region` | No | string | detected | `eu`, `us`, `ca`, `au` (`ap`), `uk`, `uae` (`me`), `in` | Data region of the account | `us` |

Where to get them:

- **Client id / secret**: in the Check Point Infinity Portal create an API key for the
  **Email & Collaboration** service (Global Settings -> API Keys). See the Check Point Portal
  Administration Guide.
- **Region**: keys are regional. Without `X-Checkpoint-Region` the server exchanges the key for
  a token at the EU gateway, uses the region carried in the token, and if that region returns
  no scopes it tries the other regional gateways.

A request to `/mcp` without the required headers gets HTTP 401 listing them. An unknown region
does not block `tools/list`; tools then return an `invalid_argument` error naming the allowed
regions.

## Tools

All tools return a JSON string. List tools return `{items, count, total, has_more, scroll_id}`;
pass `scroll_id` back as `scrollId` for the next page. With a key that covers several tenants,
queries run across all of them and action tools need a `scope` (`farm:tenant`).

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `hec_query_events` | Search security events | eventTypes, eventStates, severities, startDate, endDate, saas, eventIds, scrollId |
| `hec_get_event` | One event | **eventId** |
| `hec_search_emails` | Search secured entities (emails, files) | **saas**, **startDate**, endDate, saasEntity, filters (`[{saasAttrName, saasAttrOp, saasAttrValue}]`), scrollId |
| `hec_get_email` | One entity | **entityId** |
| `hec_quarantine_events` | Quarantine the emails behind events (**destructive**, reversible) | **eventIds**, scope |
| `hec_restore_events` | Restore them (**write**) | **eventIds**, scope |
| `hec_quarantine_emails` | Quarantine emails by entity id (**destructive**, reversible) | **entityIds**, entityType, scope |
| `hec_restore_emails` | Restore emails (**write**) | **entityIds**, entityType, scope |
| `hec_get_task_status` | Progress of a quarantine / restore task | **taskId**, scope |
| `hec_list_exceptions` | Allow / block rules | **excType** (`whitelist`, `blacklist`) |
| `hec_add_exception` | Add a rule (**write**) | **excType**, senderEmail, senderDomain, senderName, recipient, subject, attachmentMd5, comment, senderEmailMatching, senderDomainMatching, subjectMatching |
| `hec_update_exception` | Update a rule (**write**) | **excType**, **excId**, same fields |
| `hec_delete_exception` | Delete a rule (**destructive**) | **excType**, **excId** |

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "Check Point rejected the client id / secret (token request failed)", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`.

## Run locally

```bash
uv sync
uv run python -m avanan_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t avanan-mcp:dev .
docker run --rm -p 8080:8080 avanan-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). Credentials are never read from
the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Checkpoint-Client-Id: your-client-id" \
  -H "X-Checkpoint-Client-Secret: your-client-secret" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# phishing events since a date
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Checkpoint-Client-Id: your-client-id" \
  -H "X-Checkpoint-Client-Secret: your-client-secret" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hec_query_events","arguments":{"eventTypes":["phishing"],"startDate":"2026-01-01T00:00:00.000Z"}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool names** keep their existing `hec_` prefix because they are an existing contract.
- **Write tools.** Quarantine, restore and exception changes affect users' mailboxes and mail
  filtering. They are annotated (`readOnlyHint=false`; quarantine and delete also
  `destructiveHint=true`) and their descriptions tell the agent to act only on an explicit
  request. `hec_list_exceptions` is read-only.
- **Optional additions.** `X-Checkpoint-Region` and the `scope` argument on action tools are
  optional and do not change behaviour for existing connections.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
