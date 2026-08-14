# Plan: Connect Bob to the Summarizer via MCP Context Forge Gateway

## Overview

Bob calls the summarizer agent as the MCP tool **`a2a-summarizer`** by connecting to the
MCP Context Forge gateway as a remote MCP server. No new infrastructure is required — the
gateway already auto-bridges every registered A2A agent into an MCP tool.

### What was discovered from live gateway probing (2026-08-14)

| Fact | Value |
|---|---|
| Gateway URL | `GATEWAY_URL` |
| Gateway version | ContextForge 1.0.7, MCP protocol `2025-06-18` |
| MCP streamable-HTTP endpoint | `POST /mcp` (server name: `mcp-streamable-http 1.28.1`) |
| MCP SSE endpoint | `GET /sse` |
| Auth | `Authorization: Bearer <MCPGATEWAY_BEARER_TOKEN>` |
| `tools/list` result | `a2a-summarizer` and `a2a-helloworld-server` already present |
| `a2a-summarizer` input schema | `{ "query": string }` (required) |

**Key finding:** No server registration script is needed. The gateway automatically exposes
every registered A2A agent as an MCP tool at the `/mcp` endpoint. The `a2a-summarizer`
tool is already live and callable.

### Auth boundary

Bob authenticates to the gateway with the `MCPGATEWAY_BEARER_TOKEN` API token (generated
from the admin UI and stored in `secrets.env`). The summarizer agent currently runs with
`summarizer_agent_auth_enabled = false` (default), so no Vault JWT is required at the
Bob or gateway layer for the call to reach the agent.

If `summarizer_agent_auth_enabled` is later set to `true`, the gateway's
`passthroughHeaders: [Authorization]` will forward Bob's bearer token to the agent — at
that point the token would need to be a Vault-issued `summarizer:summarize`-scoped JWT
instead of a gateway API token. That is a separate future task.

---

## Sub-Task 1 — Add MCP Context Forge gateway to Bob's MCP server config

**Intent:** Register the MCP Context Forge gateway as a remote streamable-HTTP MCP server
in `.bob/mcp.json`. Bob will connect to `POST /mcp` using the gateway bearer token. Once
connected, Bob can invoke `a2a-summarizer` as a tool in chat.

**Expected Outcomes:**
- `.bob/mcp.json` has a new `"mcp-context-forge"` entry using `streamable-http` transport.
- Bob shows the gateway as an active MCP server on next reload.
- Bob can list and call `a2a-summarizer` with a `query` string.

**Todo List:**
1. Read the current `.bob/mcp.json`.
2. Add a `"mcp-context-forge"` server entry:
   ```json
   "mcp-context-forge": {
     "type": "streamable-http",
     "url": "GATEWAY_URL/mcp",
     "headers": {
       "Authorization": "Bearer <MCPGATEWAY_BEARER_TOKEN from secrets.env>"
     }
   }
   ```
3. Write the updated `.bob/mcp.json`.
4. Verify Bob loads the server (check MCP server status panel or run a `tools/list` probe).

**Relevant Context:**
- [`.bob/mcp.json`](../.bob/mcp.json) — existing config, currently only the `terraform` server
- `secrets.env` — `MCPGATEWAY_BEARER_TOKEN` is the API token generated from the admin UI
- Gateway MCP endpoint: `POST /mcp`, no session setup needed for streamable-HTTP
- Tool name to test with: `a2a-summarizer`, input: `{"query": "..."}`

**Status:** [x] done

---

## Sub-Task 2 — Update AGENTS.md to document the Bob ↔ gateway MCP connection

**Intent:** Document the `.bob/mcp.json` entry, how to refresh the bearer token when it
expires, and what tool Bob exposes.

**Expected Outcomes:**
- `AGENTS.md` has a "Bob MCP Integration" section that describes:
  - The MCP endpoint (`/mcp`) and transport type
  - Where the bearer token comes from and how to rotate it
  - The tool name (`a2a-summarizer`) and its input schema
  - Note that rotating `MCPGATEWAY_BEARER_TOKEN` requires updating `.bob/mcp.json` manually

**Todo List:**
1. Open `AGENTS.md` and find the MCP Context Forge section.
2. Add a "Bob MCP Integration" subsection after it.
3. Document the above points.

**Relevant Context:**
- [`AGENTS.md`](../AGENTS.md)
- Token rotation: generate a new API token from the MCP Context Forge admin UI
  (`{MCPGATEWAY_URL}` → Settings → API Tokens), paste into `secrets.env` and `.bob/mcp.json`

**Status:** [x] done
