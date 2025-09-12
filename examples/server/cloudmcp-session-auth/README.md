# CloudMCP Session‑Auth MCP Proxy Server

A streamable‑HTTP MCP server protected by CloudMCP session OAuth (Bearer) that can dynamically aggregate and proxy features (tools, prompts, and resources) from other MCP servers. It acts as a gateway: you connect UI/agents to this single server, and it federates capabilities from multiple downstream servers you add at runtime.

This example is ready to be split out into its own repo with a minimal management API; it intentionally omits build/deploy instructions here.

## What It Does

- Exposes an MCP endpoint at `/mcp`, protected by OAuth using CloudMCP session verification.
- Lets you dynamically add downstream MCP servers (stdio transport) and surfaces their:
  - Tools (with call forwarding)
  - Prompts (with get forwarding)
  - Resources (with read forwarding), plus a catch‑all proxy URI template
- Namespaces downstream items using a prefix (default: `<sanitized-name>-`) to avoid collisions.
- Mirrors client roots to downstream servers so file resources behave correctly through the proxy.
- Provides a simple management API to add/remove/update servers and control which tools are enabled per server.

## How It Works

- Authentication:
  - The `/mcp` endpoint is wrapped with a Bearer‑token middleware that verifies CloudMCP sessions via `GET https://cloudmcp.run/api/auth/mcp/get-session` (configurable). It also serves protected resource metadata under `/.well-known/oauth-protected-resource/mcp`.
- Proxying downstream servers:
  - When you POST `/add-server`, the server starts an MCP client over stdio (`CommandTransport`) to the given command and connects.
  - It lists tools, prompts, and resources from the downstream server and registers proxied counterparts on the primary server:
    - Tools: registered under `<prefix><toolName>`, forwarded using `CallTool` to the downstream.
    - Prompts: registered under `<prefix><promptName>`, forwarded using `GetPrompt` to the downstream.
    - Resources: registered using proxied URIs: `proxy://<sanitized-server-name>/<percent-encoded-remote-URI>`. A catch‑all resource template `proxy://<sanitized-server-name>/{orig}` allows ad‑hoc reads of any downstream URI.
  - Tool/prompt list changes from downstream are tracked and reconciled automatically.
- Roots propagation:
  - When a UI client updates roots, the proxy introspects them and mirrors to each downstream client (`AddRoots`/`RemoveRoots`), enabling downstream file resource handlers to honor UI roots.

## Management API

All endpoints below are protected by the same Bearer middleware as `/mcp`.

- POST `/add-server`
  - Body:
    - `name` (string, required): namespace for proxied items.
    - `command` (string, required): program/script to exec (stdio MCP server).
    - `args` (string[], optional)
    - `env` (object<string,string>, optional)
    - `dir` (string, optional)
    - `include` (string[], optional): enable only these remote tool names; otherwise all tools enabled by default.
    - `exclude` (string[], optional): deny‑list for tools when `include` is not set.
    - `prefix` (string, optional): namespace prefix, default `<sanitized-name>-`.
  - Behavior:
    - Validates that proxied tool and prompt names won’t collide with existing server entries.
    - Syncs tools, prompts, and resources; installs the catch‑all resource template; mirrors current UI roots to the new downstream.

- POST `/remove-server`
  - Body: `{ "name": string }`
  - Removes all proxied tools/prompts/resources for the server and closes the downstream session.

- POST `/update-server`
  - Body (any of the following):
    - `name` (string, required)
    - `prefix` (string, optional)
    - `include` (string[], optional)
    - `exclude` (string[], optional)
    - `command` (string, optional)
    - `args` (string[], optional)
    - `env` (object<string,string>, optional)
    - `dir` (string, optional)
  - Behavior:
    - Validates name collisions for tools and prompts under the new prefix.
    - If `command/args/env/dir` change, a new stdio client is started, proxied items are added, then old ones are removed, and the old session is closed (graceful restart).
    - If only `prefix` changes, new prefixed items are added first, then old prefixed items removed (minimizing downtime).
    - Filter changes (`include`/`exclude`) affect only tools and trigger a resync.

- POST `/set-enabled-tools`
  - Body: `{ "name": string, "enabled": string[] }` where entries are the proxied (prefixed) tool names for this server (e.g., `"playwright-browse"`).
  - Semantics:
    - Validates each name starts with the server’s current prefix and maps them back to remote tool names internally.
    - If `enabled` covers all remote tools (by count), clears filters (all enabled by default).
    - Otherwise creates an include‑set for exactly those remote tools and clears exclude.
    - Validates collisions for the provided proxied names under the current prefix.

- GET `/servers`
  - Returns a list of all connected servers with complete discovery info for UI controls:
    - `name`, `command`, `args`, `dir`, `toolPrefix`
    - `tools`: current proxied tool names (namespaced)
    - `remoteTools[]`:
      - `name`, `description`, `enabled` (boolean), `proxiedName` (if enabled)
    - `prompts[]`:
      - `name`, `description`, `proxiedName`
      - `arguments[]`: `{ name, title, description, required }`
    - `resources[]`:
      - `name` (optional), `uri` (remote), `proxiedUri` (proxy scheme), `description`, `mimeType`
    - `resourceTemplates[]`:
      - `uriTemplate`, `description`, `mimeType`

## Namespacing & Collisions

- Tools and prompts are registered under a configurable prefix (default `<sanitized-name>-`).
- Adds/updates validate that prospective proxied names don’t conflict with existing server entries. For updates, the proxy’s current names are excluded from conflict checks so replacements are allowed.

### Sanitization Rules

- To comply with MCP naming constraints, the proxy normalizes identifiers:
  - Allowed characters for tool and prompt names are `[a-z0-9_-]`.
  - The `name` you supply for a downstream server is sanitized to this set and lowercased; this sanitized value becomes the default `prefix` base and the host in `proxy://<sanitized-server-name>/...` URIs.
  - A user-supplied `prefix` is sanitized to the same set and forced to end with `-`.
  - Any disallowed character becomes `-`, repeated separators are collapsed, and leading/trailing separators are trimmed.
  - If two different `name` values sanitize to the same identifier, set an explicit `prefix` for at least one server to avoid collisions.

## Call Forwarding & Resource Proxying

- Tools: incoming `tools/call` are forwarded to the downstream with the original tool name and arguments; responses are relayed back as‑is.
- Prompts: incoming `prompts/get` are forwarded similarly.
- Resources:
  - UI/agents can read remote resources by using `proxiedUri` values or constructing `proxy://<sanitized-server-name>/<percent-encoded-remote-URI>`.
  - The proxy decodes the proxied URI, calls the downstream `resources/read`, and returns the result.

## Roots Synchronization

- UI clients remain the source of truth for roots.
- On `roots/list_changed`, the proxy fetches the current client roots and mirrors them to all downstream clients via `AddRoots`/`RemoveRoots` so downstream file reads honor the same constraints.

## Notes & Limitations

- Transport: downstream connections use stdio only (CommandTransport). HTTP transports are intentionally not supported here.
- Filters: tool toggles (include/exclude) are supported; prompts and resources are always proxied.
- Subscriptions: resource subscription forwarding is not implemented in this example.
- Schemas: downstream tools must expose a non‑nil input schema; such tools are skipped otherwise to satisfy server constraints.
