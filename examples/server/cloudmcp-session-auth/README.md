# CloudMCP Session Auth (MCP Server Example)

This example shows how to protect an MCP server using a custom OAuth verifier
that calls a provider-specific session endpoint ("introspection-like") instead
of validating JWTs locally. It demonstrates using the Go MCP SDK's
`auth.RequireBearerToken` middleware and passing verified token info into MCP
tools via `req.Extra.TokenInfo`.

## What it does

- Accepts `Authorization: Bearer <access_token>` on `/mcp`
- Verifies the access token by calling `GET https://cloudmcp.run/api/auth/mcp/get-session`
- Optionally checks the session `userId` equals `USER_ID` env var
- Enforces token expiration and (optionally) scopes
- Makes verified token info available to tools

## Run

```bash
cd examples/server/cloudmcp-session-auth

# Initialize deps (first run)
go mod tidy

# Start server
ADDR=":8080" \
USER_ID="alice" \
CLOUDMCP_GET_SESSION_URL="https://cloudmcp.run/api/auth/mcp/get-session" \
go run .
```

## Call the MCP endpoint

The streamable transport requires Accept to include both JSON and SSE:

```bash
ACCESS_TOKEN="<your access token>"

curl -sS \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  --data '{
    "jsonrpc":"2.0",
    "id":"1",
    "method":"tools/call",
    "params":{"name":"whoami","arguments":{}}
  }' \
  http://localhost:8080/mcp
```

Example response:

```json
{"jsonrpc":"2.0","id":"1","result":{"content":[{"type":"text","text":"{\"userId\":\"alice\",\"scopes\":[\"openid\"],\"sessionId\":\"...\"}"}],"isError":false}}
```

## Environment variables

- `ADDR`: HTTP listen address (default `:8080`)
- `USER_ID`: if set, the verifier rejects tokens whose session `userId` differs
- `CLOUDMCP_GET_SESSION_URL`: override the get-session endpoint URL

## Notes

- This pattern is appropriate when your OAuth provider exposes a secure session
  lookup for the presented token. All calls are over HTTPS.
- If you need centralized scope enforcement, set `Scopes` in
  `RequireBearerTokenOptions`. You can also check per-tool using
  `req.Extra.TokenInfo.Scopes`.

