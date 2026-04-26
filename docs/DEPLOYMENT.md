# Deployment

## Starting the server

**stdio (default):**

```bash
mcpsafetywarden-server
```

Reads from stdin, writes to stdout. This is the mode used by Claude Desktop and any MCP client that manages the subprocess.

**streamable_http:**

```bash
MCP_TRANSPORT=streamable_http MCP_PORT=8000 mcpsafetywarden-server
```

With bearer auth:

```bash
MCP_TRANSPORT=streamable_http MCP_AUTH_TOKEN=mysecrettoken mcpsafetywarden-server
```

Connect your MCP client to `http://127.0.0.1:8000/mcp` with header `Authorization: Bearer mysecrettoken`.

**SSE:**

```bash
MCP_TRANSPORT=sse MCP_PORT=8000 mcpsafetywarden-server
```

## Local HTTP server (full example)

```bash
MCP_TRANSPORT=streamable_http \
MCP_HOST=127.0.0.1 \
MCP_PORT=8000 \
MCP_AUTH_TOKEN=<your_secret_token> \
ANTHROPIC_API_KEY=<your_key> \
mcpsafetywarden-server
```

## Container

A `Dockerfile` is not included. A minimal setup:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
ENV MCP_TRANSPORT=streamable_http
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000
EXPOSE 8000
CMD ["mcpsafetywarden-server"]
```

Pass `MCP_AUTH_TOKEN`, `MCP_DB_ENCRYPTION_KEY`, and API keys as container environment variables. Do not bake them into the image.

## Mandatory gateway pattern

Instead of adding every MCP server to `claude_desktop_config.json`, add **only the wrapper** and register all other servers inside it. Claude then has no direct path to any underlying server - every tool call must go through `safe_tool_call`.

**`claude_desktop_config.json` - wrapper only:**

```json
{
  "mcpServers": {
    "mcpsafetywarden": {
      "command": "mcpsafetywarden-server",
      "args": [],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

**Register servers once via CLI before starting Claude Desktop:**

```bash
mcpsafetywarden register github --transport stdio \
  --command npx \
  --args '["-y", "@modelcontextprotocol/server-github"]' \
  --env '{"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..."}'

mcpsafetywarden register slack --transport stdio \
  --command npx \
  --args '["-y", "@modelcontextprotocol/server-slack"]' \
  --env '{"SLACK_BOT_TOKEN": "xoxb-..."}'
```

Claude sees only the wrapper's 18 tools. To use github or slack it must call `safe_tool_call(server_id="github", ...)` - registration is enforced because `safe_tool_call` rejects any unregistered `server_id`.

## Production considerations

- **Rate limiting** is in-process and resets on restart. For multi-replica deployments, replace the deque-based limiter with a shared store such as Redis.
- **Database** is a local SQLite file. For shared deployments, consider a networked database.
- **Bearer auth** covers the HTTP transport layer. For multi-tenant deployments, place an API gateway (nginx, Caddy, AWS API Gateway) in front and leave `MCP_AUTH_TOKEN` unset.
- **Logging** goes to stderr via Python's `logging` module. Redirect and aggregate as needed.
- **Database permissions** are set to `0o600` on POSIX systems. On Windows, use filesystem ACLs.
