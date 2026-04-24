# Contributing

1. Fork the repository and create a branch from `main`.
2. Make your changes. Keep functions focused. Follow the existing pattern: validation first, then logic, then return `json.dumps(...)` for MCP tools.
3. Test manually using the CLI against a real or mock MCP server.
4. Open a pull request with a clear description of what changed and why.

## Code standards

- No inline comments unless the reason is non-obvious.
- No docstring blocks beyond the existing MCP tool docstrings (which are user-facing).
- Match the surrounding code style: `Optional[str]` type hints, `_log.warning/error` for operator-visible events, `_log.debug` for internal traces.

## Adding a new MCP tool

1. Define an async (or sync) function in `mcpsafetywarden/server.py` decorated with `@mcp.tool()`.
2. Use `db.*` for persistence, `cm.call_tool_with_telemetry` for proxied execution.
3. Add a corresponding CLI command in `mcpsafetywarden/cli.py` with `@app.command()`.
4. Follow the existing pattern: validate input, check rate limit if it is a management operation, return `json.dumps(...)`.
