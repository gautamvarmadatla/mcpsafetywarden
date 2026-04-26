# Security

## Secrets in arguments

The wrapper redacts credential-shaped values (JWTs, API keys, PEM blocks, long hex and base64 blobs) from tool arguments before storing them. If a secret is detected in an argument, a warning is included in the telemetry response. Prefer setting secrets as environment variables on the wrapped server rather than passing them as tool arguments.

## Child process isolation

When spawning stdio servers, the wrapper strips its own secrets from the child process environment: `MCP_AUTH_TOKEN`, `MCP_DB_ENCRYPTION_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `SNYK_TOKEN`, `MCP_SCANNER_API_KEY`, `MCP_SCANNER_LLM_API_KEY`. Supply needed env vars explicitly via the `env` parameter in `register_server`.

## Input validation

All server IDs, URLs, commands, and argument values are length-checked before storage. URLs are checked against an SSRF blocklist. Shell interpreters with eval flags are rejected at registration time.

## HTTP auth

Set `MCP_AUTH_TOKEN` for any HTTP deployment. The token is compared with `hmac.compare_digest` to prevent timing attacks. Without a token, the server logs a warning and accepts all connections.

## Database

Enable at-rest encryption with `MCP_DB_ENCRYPTION_KEY` to protect stored server credentials (env vars, HTTP headers). The database file is set to `0o600` on POSIX systems.

## Argument scanning

Every tool call argument is scanned for 20+ attack categories before the call is forwarded. If an LLM key is available, flagged values get a second-pass LLM verification to clear false positives. Blocked calls return a structured response showing exactly which argument triggered which category. Pass `args_scan_override=True` (or `--args-scan-override` on the CLI) to bypass after manual review.

## Injection quarantine

Tool output flagged as a prompt injection attempt is stored in the database under the run ID but is never returned to the calling agent. The response contains a quarantine notice and the run ID for forensic review.
