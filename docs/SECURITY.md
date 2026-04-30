# Security

## Credential protection (automatic)

When you call `register_server` (or `onboard_server`) with real credentials in `headers` or `env`, the wrapper automatically intercepts them before anything touches model context:

1. **Detection**: `looks_like_secret()` identifies JWTs, Bearer tokens, API keys (Anthropic, OpenAI, AWS, GitHub, Slack), PEM blocks, and long hex/base64 blobs.
2. **Substitution**: each detected secret is stored in the `credential_refs` table and replaced with an opaque `cref_<16-hex>` identifier. Only the identifier is written to the server record and returned in the response.
3. **Resolution**: at connection time, `open_streams()` silently resolves every `cref_` value back to the real credential before opening the transport. Security scan functions that bypass `open_streams` use `resolve_server_crefs()` for the same effect.
4. **Response scrubbing**: `_scrub_content()` applies `redact_text()` to tool outputs before returning them, so secrets that leak through a downstream server are stripped from responses stored in the database and returned to the model.

The model context, conversation history, and logs only ever see the `cref_` identifier. If a cref cannot be resolved (DB key rotated, record deleted), a warning is logged and the connection will fail authentication rather than silently passing a literal `cref_` string.

**Lifecycle:** crefs are deleted automatically when a server is re-registered with new credentials or when inspection fails after registration. Re-registering with the same `cref_` identifier (to update URL or transport while keeping credentials) preserves the ref.

**At-rest encryption:** set `MCP_DB_ENCRYPTION_KEY` (a Fernet key) to encrypt both server credentials and `cref_` values stored in the database. Without this key the database is plaintext SQLite.

## Secrets in arguments

The wrapper redacts credential-shaped values (JWTs, API keys, PEM blocks, long hex and base64 blobs) from tool arguments before storing them. If a secret is detected in an argument, a warning is included in the telemetry response. Prefer setting secrets as environment variables on the wrapped server rather than passing them as tool arguments.

## Child process isolation

When spawning stdio servers, the wrapper strips its own secrets from the child process environment: `MCP_AUTH_TOKEN`, `MCP_DB_ENCRYPTION_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `SNYK_TOKEN`, `MCP_SCANNER_API_KEY`, `MCP_SCANNER_LLM_API_KEY`. Supply needed env vars explicitly via the `env` parameter in `register_server`.

## Input validation

All server IDs, URLs, commands, and argument values are length-checked before storage. URLs are checked against an SSRF blocklist. Shell interpreters with eval flags are rejected at registration time.

## HTTP auth

Set `MCP_AUTH_TOKEN` for any HTTP deployment. The token is compared with `hmac.compare_digest` to prevent timing attacks. Without a token, the server logs a warning and accepts all connections.

## Database

The SQLite database stores server registrations, tool behavior profiles, security scan results, execution history, and credential refs. The file is set to `0o600` on POSIX systems. Enable at-rest encryption with `MCP_DB_ENCRYPTION_KEY` (Fernet) to protect stored `env`, `headers`, and `cref_` values at rest. See [Credential protection](#credential-protection-automatic) above for how credentials are handled before they reach the database.

## Argument scanning

Every tool call argument is scanned for 20+ attack categories before the call is forwarded. If an LLM key is available, flagged values get a second-pass LLM verification to clear false positives. Blocked calls return a structured response showing exactly which argument triggered which category. Pass `args_scan_override=True` (or `--args-scan-override` on the CLI) to bypass after manual review.

## Injection quarantine

Tool output flagged as a prompt injection attempt is stored in the database under the run ID but is never returned to the calling agent. The response contains a quarantine notice and the run ID for forensic review.
