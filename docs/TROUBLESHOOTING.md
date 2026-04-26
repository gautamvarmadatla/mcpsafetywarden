# Troubleshooting

**`Tool '<name>' not found on server '<id>'.`**
Run `mcpsafetywarden inspect <server_id>` to refresh the tool list from the live server.

**`Server '<id>' not registered.`**
Run `mcpsafetywarden register` or `mcpsafetywarden onboard` first.

**`Rate limit exceeded.`**
Two separate limits:
- Management operations (register, inspect, scan, replay, etc.): 10 calls per 60 seconds per server and 100 globally. Limits are in `mcpsafetywarden/server.py` (`_MGMT_RATE_LIMIT_MAX`, `_GLOBAL_RATE_LIMIT_MAX`).
- Tool calls via `safe_tool_call`: 20 calls per 60 seconds per tool. Limit is in `mcpsafetywarden/client_manager.py` (`_RATE_LIMIT_MAX_CALLS`).

Wait for the window to expire. For heavy automation, batch operations or increase the relevant limit constants.

**`URL targets a private or restricted address.`**
The SSRF filter blocked a private IP, localhost, or cloud metadata endpoint. This is intentional. If you are proxying a legitimate internal server, use the `stdio` transport instead.

**`Registering a shell interpreter with an eval flag is not permitted.`**
You tried to register `bash -c` or similar. Use a dedicated MCP server script as the command instead of a shell one-liner.

**LLM classification shows `confidence: 0%` for all tools.**
No LLM API key was found. Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY`. Classification falls back to rule-based when no key is available.

**Scan fails immediately with `confirm_authorized must be True`.**
The mcpsafety+ scanner requires explicit authorization before sending live probes. Pass `--yes` on the CLI or `confirm_authorized=True` on the MCP tool.

**`snyk-agent-scan not available.`**
Install with `pip install snyk-agent-scan`. If the binary is installed but not on `PATH`, the wrapper falls back to the Python module invocation automatically. Check that `pip show snyk-agent-scan` shows the package.

**`SNYK_TOKEN is required for snyk-agent-scan.`**
Set `SNYK_TOKEN=snyk_uat.<your_token>` in your environment or pass `--api-key snyk_uat.<your_token>` on the CLI. Get a free token at [app.snyk.io/account](https://app.snyk.io/account).

**Snyk scan returns 0 findings on a server that has obvious issues.**
Snyk analyses tool metadata only - it does not call tools or inspect server-side logic. If the malicious content is not in tool names, descriptions, or schemas, Snyk will not detect it. Use `--provider anthropic` with `--yes` for active probing.

**`MCP_DB_ENCRYPTION_KEY is set but Fernet init failed.`**
The key is malformed. Regenerate it:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Decryption failure logged at ERROR level.**
The encryption key changed after data was written (key rotation). The affected server's env and headers will read as empty until the server is re-registered with the new key.
