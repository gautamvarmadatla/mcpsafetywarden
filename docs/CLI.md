## CLI Reference

### Global flags

All commands support `--json` for machine-readable output. Commands with confirmation prompts support `--yes` / `-y` to skip them.

### Typical workflow

```bash
# Register, inspect, and scan a local stdio server in one step
mcpsafetywarden onboard my-server \
  --transport stdio \
  --command python \
  --args '["my_mcp_server.py"]' \
  --scan-provider anthropic

# Check what tools were discovered
mcpsafetywarden list my-server

# Execute a tool safely
mcpsafetywarden call my-server read_file --args '{"path": "/tmp/data.txt"}'

# Execute a risky tool (interactive menu appears if blocked)
mcpsafetywarden call my-server delete_file --args '{"path": "/tmp/old.txt"}'
```

**`call` interactive flow when a tool is blocked:**

```
Warning  Blocked  risk: HIGH
  1.  list_files  -- reduction: HIGH  coverage: partial
  2.  More options

Pick: 2

  B.  Proceed with original tool despite risk
  C.  Abort

Pick [B/b/C/c]: B

ok  142ms  [explicit_approval]
```

To bypass the menu in scripts, pass `--approved`:

```bash
mcpsafetywarden call my-server delete_file \
  --args '{"path": "/tmp/old.txt"}' \
  --approved
```

### Commands

**`list [server_id]`**
List all registered servers. Pass `server_id` to list tools on a specific server.

```bash
mcpsafetywarden list
mcpsafetywarden list my-server
mcpsafetywarden list my-server --json
```

**`onboard <server_id>`**
Register + inspect + security scan in one call. Prompts for authorization before scanning unless `--yes` is passed.

```bash
mcpsafetywarden onboard my-server --transport stdio --command python --args '["server.py"]'
mcpsafetywarden onboard my-server --transport streamable_http --url https://mcp.example.com/mcp \
  --headers '{"Authorization": "Bearer TOKEN"}' \
  --scan-provider anthropic --scan-model claude-opus-4-7 --scan-api-key sk-ant-... --yes
```

**`register <server_id>`**
Register only, without scanning.

```bash
mcpsafetywarden register my-server --transport stdio --command python --args '["server.py"]'
mcpsafetywarden register my-server --transport stdio --command python --no-inspect
mcpsafetywarden register my-server --transport stdio --command python --args '["server.py"]' --provider anthropic
```

**`inspect <server_id>`**
Reconnect to a registered server, refresh tools, re-classify.

```bash
mcpsafetywarden inspect my-server --provider anthropic
mcpsafetywarden inspect my-server --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
```

**`scan <server_id>`**
Run a security scan against a single server. Prompts for authorization before probing.

- `anthropic`, `openai`, `gemini`, `ollama` - mcpsafety+ 5-stage pipeline (Recon -> Planner -> Hacker -> Auditor -> Supervisor)
- `cisco` - Cisco AI Defense: AST taint analysis, YARA rules, optional cloud ML engine
- `snyk` - Snyk: prompt injection, tool shadowing, toxic data flows, hardcoded secrets

For Ollama set `OLLAMA_MODEL` before running. Web research (DuckDuckGo/HackerNews/Arxiv CVE lookup in the Auditor stage) is skipped by default to avoid leaking findings externally; pass `--web-research` to enable it.

If a **Kali MCP** server is registered, nmap and traceroute results are shown after the findings table and included in `--json` output under `network_scan`. If a **Burp Suite MCP** server is registered, the number of HTTP-layer findings Burp contributed is shown as a summary line; use `--json` for the full evidence.

```bash
mcpsafetywarden scan my-server --provider anthropic
mcpsafetywarden scan my-server --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
mcpsafetywarden scan my-server --provider ollama              # local model, no API key
mcpsafetywarden scan my-server --provider cisco
mcpsafetywarden scan my-server --provider anthropic --web-research --destructive --timeout 600 --yes
```

**`scan-all`**
Run the full 5-stage mcpsafety+ pipeline against every registered server (or a comma-separated subset via `--servers`). Results are stored per server and displayed as a combined risk table. Only mcpsafety+ providers are supported (not `cisco` or `snyk`). Web research is skipped by default; pass `--web-research` to enable.

```bash
mcpsafetywarden scan-all --provider anthropic
mcpsafetywarden scan-all --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
mcpsafetywarden scan-all --provider ollama --servers my-server,other-server --yes
mcpsafetywarden scan-all --provider openai --web-research --timeout 600 --json
```

**`call <server_id> <tool_name>`**
Execute a tool through the risk gate. Interactive menu appears if the tool is blocked.

Every argument value is scanned for 20+ attack categories (SSRF, SQL/NoSQL/LDAP/XPath injection, command injection, path traversal, XXE, prompt injection, deserialization payloads, base64-encoded variants, and more) before the call is forwarded. If an LLM key is set, a second-pass LLM verification runs on flagged args to clear false positives. Without an LLM key, the CLI prompts you to confirm before proceeding.

```bash
mcpsafetywarden call my-server search_web --args '{"query": "site:example.com"}'
mcpsafetywarden call my-server delete_file --args '{"path": "/tmp/x"}' --approved
mcpsafetywarden call my-server run_query --args '{"sql": "SELECT id FROM users"}' --args-scan-override
```

| Flag | Effect |
|---|---|
| `--approved` | Bypass the risk gate for a high-risk tool you have reviewed |
| `--args-scan-override` | Skip argument safety scanning (use only when you trust the args) |
| `--provider` | LLM provider for alternatives and arg verification (`anthropic`\|`openai`\|`gemini`\|`ollama`) |

**`preflight <server_id> <tool_name>`**
Assess risk without executing.

```bash
mcpsafetywarden preflight my-server delete_file
mcpsafetywarden preflight my-server delete_file --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
```

**`profile <server_id> <tool_name>`**
Print the full behavior profile.

```bash
mcpsafetywarden profile my-server read_file --json
```

**`retry-policy <server_id> <tool_name>`**
Print retry and timeout recommendations.

```bash
mcpsafetywarden retry-policy my-server call_api
mcpsafetywarden retry-policy my-server call_api --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
```

**`alternatives <server_id> <tool_name>`**
List safer alternatives to a tool.

```bash
mcpsafetywarden alternatives my-server delete_file --provider anthropic
```

**`replay <server_id> <tool_name>`**
Run the tool twice and compare outputs. Prompts for confirmation. If a **Burp Suite MCP** server is registered, Burp proxy traffic captured during both calls is appended to the result - useful for spotting network-level differences even when output text is identical.

```bash
mcpsafetywarden replay my-server get_status --args '{"id": "123"}' --yes
```

**`policy <server_id> <tool_name>`**
Read or set a permanent execution policy. Without `--set`, prints the current policy.

By default no policy is set and `safe_tool_call` decides at runtime based on the behavior profile: low or medium-low risk tools run immediately, medium/high-risk tools trigger the approval gate. Setting a policy overrides that completely - `allow` bypasses the risk gate (argument scanning still runs unless `--args-scan-override` is also passed), `block` rejects unconditionally.

```bash
mcpsafetywarden policy my-server read_file             # read current policy
mcpsafetywarden policy my-server read_file --set allow  # always execute without preflight
mcpsafetywarden policy my-server drop_table --set block # never execute
mcpsafetywarden policy my-server read_file --set clear  # remove policy, resume normal flow
```

**`history <server_id> <tool_name>`**
Show recent execution history.

```bash
mcpsafetywarden history my-server delete_file --limit 50
```

**`ping <server_id>`**
Check if a server is reachable. If a **Kali MCP** server is registered and the pinged server uses the `sse` or `streamable_http` transport, also runs `quick_scan` and `traceroute` against the target host and displays the output in labeled panels. Stdio servers have no network address to scan so Kali recon is skipped.

```bash
mcpsafetywarden ping my-server
```

**`get-scan <server_id>`**
Print the latest stored security scan report.

```bash
mcpsafetywarden get-scan my-server --json
```

**Exit codes:**
- `0`: success
- `1`: error (tool not found, blocked by policy, unreachable server, invalid input)
