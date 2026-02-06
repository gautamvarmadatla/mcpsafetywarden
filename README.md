# mcp-behavior-wrapper

A proxy server that wraps any MCP server and adds behavioral profiling, security scanning, risk gating, and safe execution to its tools.

Instead of calling a wrapped server's tools directly, you route calls through this wrapper. It classifies each tool, builds a behavior profile from observed runs, checks for injection attacks, and can block or gate risky tools before they execute.

---

## Overview

Most MCP servers expose tools with no information about what those tools actually do at runtime: whether they write data, call external services, delete things, or produce outputs that contain adversarial content.

This wrapper solves that by sitting between an MCP client and one or more wrapped servers. It:

- Classifies every tool by effect class, destructiveness, and retry safety using static rules and optionally an LLM.
- Builds observed behavior profiles from live execution data: latency percentiles, failure rates, output size, schema stability.
- Scans tool call arguments for injection attacks (SSRF, SQL/NoSQL injection, command injection, prompt injection, path traversal, and more) before forwarding the call.
- Scans tool output for prompt injection using regex rules and an LLM deep scan.
- Runs security audits using a five-stage pentest pipeline, Cisco AI Defense, or Snyk.
- Optionally integrates with **Kali Linux MCP** (nmap network recon, service fingerprinting, traceroute) and **Burp Suite MCP** (raw HTTP probes, Collaborator OOB detection, proxy history evidence) to add real network and HTTP-layer data to every scan.
- Gates tool execution: low or medium-low risk tools run immediately, medium/high-risk tools are blocked until a user approves or picks a safer alternative.
- Stores all run telemetry in a local SQLite database.

Use it when you need to audit what third-party or internal MCP tools actually do before trusting them in an agent workflow.

---

## Features

**Behavioral profiling**
- Static classification of effect class (read_only, additive_write, mutating_write, external_action, destructive), retry safety, and destructiveness.
- LLM-assisted classification via Anthropic, OpenAI, Gemini, or Ollama - LLM and rule-based signals are combined via weighted voting, producing higher confidence across all tools.
- Observed stats updated after every proxied call: p50/p95 latency, failure rate, output size, schema stability.

**Security scanning**
- mcpsafety+ five-stage pipeline: Recon, Planner, Hacker (live probing), Auditor (CVE/Arxiv research), Supervisor (final report). Enhanced over [mcpsafetyscanner](https://github.com/johnhalloran321/mcpsafetyscanner) (Radosevich & Halloran, arxiv 2504.03767).
- LLM provider choice for mcpsafety+: Anthropic, OpenAI, Gemini, or Ollama (local, no API key).
- Multi-server scan: run the full pipeline against every registered server in one call via `scan_all_servers`.
- Cisco AI Defense: AST and taint analysis, YARA rules, optional cloud ML engine.
- Snyk: prompt injection, tool shadowing, toxic data flows, hardcoded secrets.
- **Kali MCP integration**: if a Kali Linux MCP server is registered, the Recon stage automatically runs `quick_scan`, `vulnerability_scan`, and `traceroute` against the target host before the LLM analyzes tool schemas. Real port and service data feeds the Planner so attack hypotheses are grounded in what is actually running.
- **Burp Suite MCP integration**: if a Burp Suite MCP server is registered, the Hacker stage sends raw HTTP/1.1 probes directly to the MCP endpoint (malformed JSON, missing headers, oversized payloads), triggers Collaborator out-of-band payloads to detect blind SSRF (Pro edition), and pulls automated scanner findings (Pro edition). Proxy history feeds the Auditor as raw evidence. Community edition tools run automatically; Pro-only tools are tried and silently skipped if unavailable.
- All findings stored and surfaced automatically in subsequent preflight assessments.

**Safe execution**
- Argument scanning on every tool call: 20+ attack categories (SSRF, SQL/NoSQL/LDAP/XPath injection, command injection, path traversal, XXE, template injection, prompt injection, deserialization payloads, base64-encoded variants, Windows-specific paths). When an LLM key is set, flagged args get a second-pass LLM verification to clear false positives.
- Two-layer injection scanning on every tool output: 40+ regex patterns then LLM deep scan.
- Injection-flagged output is quarantined and never returned to the caller.
- Risk gating with per-tool permanent policies (allow/block) or per-call approval flow.
- Alternatives suggestion: when a tool is blocked, the LLM ranks safer substitutes by risk reduction and functional coverage.

**CLI**
- 16 subcommands covering all 17 MCP tools (`list` covers both `list_servers` and `list_server_tools`).
- Interactive risk menu for `call`: pick an alternative, approve the original, or abort.
- `scan-all` runs the full pentest pipeline across all registered servers in one command.
- `--json` flag on every command for scripting and pipelines.
- `--yes` / `-y` flag on confirmation prompts for CI use.

**Transport**
- stdio (default), SSE, and streamable_http.
- Bearer token auth middleware for HTTP transports.

---

## Architecture

```
MCP Client (Claude Desktop, agent, cli.py)
        |
        v
  server.py  (FastMCP, 17 tools, rate limiting, bearer auth)
        |
        +---> client_manager.py  (connects to wrapped servers, records telemetry, injection scan)
        |
        +---> database.py        (SQLite: servers, tools, runs, profiles, scans, policies)
        |
        +---> classifier.py      (rule-based + LLM tool classification)
        |
        +---> profiler.py        (computes behavior profiles from run history)
        |
        +---> scanner.py         (LLM, Cisco, Snyk scan orchestration)
        |
        +---> mcpsafety_scanner.py (five-stage pentest pipeline)
        |
        +---> security_utils.py  (redaction, normalisation, injection detection helpers)
```

`cli.py` imports from `server.py` and `database.py` directly. It does not use the MCP protocol; it calls the same Python functions that the MCP tools call, which means no network hop for CLI usage.

**Request flow for `safe_tool_call`:**

1. Lookup tool record and behavior profile in SQLite.
2. Check permanent policy (allow/block).
3. Run `_preflight_assessment`: compute risk level from profile and latest security scan findings.
4. If low or medium-low risk: scan args for threats -> forward call to wrapped server via `client_manager` -> scan output -> record telemetry -> return result.
5. If medium/high risk and not approved: fetch LLM-ranked alternatives, return blocked response with numbered menu.
6. If approved or alternative selected: scan args for threats -> execute -> scan output -> record telemetry -> return result.

---

## Auxiliary Security Tool Integrations

The wrapper detects Kali and Burp by looking for registered servers whose `server_id` contains `"kali"` or `"burp"` (case-insensitive). Registration is the only setup step — once registered, the tools activate automatically on every scan, ping, and replay test.

### Kali Linux MCP (`ccq1/awsome_kali_MCPServers`)

Docker-based, Apache 2.0, no auth. Adds real network reconnaissance to the Recon stage and network data to `ping_server`.

**What it contributes:**

| Pipeline stage / tool | Kali tools called | What it adds |
|---|---|---|
| Recon (before Planner) | `quick_scan(target)`, `vulnerability_scan(target)`, `traceroute(target)` | Open ports, running services, OS fingerprint, network path - Planner uses this to craft targeted hypotheses |
| `ping_server` | `quick_scan(target)`, `traceroute(target)` | Network reachability detail beyond the MCP protocol ping |

**Setup:**

```bash
# Pull and run the Kali MCP Docker image
docker pull ccq1/awsome-kali-mcp   # adjust image name to match the published tag

# Register it with the wrapper (server_id must contain "kali")
python cli.py register kali-mcp \
  --transport stdio \
  --command docker \
  --args '["run", "-i", "--rm", "ccq1/awsome-kali-mcp"]'
```

Note: `vulnerability_scan` runs nmap vuln scripts which can take 60-90 seconds per target. On `scan-all` across many servers this adds up. Register only when you want network recon in your scans.

### Burp Suite MCP (`PortSwigger/mcp-server`)

Kotlin, GPL-3.0, no auth, runs as a stdio proxy to a local Burp Suite instance on port 9876. Community edition tools run always; Pro-only tools (Collaborator, scanner) are tried and silently skipped on failure.

**What it contributes:**

| Pipeline stage / tool | Burp tools called | Edition | What it adds |
|---|---|---|---|
| Hacker (after LLM probing) | `SendHttp1Request` x3 | Community | Raw HTTP probes: malformed JSON body, missing Content-Type, oversized method field |
| Hacker | `GenerateCollaboratorPayload`, `GetCollaboratorInteractions` | Pro | Out-of-band DNS/HTTP callbacks - detects blind SSRF and blind injection |
| Hacker | `GetScannerIssues` | Pro | Automated active scanner findings against the MCP endpoint |
| Auditor | `GetProxyHttpHistoryRegex` | Community | Raw HTTP traffic evidence for every finding the Auditor validates |
| `run_replay_test` | `GetProxyHttpHistoryRegex` | Community | HTTP traffic captured during both tool calls, appended to the replay result |

**Setup:**

1. Install [Burp Suite](https://portswigger.net/burp) (Community or Professional).
2. Install the [MCP Server extension](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc) from the BApp Store.
3. Start Burp Suite - the extension starts an MCP server on `127.0.0.1:9876`.
4. Register it with the wrapper (server_id must contain `"burp"`):

```bash
# Clone the PortSwigger MCP server proxy
git clone https://github.com/PortSwigger/mcp-server
cd mcp-server

# Register (the proxy connects stdio -> Burp's localhost:9876)
python cli.py register burp-mcp \
  --transport stdio \
  --command java \
  --args '["-jar", "/path/to/burp-mcp-server.jar"]'
```

---

## Prerequisites

- Python 3.10 or later.
- `pip` for dependency installation.
- At least one wrapped MCP server to proxy (stdio subprocess, SSE endpoint, or streamable_http endpoint).
- **Recommended: an API key for at least one LLM provider** (Anthropic, OpenAI, Gemini, or a local Ollama instance).

**Why an LLM key matters:**

The wrapper has two operating modes depending on whether an LLM is available:

| Capability | Without LLM key | With LLM key |
|---|---|---|
| Tool classification | Rule-based heuristics only - low confidence on ambiguous tool names | LLM resolves ambiguous cases; higher confidence across the board |
| Injection scanning | Regex patterns only (40+ rules) | Regex + LLM deep scan - catches obfuscated and novel injections |
| Risk gate alternatives | None - gate shows "More options" only | LLM ranks safer substitute tools by risk reduction and functional coverage |
| Security scanning | Not available (mcpsafety+ requires an LLM) | Full 5-stage pentest: Recon, Planner, Hacker, Auditor, Supervisor |

Set at minimum `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY` before starting the server. For a fully local setup with no API keys, run [Ollama](https://ollama.com) and set `OLLAMA_MODEL` - then pass `--provider ollama` (or `scan_provider="ollama"`) explicitly on every command, as Ollama is not auto-detected from environment variables.

---

## Installation

```bash
git clone <YOUR_REPO_URL>
cd mcp-behavior-wrapper
pip install -r requirements.txt
```

Verify the install:

```bash
python server.py --help 2>&1 || echo "Server starts on run, not --help"
python cli.py --help
```

The SQLite database (`behavior_profiles.db`) is created automatically in the project directory on first run.

**Optional: at-rest encryption for stored credentials**

The wrapper stores server env vars and HTTP headers in the database. To encrypt them at rest:

```bash
pip install cryptography
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the printed key as `MCP_DB_ENCRYPTION_KEY` before starting the server. Keep this key safe; losing it makes stored credentials unrecoverable.

---

## Configuration

All configuration is via environment variables. No config file is required.

| Variable | Default | Purpose |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio`, `sse`, or `streamable_http` |
| `MCP_HOST` | `127.0.0.1` | Bind address for HTTP transports |
| `MCP_PORT` | `8000` | Bind port for HTTP transports |
| `MCP_AUTH_TOKEN` | (unset) | Bearer token for HTTP transport auth. Unset means no auth (log warning is emitted). |
| `MCP_DB_ENCRYPTION_KEY` | (unset) | Fernet key to encrypt `env_json` and `headers_json` at rest |
| `ANTHROPIC_API_KEY` | (unset) | Enables Anthropic as LLM provider for classification and scanning |
| `OPENAI_API_KEY` | (unset) | Enables OpenAI as LLM provider |
| `GEMINI_API_KEY` | (unset) | Enables Gemini as LLM provider |
| `GOOGLE_API_KEY` | (unset) | Legacy alias for `GEMINI_API_KEY` |
| `OLLAMA_MODEL` | (unset) | Model name for Ollama provider (e.g. `llama3.1`, `mistral`) |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Ollama API base URL (OpenAI-compatible) |
| `SNYK_TOKEN` | (unset) | Enables Snyk E001 prompt-injection detection |
| `MCP_SCANNER_API_KEY` | (unset) | Cisco AI Defense API key for cloud ML engine |
| `MCP_SCANNER_LLM_API_KEY` | (unset) | LLM key for Cisco internal AST analysis (falls back to `OPENAI_API_KEY`) |

**Example `.env` for local development:**

```bash
MCP_TRANSPORT=stdio
ANTHROPIC_API_KEY=sk-ant-...
MCP_DB_ENCRYPTION_KEY=<generated_fernet_key>
```

**Security note:** Never commit API keys or the encryption key to version control. Pass them via environment variables or a secrets manager. The wrapper strips all keys from the environment before spawning stdio child processes.

---

## Running the MCP Server

**stdio (default):**

```bash
python server.py
```

The server reads from stdin and writes to stdout. This is the mode used by Claude Desktop and other MCP clients that manage the subprocess.

**HTTP (streamable_http):**

```bash
MCP_TRANSPORT=streamable_http MCP_PORT=8000 python server.py
```

Set `MCP_AUTH_TOKEN` to require bearer auth on all requests:

```bash
MCP_TRANSPORT=streamable_http MCP_AUTH_TOKEN=mysecrettoken python server.py
```

**SSE:**

```bash
MCP_TRANSPORT=sse MCP_PORT=8000 python server.py
```

---

## Using the CLI

The CLI wraps every MCP tool as a subcommand. It imports server functions directly so no running server process is needed.

```bash
python cli.py --help
python cli.py <command> --help
```

**Typical onboarding workflow:**

```bash
# Register, inspect, and scan a local stdio server in one step
python cli.py onboard my-server \
  --transport stdio \
  --command python \
  --args '["my_mcp_server.py"]' \
  --scan-provider anthropic

# Check what tools were discovered
python cli.py list my-server

# Execute a tool safely
python cli.py call my-server read_file --args '{"path": "/tmp/data.txt"}'

# Execute a risky tool (interactive menu appears if blocked)
python cli.py call my-server delete_file --args '{"path": "/tmp/old.txt"}'
```

**`call` interactive flow when a tool is blocked:**

```
⚠ Blocked  risk: HIGH
  1.  list_files  -- reduction: HIGH  coverage: partial
  2.  More options

Pick: 2

  B.  Proceed with original tool despite risk
  C.  Abort

Pick [B/b/C/c]: B

✓  142ms  [explicit_approval]
```

To bypass the menu in scripts, pass `--approved`:

```bash
python cli.py call my-server delete_file \
  --args '{"path": "/tmp/old.txt"}' \
  --approved
```

---

## CLI Reference

### Global flags

All commands support `--json` for machine-readable output. Commands with confirmation prompts support `--yes` / `-y` to skip them.

### Commands

**`list [server_id]`**
List all registered servers. Pass `server_id` to list tools on a specific server.

```bash
python cli.py list
python cli.py list my-server
python cli.py list my-server --json
```

**`onboard <server_id>`**
Register + inspect + security scan in one call. Prompts for authorization before scanning unless `--yes` is passed.

```bash
python cli.py onboard my-server --transport stdio --command python --args '["server.py"]'
python cli.py onboard my-server --transport streamable_http --url https://mcp.example.com/mcp \
  --headers '{"Authorization": "Bearer TOKEN"}' \
  --scan-provider anthropic --scan-model claude-opus-4-7 --scan-api-key sk-ant-... --yes
```

**`register <server_id>`**
Register only, without scanning.

```bash
python cli.py register my-server --transport stdio --command python --args '["server.py"]'
python cli.py register my-server --transport stdio --command python --no-inspect
python cli.py register my-server --transport stdio --command python --args '["server.py"]' --provider anthropic
```

**`inspect <server_id>`**
Reconnect to a registered server, refresh tools, re-classify.

```bash
python cli.py inspect my-server --provider anthropic
python cli.py inspect my-server --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
```

**`scan <server_id>`**
Run a security scan against a single server. Prompts for authorization before probing.

- `anthropic`, `openai`, `gemini`, `ollama` - mcpsafety+ 5-stage pipeline (Recon -> Planner -> Hacker -> Auditor -> Supervisor)
- `cisco` - Cisco AI Defense: AST taint analysis, YARA rules, optional cloud ML engine
- `snyk` - Snyk: prompt injection, tool shadowing, toxic data flows, hardcoded secrets

For Ollama set `OLLAMA_MODEL` before running. Web research (DuckDuckGo/HackerNews/Arxiv CVE lookup in the Auditor stage) is skipped by default to avoid leaking findings externally; pass `--web-research` to enable it.

If a **Kali MCP** server is registered, nmap and traceroute results are shown after the findings table and included in `--json` output under `network_scan`. If a **Burp Suite MCP** server is registered, the number of HTTP-layer findings Burp contributed is shown as a summary line; use `--json` for the full evidence.

```bash
python cli.py scan my-server --provider anthropic
python cli.py scan my-server --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
python cli.py scan my-server --provider ollama              # local model, no API key
python cli.py scan my-server --provider cisco
python cli.py scan my-server --provider anthropic --web-research --destructive --timeout 600 --yes
```

**`scan-all`**
Run the full 5-stage mcpsafety+ pipeline against every registered server (or a comma-separated subset via `--servers`). Results are stored per server and displayed as a combined risk table. Only mcpsafety+ providers are supported (not `cisco` or `snyk`). Web research is skipped by default; pass `--web-research` to enable.

```bash
python cli.py scan-all --provider anthropic
python cli.py scan-all --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
python cli.py scan-all --provider ollama --servers my-server,other-server --yes
python cli.py scan-all --provider openai --web-research --timeout 600 --json
```

**`call <server_id> <tool_name>`**
Execute a tool through the risk gate. Interactive menu appears if the tool is blocked.

Every argument value is scanned for 20+ attack categories (SSRF, SQL/NoSQL/LDAP/XPath injection, command injection, path traversal, XXE, prompt injection, deserialization payloads, base64-encoded variants, and more) before the call is forwarded. If an LLM key is set, a second-pass LLM verification runs on flagged args to clear false positives. Without an LLM key, the CLI prompts you to confirm before proceeding.

```bash
python cli.py call my-server search_web --args '{"query": "site:example.com"}'
python cli.py call my-server delete_file --args '{"path": "/tmp/x"}' --approved

# Skip arg safety scan - only use when you have verified the args are safe
python cli.py call my-server run_query --args '{"sql": "SELECT id FROM users"}' --args-scan-override
```

| Flag | Effect |
|---|---|
| `--approved` | Bypass the risk gate for a high-risk tool you have reviewed |
| `--args-scan-override` | Skip argument safety scanning (use only when you trust the args) |
| `--provider` | LLM provider for alternatives and arg verification (`anthropic`\|`openai`\|`gemini`\|`ollama`) |

**`preflight <server_id> <tool_name>`**
Assess risk without executing.

```bash
python cli.py preflight my-server delete_file
python cli.py preflight my-server delete_file --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
```

**`profile <server_id> <tool_name>`**
Print the full behavior profile.

```bash
python cli.py profile my-server read_file --json
```

**`retry-policy <server_id> <tool_name>`**
Print retry and timeout recommendations.

```bash
python cli.py retry-policy my-server call_api
python cli.py retry-policy my-server call_api --provider anthropic --model claude-opus-4-7 --api-key sk-ant-...
```

**`alternatives <server_id> <tool_name>`**
List safer alternatives to a tool.

```bash
python cli.py alternatives my-server delete_file --provider anthropic
```

**`replay <server_id> <tool_name>`**
Run the tool twice and compare outputs. Prompts for confirmation. If a **Burp Suite MCP** server is registered, Burp proxy traffic captured during both calls is appended to the result - useful for spotting network-level differences even when output text is identical.

```bash
python cli.py replay my-server get_status --args '{"id": "123"}' --yes
```

**`policy <server_id> <tool_name>`**
Read or set a permanent execution policy. Without `--set`, prints the current policy.

By default no policy is set and `safe_tool_call` decides at runtime based on the behavior profile: low or medium-low risk tools run immediately, medium/high-risk tools trigger the approval gate. Setting a policy overrides that completely - `allow` bypasses the risk gate (argument scanning still runs unless `--args-scan-override` is also passed), `block` rejects unconditionally.

```bash
python cli.py policy my-server read_file             # read current policy
python cli.py policy my-server read_file --set allow  # always execute without preflight
python cli.py policy my-server drop_table --set block # never execute
python cli.py policy my-server read_file --set clear  # remove policy, resume normal flow
```

**`history <server_id> <tool_name>`**
Show recent execution history.

```bash
python cli.py history my-server delete_file --limit 50
```

**`ping <server_id>`**
Check if a server is reachable. If a **Kali MCP** server is registered, also runs `quick_scan` and `traceroute` against the target host and displays the output in labeled panels.

```bash
python cli.py ping my-server
```

**`get-scan <server_id>`**
Print the latest stored security scan report.

```bash
python cli.py get-scan my-server --json
```

**Exit codes:**
- `0`: success
- `1`: error (tool not found, blocked by policy, unreachable server, invalid input)

---

## MCP Integration

### Connecting with Claude Desktop

Add the wrapper to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-behavior-wrapper": {
      "command": "python",
      "args": ["/absolute/path/to/mcp-behavior-wrapper/server.py"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-...",
        "MCP_DB_ENCRYPTION_KEY": "<generated_fernet_key>"
      }
    },

    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/yourname/Documents"]
    },

    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..."
      }
    }
  }
}
```

The wrapper and the servers it proxies are registered separately in Claude Desktop. Claude sees all of them - but you route calls through `mcp-behavior-wrapper` (using `safe_tool_call`, `preflight_tool_call`, etc.) instead of calling `filesystem` or `github` directly. First register each server with the wrapper:

```bash
python cli.py register filesystem --transport stdio \
  --command npx \
  --args '["-y", "@modelcontextprotocol/server-filesystem", "/Users/yourname/Documents"]'

python cli.py register github --transport stdio \
  --command npx \
  --args '["-y", "@modelcontextprotocol/server-github"]' \
  --env '{"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..."}'
```

---

> ### Using the wrapper as a mandatory gateway for all tool calls
>
> Instead of adding every MCP server to `claude_desktop_config.json`, you can add **only the wrapper** and register all other servers inside it. Claude then has no direct path to any underlying server - every tool call must go through `safe_tool_call`, making the wrapper a mandatory enforcement point for risk gating, arg scanning, and output inspection across your entire MCP setup.
>
> **`claude_desktop_config.json` - wrapper only:**
>
> ```json
> {
>   "mcpServers": {
>     "mcp-behavior-wrapper": {
>       "command": "python",
>       "args": ["/absolute/path/to/mcp-behavior-wrapper/server.py"],
>       "env": {
>         "ANTHROPIC_API_KEY": "sk-ant-..."
>       }
>     }
>   }
> }
> ```
>
> **Register your servers once via CLI before starting Claude Desktop:**
>
> ```bash
> python cli.py register github --transport stdio \
>   --command npx \
>   --args '["-y", "@modelcontextprotocol/server-github"]' \
>   --env '{"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..."}'
>
> python cli.py register slack --transport stdio \
>   --command npx \
>   --args '["-y", "@modelcontextprotocol/server-slack"]' \
>   --env '{"SLACK_BOT_TOKEN": "xoxb-..."}'
> ```
>
> Claude sees only the wrapper's 17 tools. To use github or slack it must call `safe_tool_call(server_id="github", ...)` - there is no other route. Registration is enforced because `safe_tool_call` rejects any `server_id` that is not registered.

**Field notes:**

| Field | Required | Notes |
|---|---|---|
| `args` | Yes | Absolute path to `server.py`. Relative paths fail when Claude Desktop launches from a different working directory. |
| `ANTHROPIC_API_KEY` | Strongly recommended | Enables LLM classification, deep injection scanning, risk gate alternatives, and the full mcpsafety+ pentest pipeline. Use `OPENAI_API_KEY` or `GEMINI_API_KEY` instead if preferred. Without any key the wrapper operates in rule-based-only mode - see [Prerequisites](#prerequisites). |
| `MCP_DB_ENCRYPTION_KEY` | Recommended | Encrypts stored server credentials (env vars, headers) at rest. Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `MCP_TRANSPORT` | No | Defaults to `stdio`. Leave as-is for Claude Desktop. |
| `MCP_AUTH_TOKEN` | No | Not needed for stdio; only relevant for HTTP deployments. Omit or leave empty. |

Restart Claude Desktop. All 17 wrapper tools appear in Claude's tool list.

### Connecting with an HTTP client

```bash
MCP_TRANSPORT=streamable_http MCP_AUTH_TOKEN=mytoken python server.py
```

Configure your MCP client to connect to `http://127.0.0.1:8000/mcp` with header `Authorization: Bearer mytoken`.

### Available MCP tools

| Tool | What it does |
|---|---|
| `onboard_server` | Register + inspect + security scan in one call |
| `register_server` | Register a server; optionally auto-inspect |
| `inspect_server` | Refresh tool list and profiles |
| `list_servers` | List all registered servers |
| `list_server_tools` | List tools on a server with summary profiles |
| `preflight_tool_call` | Risk assessment without execution |
| `safe_tool_call` | Execute with risk gating and interactive alternatives |
| `get_tool_profile` | Full behavior profile with observed stats |
| `get_retry_policy` | Retry and timeout recommendations |
| `suggest_safer_alternative` | LLM-ranked safer substitutes |
| `run_replay_test` | Idempotency test (runs tool twice); appends Burp proxy traffic if Burp is registered |
| `security_scan_server` | Live security audit (mcpsafety+, Cisco, Snyk); Kali nmap enriches Recon, Burp adds HTTP-layer probes to Hacker and evidence to Auditor |
| `scan_all_servers` | Run mcpsafety+ pipeline across all registered servers |
| `get_security_scan` | Latest stored scan report |
| `set_tool_policy` | Permanent allow/block policy for a tool |
| `get_run_history` | Recent execution history |
| `ping_server` | Reachability check with latency; adds Kali nmap + traceroute if Kali is registered |

---

## Project Structure

```
mcp-behavior-wrapper/
├── server.py               # FastMCP server, all MCP tools, rate limiting, bearer auth
├── cli.py                  # CLI (typer + rich), imports server.py functions directly
├── client_manager.py       # Connects to wrapped servers, injection scanning, telemetry
├── database.py             # SQLite persistence (servers, tools, runs, profiles, scans, policies)
├── classifier.py           # Static rule-based + LLM tool classification
├── profiler.py             # Builds behavior profiles from run history
├── scanner.py              # LLM, Cisco AI Defense, Snyk scan orchestration
├── mcpsafety_scanner.py    # Five-stage pentest pipeline (Recon, Planner, Hacker, Auditor, Supervisor)
├── security_utils.py       # Text normalisation, redaction, credential detection
├── requirements.txt
└── behavior_profiles.db    # Created at runtime
```

---

## Development

**Install dependencies:**

```bash
pip install -r requirements.txt
```

**Run the server in stdio mode and observe logs:**

```bash
python server.py 2>server.log
```

**Run the CLI against a test server:**

```bash
python cli.py onboard test-server --transport stdio --command python --args '["<YOUR_TEST_SERVER>.py"]'
python cli.py list test-server
python cli.py call test-server <tool_name>
```

**Adding a new MCP tool:**

1. Define an async (or sync) function in `server.py` decorated with `@mcp.tool()`.
2. Use `db.*` for persistence, `cm.call_tool_with_telemetry` for proxied execution.
3. Add a corresponding CLI command in `cli.py` with `@app.command()`.
4. Follow the existing pattern: validate input, check rate limit if it is a management operation, return `json.dumps(...)`.

**Logging:**

Every module uses `logging.getLogger(__name__)`. The server does not call `logging.basicConfig` itself - configure logging in your entry point or launcher script before importing the server. Example: `logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)s %(message)s")`.

---

## Testing

There is no automated test suite at this time. To validate behavior manually:

**Verify tool classification:**

```bash
python cli.py onboard test-server --transport stdio --command python --args '["<YOUR_MCP_SERVER>.py"]'
python cli.py list test-server --json
```

Check that `effect_class` values match what you expect for each tool.

**Verify injection scanning:**

Call a tool that returns text content. Inject a test pattern such as `"Ignore all previous instructions"` into the tool output (by modifying the wrapped server temporarily) and confirm the wrapper returns a quarantined response.

**Verify risk gating:**

```bash
python cli.py preflight test-server <high_risk_tool>
python cli.py call test-server <high_risk_tool>
# Should block and show alternatives menu
python cli.py call test-server <high_risk_tool> --approved
# Should execute
```

**Verify policy enforcement:**

```bash
python cli.py policy test-server <tool_name> --set block
python cli.py call test-server <tool_name>
# Should return policy_blocked immediately
python cli.py policy test-server <tool_name> --set clear
```

---

## Deployment

### Local (stdio with Claude Desktop)

Set the absolute path in `claude_desktop_config.json` as shown in the MCP Integration section. No additional setup is needed.

### Local HTTP server

```bash
MCP_TRANSPORT=streamable_http \
MCP_HOST=127.0.0.1 \
MCP_PORT=8000 \
MCP_AUTH_TOKEN=<your_secret_token> \
ANTHROPIC_API_KEY=<your_key> \
python server.py
```

### Container

A `Dockerfile` is not included. A minimal setup:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
ENV MCP_TRANSPORT=streamable_http
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000
EXPOSE 8000
CMD ["python", "server.py"]
```

Pass `MCP_AUTH_TOKEN`, `MCP_DB_ENCRYPTION_KEY`, and API keys as container environment variables. Do not bake them into the image.

### Production considerations

- **Rate limiting** is in-process and resets on restart. For multi-replica deployments, replace the deque-based limiter with a shared store such as Redis.
- **Database** is a local SQLite file. For shared deployments, consider replacing with a networked database.
- **Bearer auth** covers the HTTP transport layer. For multi-tenant deployments, place an API gateway (nginx, Caddy, AWS API Gateway) in front and leave `MCP_AUTH_TOKEN` unset.
- **Logging** goes to stderr by default via Python's `logging` module. Redirect and aggregate as needed for your observability stack.
- **Database permissions** are set to owner-only (0o600) on POSIX systems. On Windows this is a no-op; use filesystem ACLs.

---

## Troubleshooting

**`Tool '<name>' not found on server '<id>'.`**
Run `python cli.py inspect <server_id>` to refresh the tool list from the live server.

**`Server '<id>' not registered.`**
Run `python cli.py register` or `python cli.py onboard` first.

**`Rate limit exceeded.`**
Management operations are limited to 10 calls per 60 seconds per server and 100 globally. Wait for the window to expire. For heavy automation, batch operations or increase limits in `server.py`.

**`URL targets a private or restricted address.`**
The SSRF filter blocked a private IP, localhost, or cloud metadata endpoint. This is intentional. If you are proxying a legitimate internal server over stdio instead, use the `stdio` transport.

**`Registering a shell interpreter with an eval flag is not permitted.`**
You tried to register `bash -c` or similar. Use a dedicated MCP server script as the command instead of a shell one-liner.

**LLM classification shows `confidence: 0%` for all tools.**
No LLM API key was found. Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY`. Classification falls back to rule-based when no key is available, which gives lower confidence on ambiguous tool names.

**Scan fails immediately with `confirm_authorized must be True`.**
The mcpsafety+ scanner requires explicit authorization before sending live probes. Pass `--yes` on the CLI or `confirm_authorized=True` on the MCP tool.

**`MCP_DB_ENCRYPTION_KEY is set but Fernet init failed.`**
The key is malformed. Regenerate it with:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Decryption failure logged at ERROR level.**
The encryption key changed after data was written (key rotation). The affected server's env and headers fields will read as empty until the data is re-written with the new key by re-registering the server.

---

## Security

**Secrets in arguments**
The wrapper redacts credential-shaped values (JWTs, API keys, PEM blocks, long hex and base64 blobs) from tool arguments before storing them. If a secret is detected in an argument, a warning is included in the telemetry response. Prefer setting secrets as environment variables on the wrapped server rather than passing them as tool arguments.

**Child process isolation**
When spawning stdio servers, the wrapper strips its own secrets (`MCP_AUTH_TOKEN`, `MCP_DB_ENCRYPTION_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `SNYK_TOKEN`, `MCP_SCANNER_API_KEY`, `MCP_SCANNER_LLM_API_KEY`) from the child process environment. Supply needed env vars explicitly via the `env` parameter in `register_server`.

**Input validation**
All server IDs, URLs, commands, and argument values are length-checked before storage. URLs are checked against the SSRF blocklist. Shell interpreters with eval flags are rejected at registration time.

**HTTP auth**
Set `MCP_AUTH_TOKEN` for any HTTP deployment. The token is compared with `hmac.compare_digest` to prevent timing attacks. Without a token, the server logs a warning and accepts all connections.

**Database**
Enable at-rest encryption with `MCP_DB_ENCRYPTION_KEY` to protect stored server credentials. The database file is set to `0o600` on POSIX systems.

**Argument scanning**
Every tool call argument is scanned for 20+ attack categories before the call is forwarded to the wrapped server. If an LLM key is available, flagged values are sent for a second-pass LLM verification to clear false positives. Blocked calls return a structured response showing exactly which argument triggered which category. Pass `args_scan_override=True` (or `--args-scan-override` on the CLI) to bypass after manual review.

**Injection quarantine**
Tool output flagged as a prompt injection attempt is stored in the database under the run ID but is never returned to the calling agent. The response contains a quarantine notice and the run ID for forensic review.

---

## Contributing

1. Fork the repository and create a branch from `main`.
2. Make your changes. Keep functions focused. Follow the existing pattern: validation first, then logic, then return `json.dumps(...)` for MCP tools.
3. Test manually using the CLI against a real or mock MCP server.
4. Open a pull request with a clear description of what changed and why.

Code standards:
- No inline comments unless the reason is non-obvious.
- No docstring blocks beyond the existing MCP tool docstrings (which are user-facing).
- Match the surrounding code style: `Optional[str]` type hints, `_log.warning/error` for operator-visible events, `_log.debug` for internal traces.

---

## License

`<LICENSE PLACEHOLDER>`

---

## Roadmap

- Automated test suite (unit tests for classifier, profiler, and security_utils; integration tests with a mock MCP server).
- Redis-backed rate limiting for multi-replica deployments.
- Schema drift detection: alert when a wrapped tool's input or output schema changes between runs.
- Web dashboard for server health, tool risk overview, and run history.
- `mcp-wrapper` as an installable package with a proper entry point.
