# Tool Reference

Complete reference for all 18 MCP tools exposed by mcpsafetywarden.

## Quick reference

| Tool | Category | What it does |
|---|---|---|
| [`onboard_server`](#onboard_server) | Setup | Register + inspect + security scan in one call |
| [`register_server`](#register_server) | Setup | Register a server; optionally auto-inspect |
| [`inspect_server`](#inspect_server) | Setup | Refresh tool list and profiles |
| [`list_servers`](#list_servers) | Inspection | List all registered servers |
| [`list_server_tools`](#list_server_tools) | Inspection | List tools on a server with summary profiles |
| [`get_tool_profile`](#get_tool_profile) | Inspection | Full behavior profile with observed stats |
| [`get_run_history`](#get_run_history) | Inspection | Recent execution history for a tool |
| [`preflight_tool_call`](#preflight_tool_call) | Risk | Risk assessment without execution |
| [`safe_tool_call`](#safe_tool_call) | Execution | Execute with risk gating and alternatives |
| [`get_retry_policy`](#get_retry_policy) | Execution | Retry and timeout recommendations |
| [`suggest_safer_alternative`](#suggest_safer_alternative) | Execution | LLM-ranked safer substitutes |
| [`run_replay_test`](#run_replay_test) | Execution | Idempotency test (calls tool twice) |
| [`set_tool_policy`](#set_tool_policy) | Policy | Permanent allow/block policy for a tool |
| [`security_scan_server`](#security_scan_server) | Scanning | Live security audit of a server |
| [`scan_all_servers`](#scan_all_servers) | Scanning | mcpsafety+ pipeline across all servers |
| [`get_security_scan`](#get_security_scan) | Scanning | Latest stored scan report |
| [`check_server_drift`](#check_server_drift) | Diagnostics | Detect schema and tool-list drift against stored baseline |
| [`ping_server`](#ping_server) | Diagnostics | Reachability check with latency |

## Setup

### `onboard_server`

One-shot onboarding: registers the server, inspects its tools, and runs a security scan. Equivalent to calling `register_server` -> `security_scan_server` in sequence.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | Unique identifier for this server |
| `transport` | string | Yes | `"stdio"`, `"sse"`, or `"streamable_http"` |
| `command` | string | stdio only | Executable to launch (e.g. `"python"`) |
| `args` | list | No | Arguments for the command (e.g. `["server.py"]`) |
| `url` | string | sse/http only | Server URL |
| `env` | object | No | Extra environment variables for the child process |
| `headers` | object | No | HTTP headers for sse/streamable_http |
| `scan_provider` | string | No | LLM provider for the security scan (`"anthropic"`, `"openai"`, `"gemini"`, `"ollama"`, `"cisco"`, `"snyk"`) |
| `scan_model` | string | No | Model ID override for the scan provider |
| `scan_api_key` | string | No | API key override (prefer env vars in production) |
| `github_url` | string | No | GitHub URL of the server's source repository; enables source-code scanning layers during security scans |
| `confirm_scan_authorized` | bool | No | Must be `true` to authorize active probing with all providers including `cisco` and `snyk` (default `false`) |

**Returns** JSON with `server_id`, `register` result, and `security_scan` result. If no LLM provider is detected, `security_scan` is skipped with a hint.

**Example**
```json
{
  "server_id": "my-server",
  "transport": "stdio",
  "command": "python",
  "args": ["server.py"],
  "scan_provider": "anthropic",
  "confirm_scan_authorized": true
}
```

### `register_server`

Register a server for proxying without running a security scan. `auto_inspect` (default `true`) immediately connects and discovers tools.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | Unique identifier. Must not contain `"::"`. Max 256 chars. |
| `transport` | string | Yes | `"stdio"`, `"sse"`, or `"streamable_http"` |
| `command` | string | stdio only | Executable path or name |
| `args` | list | No | Command arguments. Max 50 entries, each max 1024 chars. |
| `url` | string | sse/http only | Server URL. SSRF-checked; private IPs and cloud metadata endpoints are blocked. |
| `env` | object | No | Key-value pairs overlaid onto the parent env (minus wrapper secrets) for the child process |
| `headers` | object | No | HTTP headers sent with every request. Max 20 pairs. |
| `auto_inspect` | bool | No | Discover and classify tools immediately (default `true`) |
| `classify_provider` | string | No | LLM provider for tool classification during inspect |
| `classify_model` | string | No | Model ID for the classify provider |
| `classify_api_key` | string | No | API key override |
| `github_url` | string | No | GitHub URL of the server's source repository; used by source-code scanning layers during security scans |

**Returns** JSON with `registered`, `transport`, and (if `auto_inspect`) `tools_discovered` and a `tools` array with `name`, `effect_class`, `confidence` for each tool.

**Security constraints enforced at registration**
- `server_id` must not contain `::`
- URL must pass SSRF check (no private IPs, loopback, cloud metadata endpoints)
- `stdio` + shell interpreter (`bash`, `sh`, `powershell`, etc.) + eval flag (`-c`, `/c`, `-e`) is rejected

### `inspect_server`

Reconnect to a registered server, refresh its tool list, re-classify all tools, and update stored profiles. Call after updating the wrapped server.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | Server to inspect |
| `classify_provider` | string | No | LLM provider; auto-detected from env vars if omitted |
| `classify_model` | string | No | Model ID override |
| `classify_api_key` | string | No | API key override |

**Returns** JSON with `server_id`, `tools_discovered`, and `tools` array.

## Inspection

### `list_servers`

List all registered servers.

**Parameters** None.

**Returns** JSON array. Each entry: `server_id`, `transport`, `tool_count`, `registered_at`.

### `list_server_tools`

List all known tools for a server with summarised behavior profiles.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | Server to query |

**Returns** JSON with `server_id` and `tools` array. Each tool: `name`, `description` (first 100 chars), `effect_class`, `retry_safety`, `destructiveness`, `run_count`, `confidence`.

### `get_tool_profile`

Get the full behavior profile for a tool including all observed metrics.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `tool_name` | string | Yes | |

**Returns** JSON with `tool_id`, `server_id`, `tool_name`, and `profile`. The profile includes:

| Field | Description |
|---|---|
| `effect_class` | `read_only`, `additive_write`, `mutating_write`, `external_action`, or `destructive` |
| `retry_safety` | `safe`, `caution`, or `unsafe` |
| `destructiveness` | `none`, `low`, `medium`, or `high` |
| `open_world` | Whether the tool makes calls outside the local system |
| `output_risk` | Risk level of the tool's output content |
| `latency_p50_ms` / `latency_p95_ms` | Latency percentiles from observed runs |
| `failure_rate` | Fraction of calls that returned a tool error |
| `output_size_p95_bytes` | 95th-percentile output size |
| `schema_stability` | How stable the tool's output schema is across runs (0-1) |
| `confidence` | Per-field confidence map |
| `evidence` | List of signals that informed the classification |
| `run_count` | Total calls proxied through the wrapper |

### `get_run_history`

Recent execution history for a tool: timestamps, latency, success/fail, injection warnings.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `tool_name` | string | Yes | |
| `limit` | int | No | Max rows to return (1-200, default 20) |

**Returns** JSON with `server_id`, `tool`, and `runs` array. Each run: `run_id`, `timestamp`, `success`, `is_tool_error`, `latency_ms`, `output_size`, `output_schema_hash`, `output_preview`, `notes`.

## Risk assessment

### `preflight_tool_call`

Get a behavioral risk assessment for a tool before executing it.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `tool_name` | string | Yes | |
| `args` | object | No | Reserved for future arg-aware analysis |
| `auto_scan_provider` | string | No | If no security scan exists yet, run one automatically. Accepts `"anthropic"`, `"openai"`, `"gemini"`, `"cisco"`, `"snyk"`. The combined `"mcpsafety+"` string is not a valid value here - pass the specific provider name (`"anthropic"`, etc.) directly. For the full authorized 5-stage pipeline, use `security_scan_server` with `confirm_authorized=true`. |
| `auto_scan_model` | string | No | Model override for the auto-scan |
| `auto_scan_api_key` | string | No | API key for the auto-scan provider |
| `llm_provider` | string | No | Provider for on-demand tool classification if no profile exists yet |
| `llm_model` | string | No | |
| `llm_api_key` | string | No | |

**Behavior**
- Auto-scan runs once on first preflight per server; subsequent calls reuse the stored scan.
- Auto-scan is protected by a per-server lock: concurrent preflight calls cannot trigger duplicate scans.
- Auto-scan has a 60-second hard timeout; failures are non-fatal (scan is skipped with a warning).

**Returns** JSON assessment:

| Field | Description |
|---|---|
| `assessment.likely_effect` | Predicted effect class |
| `assessment.likely_retry_safety` | Predicted retry safety |
| `assessment.likely_destructiveness` | Predicted destructiveness level |
| `assessment.risk_level` | Combined risk: `low`, `medium-low`, `medium`, `high`, or `unknown` |
| `assessment.approval_recommended` | `true` if the caller should review before proceeding |
| `assessment.open_world_exposure` | Whether the tool reaches outside the local system |
| `assessment.expected_latency_band` | Human-readable latency estimate |
| `assessment.output_size_risk` | Predicted output volume risk |
| `security` | Latest security scan finding for this specific tool (if any) |
| `observed_stats` | Latency percentiles, failure rate, output size (present only when `run_count >= 1`) |
| `confidence` | Per-field confidence scores |
| `evidence` | Classification signals |
| `data_source` | `"observed"` (>=5 runs) or `"inferred"` |
| `warning` | Present when effect_class confidence is below 50%; message includes observed run count |

## Execution

### `safe_tool_call`

End-to-end safe tool execution with risk gating and alternative selection.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `tool_name` | string | Yes | |
| `args` | object | No | Arguments to pass to the tool |
| `approved` | bool | No | Bypass the risk gate for a tool you have reviewed (default `false`) |
| `use_alternative` | string | No | Name of an alternative tool to execute instead |
| `show_more_options` | bool | No | Return the "proceed anyway / abort" options menu |
| `args_scan_override` | bool | No | Skip argument safety scanning (default `false`) |
| `llm_provider` | string | No | Provider for classification and alternative ranking |
| `llm_model` | string | No | |
| `llm_api_key` | string | No | |

**Call flow**

```
1. use_alternative set -> verify alternative, scan args -> execute -> scan output -> return result.
2. show_more_options set -> return proceed/abort options menu.
3. Check permanent policy (allow/block).
4. Run preflight assessment.
5a. Low / medium-low risk -> scan args -> execute -> scan output -> return result.
5b. Medium / high risk, not approved -> rank alternatives -> return blocked response with numbered menu.
5c. Approved -> scan args -> execute -> scan output -> return result.
```

**Argument scanning:** every value is checked against 20+ attack categories (SSRF, SQL/NoSQL/LDAP/XPath injection, command injection, path traversal, XXE, template injection, prompt injection, deserialization payloads, base64-encoded variants). When an LLM key is available, flagged values get a second-pass LLM verification to clear false positives.

**Injection quarantine:** tool output is scanned with 40+ regex patterns and then an LLM deep scan. Flagged output is stored under the run ID but never returned; the response contains a quarantine notice instead.

**Returns (low-risk or approved)**
```json
{
  "result": [...],
  "telemetry": {
    "run_id": 42,
    "success": true,
    "is_tool_error": false,
    "latency_ms": 138.4,
    "output_size_bytes": 512,
    "output_truncated": false,
    "error": null,
    "injection_warning": null,
    "args_secret_warning": null
  }
}
```

**Returns (blocked)**
```json
{
  "blocked": true,
  "reason": "approval_required",
  "tool": "delete_file",
  "risk_level": "high",
  "preflight": { ... },
  "alternatives": [
    {
      "option": 1,
      "tool": "list_files",
      "risk_reduction": "HIGH",
      "functional_coverage": "partial",
      "what_it_loses": "Cannot delete, only read.",
      "why_safer": "read-only, no destructive capability",
      "how": "Re-call safe_tool_call with use_alternative='list_files'"
    },
    {
      "option": 2,
      "tool": "More options",
      "how": "Re-call safe_tool_call with show_more_options=True"
    }
  ]
}
```

**Returns (quarantined)**
```json
{
  "quarantined": true,
  "security_warning": "Prompt injection detected in tool output ...",
  "message": "Tool output was quarantined and not returned. Raw output stored under run_id=42 for forensic review.",
  "telemetry": { ... }
}
```

### `get_retry_policy`

Recommended retry policy for a tool based on its behavior profile.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `tool_name` | string | Yes | |
| `llm_provider` | string | No | Provider for on-demand classification if no profile exists |
| `llm_model` | string | No | |
| `llm_api_key` | string | No | |

**Returns**

| Field | Description |
|---|---|
| `retry_safety` | `safe`, `caution`, `unsafe`, or `unknown` |
| `recommended_policy` | `retry_freely`, `retry_once_with_caution`, `no_retry`, or `unknown_retry_with_caution` |
| `max_retries` | Suggested maximum retry count |
| `backoff_strategy` | `exponential`, `fixed_2s`, `fixed_5s`, or `none` |
| `suggested_timeout_ms` | 3x p95 latency, or `null` if no data |
| `observed_failure_rate` | Fraction of failed calls (present only when run_count > 0) |
| `confidence` | Confidence score for the retry_safety field |
| `based_on_runs` | Number of observed runs used |

### `suggest_safer_alternative`

Find lower-risk alternatives to a tool on the same server.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `tool_name` | string | Yes | |
| `llm_provider` | string | No | Provider for semantic matching; auto-detected if omitted |
| `llm_model` | string | No | |
| `llm_api_key` | string | No | |

**Behavior**
- LLM path (default): semantic matching across all server tools, finds functionally similar substitutes even when names differ, ranks by risk reduction, explains capability tradeoffs.
- Rule-based fallback (no LLM): looks for `read_only` tools with a similar name stem and no HIGH security flag.
- Returns immediately with a message if the target tool is already `read_only` with no HIGH security finding.

**Returns**

| Field | Description |
|---|---|
| `tool` | The queried tool name |
| `current_effect` | Its current effect class |
| `current_security_flag` | Its current security risk level (if any) |
| `method` | `"llm"` or `"rule_based"` |
| `alternatives` | Array of alternatives, each with `tool`, `effect_class`, `risk_reduction` (`HIGH`/`MEDIUM`/`LOW`), `functional_coverage` (`full`/`partial`/`limited`), `why_safer`, `what_it_achieves`, `what_it_loses`, `confidence` |

### `run_replay_test`

Test idempotency by calling a tool twice with identical args and comparing outputs. Requires `approved=true` when any of the following is true: effect is not `read_only`, destructiveness is `high` or `medium`, or `approval_recommended` is set in the preflight assessment.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `tool_name` | string | Yes | |
| `args` | object | No | Arguments to pass on both calls |
| `approved` | bool | No | Required for non-read-only or flagged tools (default `false`) |

**Returns (executed)**

| Field | Description |
|---|---|
| `verdict` | `"likely_idempotent"` or `"likely_not_idempotent"` |
| `outputs_identical` | Whether both calls returned the same content |
| `call1` / `call2` | `success` and `latency_ms` for each call |
| `interpretation` | Human-readable summary |
| `burp_proxy_traffic` | HTTP traffic from both calls (present only if a Burp Suite MCP server is registered) |

**Returns (approval required)**
```json
{
  "blocked": true,
  "reason": "approval_required",
  "risk_level": "high",
  "message": "'delete_file' will be called TWICE (risk: high, effect: destructive). Re-call with approved=True to proceed.",
  "preflight": { ... }
}
```

## Policy

### `set_tool_policy`

Set a permanent execution policy for a tool, overriding the normal preflight flow.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `tool_name` | string | Yes | |
| `policy` | string or null | No | `"allow"`, `"block"`, or `null` to clear |

**Policy semantics**

| Policy | Effect |
|---|---|
| `"allow"` | Always execute without preflight. Argument scanning still runs unless `args_scan_override=true`. |
| `"block"` | Never execute, regardless of approval. Returns `policy_blocked` immediately. |
| `null` | Remove any existing policy; resume normal preflight-based risk gating. |

**Returns** JSON with `server_id`, `tool`, and `policy` (or `"cleared"`).

## Security scanning

### `security_scan_server`

Run a live security audit on a registered server's tools. Results are stored and automatically surfaced in future `preflight_tool_call` responses.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `provider` | string | No | See provider table below; omit or set to `"all"` to run all available providers |
| `background` | bool | No | Run scan in background and return immediately (default `true`) |
| `model_id` | string | No | Model override (mcpsafety+ providers only) |
| `api_key` | string | No | API key override |
| `confirm_authorized` | bool | Yes | Must be `true`; confirms you own and are authorized to test this server. Required for all providers including `cisco` and `snyk`. |
| `github_url` | string | No | GitHub URL of the server's source repository; enables entropy, AST taint flow, and rug-pull detection layers |
| `allow_destructive_probes` | bool | No | Enable path traversal, command injection, credential file probes (default `false`; safe edge-case inputs only) |
| `skip_web_research` | bool | No | Skip DuckDuckGo/HackerNews/Arxiv CVE research (default `true`) |
| `scan_timeout_s` | int | No | Hard timeout for the entire scan in seconds (default 300, clamped to 30-3600) |

**Providers**

| Provider | Type | What it does |
|---|---|---|
| `"anthropic"` | mcpsafety+ | 5-stage pipeline: Recon -> Planner -> Hacker (live probing) -> Auditor (CVE research) -> Supervisor (final report). Requires `confirm_authorized=true`. |
| `"openai"` | mcpsafety+ | Same pipeline via OpenAI |
| `"gemini"` | mcpsafety+ | Same pipeline via Gemini |
| `"ollama"` | mcpsafety+ | Same pipeline via local Ollama (set `OLLAMA_MODEL`) |
| `"cisco"` | Static | AST taint analysis, YARA rules, optional Cisco cloud ML engine. No live probing. |
| `"snyk"` | Static | Prompt injection, tool shadowing, toxic data flows, hardcoded secrets. No live probing. |

**mcpsafety+ pipeline stages**

| Stage | Description |
|---|---|
| Kali Recon | If a Kali MCP server is registered, runs nmap and traceroute before stage 0 |
| Stage 0 Recon | LLM analysis of tool metadata, schemas, and descriptions |
| Stage 0b Planner | Generates targeted attack hypotheses grounded in recon data |
| Stage 1 Hacker | Live tool probing with safe (and optionally destructive) payloads; Burp Suite probes run here if registered |
| Stage 2 Auditor | CVE/Arxiv research; validates findings; adds Burp proxy evidence |
| Stage 3 Supervisor | Synthesizes final report, ranks findings, identifies coverage gaps |

**Returns** JSON scan report with:

| Field | Description |
|---|---|
| `scan_id` | Database row ID for this scan |
| `overall_risk_level` | Worst finding across all tools: `HIGH`, `MEDIUM`, `LOW`, or `NONE` |
| `summary` | Human-readable scan summary |
| `tool_findings` | Array of per-tool findings, each with `name`, `risk_level`, `risk_tags`, `finding`, `exploitation_scenario`, `remediation`, `probes` |
| `server_level_risks` | Risks not tied to a specific tool (SSRF exposure, auth weaknesses, etc.) |

### `scan_all_servers`

Run the mcpsafety+ pipeline against all registered servers (or a specified subset) sequentially. Each server's result is stored individually. Only mcpsafety+ providers are supported (`cisco` and `snyk` are not accepted).

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `provider` | string | Yes | `"anthropic"`, `"openai"`, `"gemini"`, or `"ollama"` |
| `model_id` | string | No | |
| `api_key` | string | No | |
| `confirm_authorized` | bool | Yes | Must be `true` |
| `allow_destructive_probes` | bool | No | Default `false` |
| `skip_web_research` | bool | No | Default `true` |
| `scan_timeout_s` | int | No | Per-server timeout in seconds (default 300, clamped to 30-3600) |
| `server_ids` | list | No | Subset of server IDs to scan; scans all registered servers if omitted |

**Returns** Combined report with `overall_risk_level`, `server_results` map (keyed by `server_id`), and `skipped_servers` (servers with no registered tools).

### `get_security_scan`

Retrieve the latest security scan report for a registered server.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |

**Returns** The latest stored scan report as JSON, or an error with a hint to run `security_scan_server` first.

## Diagnostics

### `check_server_drift`

Connects to the live server, re-enumerates all tools, and compares against the stored baseline from the last `inspect_server` call.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |
| `update_baseline` | bool | No | Update stored baseline after reporting drift (default `true`). Set to `false` to audit without modifying the baseline. |

**Change severities**

| Severity | Trigger |
|---|---|
| `CRITICAL` | Tool removed (callers will break) |
| `HIGH` | Parameter removed or type changed |
| `MEDIUM` | Description changed (prompt-injection risk) or new required parameter |
| `LOW` | New optional parameter or new tool added |

**Returns** JSON with `drift_detected` (bool), `overall_severity`, and `findings` array.

### `ping_server`

Check if a registered server is reachable and measure round-trip latency. For `sse` and `streamable_http` servers, also runs Kali `quick_scan` and `traceroute` against the target host if a Kali MCP server is registered.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `server_id` | string | Yes | |

**Returns**

| Field | Description |
|---|---|
| `server_id` | |
| `status` | `"reachable"`, `"timeout"`, or `"unreachable"` |
| `latency_ms` | Round-trip time in milliseconds |
| `error` | Error message (present only when `status` is `"unreachable"`) |
| `network_scan` | Kali nmap + traceroute output (present only for sse/streamable_http when Kali is registered) |

## Rate limits

Two independent rate limiters protect the server.

**Management operations** (`register_server`, `inspect_server`, `check_server_drift`, `run_replay_test`, `security_scan_server`, `scan_all_servers`):
- 10 calls per 60 seconds per server ID
- 100 calls per 60 seconds globally across all server IDs
- Defined in `server.py`: `_MGMT_RATE_LIMIT_MAX`, `_GLOBAL_RATE_LIMIT_MAX`

**Tool calls** via `safe_tool_call`:
- 20 calls per 60 seconds per tool (identified by `server_id::tool_name`)
- Defined in `client_manager.py`: `_RATE_LIMIT_MAX_CALLS`

Both limiters are in-process. For multi-replica deployments, replace with a shared store (e.g. Redis).

## Error responses

All tools return JSON. Errors follow a consistent shape:

```json
{ "error": "<message>", "hint": "<optional recovery suggestion>" }
```

Common errors:

| Error | Cause | Resolution |
|---|---|---|
| `Tool '<name>' not found on server '<id>'.` | Tool not yet discovered | Run `inspect_server` |
| `Server '<id>' not registered.` | Server not in database | Run `register_server` or `onboard_server` |
| `Rate limit exceeded.` | Too many calls in the window | Wait and retry |
| `URL targets a private or restricted address.` | SSRF filter blocked the URL | Use stdio transport for internal servers |
| `Registering a shell interpreter with an eval flag is not permitted.` | Security policy | Use a dedicated MCP server script |
| `confirm_authorized must be True` | All providers require explicit authorization | Pass `confirm_authorized=true` |
