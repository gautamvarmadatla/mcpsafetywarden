## Auxiliary Security Tool Integrations

The wrapper detects Kali and Burp by looking for registered servers whose `server_id` contains `"kali"` or `"burp"` (case-insensitive). Registration is the only setup step - once registered, the tools activate automatically on every scan, ping, and replay test.

### Kali Linux MCP (`ccq1/awsome_kali_MCPServers`)

Docker-based, Apache 2.0, no auth. Adds real network reconnaissance to the Recon stage and network data to `ping_server`.

**What it contributes:**

| Pipeline stage / tool | Kali tools called | What it adds |
|---|---|---|
| Recon (before Planner) | `quick_scan(target)`, `vulnerability_scan(target)`, `traceroute(target)` | Open ports, running services, OS fingerprint, network path - Planner uses this to craft targeted hypotheses |
| `ping_server` | `quick_scan(target)`, `traceroute(target)` | Network reachability detail beyond the MCP protocol ping (sse/streamable_http only - no network target for stdio) |

**Setup:**

```bash
# 1. Install Docker Desktop (if not already installed)
#    Windows: winget install Docker.DockerDesktop
#    macOS:   brew install --cask docker
#    Linux:   https://docs.docker.com/engine/install/

# 2. Clone and build the image
git clone https://github.com/ccq1/awsome_kali_MCPServers
cd awsome_kali_MCPServers
docker build -t kali-mcps:latest .

# 3. Onboard with the wrapper (server_id must contain "kali")
mcpsafetywarden onboard kali-mcp \
  --transport stdio \
  --command docker \
  --args '["run", "-i", "kali-mcps:latest"]'
```

Note: `vulnerability_scan` runs nmap vuln scripts which can take 60-90 seconds per target. On `scan-all` across many servers this adds up. Register only when you want network recon in your scans.

### Burp Suite MCP (`PortSwigger/mcp-server`)

Kotlin, GPL-3.0, no auth, runs as an SSE server on port 9876. Community edition tools run always; Pro-only tools (Collaborator, scanner) are tried and silently skipped on failure.

**What it contributes:**

| Pipeline stage / tool | Burp tools called | Edition | What it adds |
|---|---|---|---|
| Hacker (after LLM probing) | `SendHttp1Request` x3 | Community | Raw HTTP probes: malformed JSON body, missing Content-Type, oversized method field |
| Hacker | `GenerateCollaboratorPayload`, `GetCollaboratorInteractions` | Pro | Out-of-band DNS/HTTP callbacks - detects blind SSRF and blind injection |
| Hacker | `GetScannerIssues` | Pro | Automated active scanner findings against the MCP endpoint |
| Auditor | `GetProxyHttpHistoryRegex` | Community | Raw HTTP traffic evidence for every finding the Auditor validates |
| `run_replay_test` | `GetProxyHttpHistoryRegex` | Community | HTTP traffic captured during both tool calls, appended to the replay result |

**Setup:**

```bash
# 1. Install Burp Suite (Community or Professional)
#    Download from https://portswigger.net/burp/releases

# 2. Build the MCP extension JAR
git clone https://github.com/PortSwigger/mcp-server.git
cd mcp-server
./gradlew embedProxyJar
# produces build/libs/burp-mcp-all.jar

# 3. Load into Burp
#    Burp -> Extensions -> Add -> Java type -> select burp-mcp-all.jar
#    Then go to the "MCP" tab in Burp and enable the server.
#    SSE endpoint starts at http://127.0.0.1:9876/sse

# 4. Onboard with the wrapper (server_id must contain "burp")
mcpsafetywarden onboard burp-mcp \
  --transport sse \
  --url http://127.0.0.1:9876/sse
```

Note: Burp prompts for approval before sending each HTTP request to a new target. Pre-approve the target host in Burp's MCP tab under "Auto-approve targets" (e.g. `mcp.example.com`) to allow automated probes without a dialog. Without pre-approval, HTTP probes will timeout and be silently skipped.

### Snyk (`snyk-agent-scan`)

Python, Apache 2.0, requires a free Snyk account token. Connects to the target MCP server, lists its tools, and runs static analysis on the tool metadata (names, descriptions, schemas). It does **not** call any tools - it only reads what the server advertises.

**What it checks:**

| Code | Severity | Check |
|---|---|---|
| E001 | HIGH | Prompt injection strings in tool descriptions or schemas |
| E002 | HIGH | Tool shadowing (a tool impersonates another) |
| E004 | HIGH | Prompt injection embedded in skill definitions |
| E005 | HIGH | Suspicious download URLs in tool metadata |
| E006 | HIGH | Malicious code patterns in descriptions |
| W007 | HIGH | Insecure credential handling patterns |
| W008 | HIGH | Hardcoded secrets in tool metadata |
| W009 | MEDIUM | Direct financial execution capabilities |
| W011 | MEDIUM | Untrusted third-party content references |
| W012 | HIGH | Unverifiable external dependencies |
| W013 | MEDIUM | System service modification capabilities |
| W015 | MEDIUM | Untrusted content flows |
| W017 | MEDIUM | Sensitive data exposure patterns |
| W019 | MEDIUM | Destructive capabilities |
| W001 | LOW | Suspicious words |
| W014 | LOW | Missing skill documentation |
| W016 | LOW | Potential untrusted content |
| W018 | LOW | Workspace data exposure |
| W020 | LOW | Local destructive capabilities |

E001 (prompt injection) requires a Snyk token for Snyk's AI-based detection. All other checks run with the token present but also degrade gracefully if the token is invalid - structural and pattern-based checks are fully offline.

**How it runs:**

Snyk is invoked as a subprocess (`snyk-agent-scan`) with a temporary config JSON pointing at the target server. The binary opens its own live MCP connection, fetches the tool list, analyzes the metadata, and returns JSON findings. The wrapper normalizes these into its common findings format and stores them in the database, where they are automatically included in future `preflight_tool_call` responses.

**Setup:**

```bash
pip install snyk-agent-scan
```

Get a free token at [app.snyk.io/account](https://app.snyk.io/account). Set it as an environment variable:

```bash
export SNYK_TOKEN=snyk_uat.<your_token>
```

Or pass it directly on the scan command:

```bash
mcpsafetywarden scan my-server --provider snyk --api-key snyk_uat.<your_token> --yes
```

Snyk is included automatically when `--provider` is omitted or set to `all`, provided `snyk-agent-scan` is installed and `SNYK_TOKEN` is set.
