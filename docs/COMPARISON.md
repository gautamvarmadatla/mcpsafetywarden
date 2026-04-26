# MCP Safety Warden vs. The Ecosystem

## The Problem This Space is Solving

MCP is under active, documented attack. This is not theoretical.

**Vulnerability research (2025-2026):**
- Astrix scanned 5,200+ MCP servers: 88% require credentials; 53% use long-lived secrets (raw API keys, PATs); only 8.5% use modern OAuth.
- Endor Labs analyzed 2,614 implementations: 82% vulnerable to path traversal, 67% using code-injection-vulnerable APIs (CWE-94), 34% vulnerable to command injection.
- Queen's University analyzed 1,899 open-source servers: 7.2% contain general vulnerabilities; 5.5% exhibit MCP-specific tool poisoning.
- OX Security (April 2026): All official MCP SDKs (Python, TypeScript, Java, Rust) allow unsanitized user input to flow into command execution via STDIO. 150M+ downloads affected. Anthropic declined to patch; stated sanitization is developer responsibility.
- 30 CVEs filed in a 60-day window (mid-2025). 13 rated critical. CVE-2025-59536 (Claude Code configuration injection, CVSS 8.7), CVE-2025-53967 (Figma MCP command injection).

**Exploit probability (Endor Labs):**
- 1 MCP plugin in an agent: 9% exploitation probability
- 3 interconnected servers: 50%+
- 10 MCP plugins: 92%

**Academic benchmarks:**
- MCPTox (arxiv 2508.14925): 45 live MCP servers, 1,312 malicious test cases across 10 risk categories. o1-mini: 72.8% attack success rate. Claude-Sonnet: highest refusal but still under 3% block rate.
- Function Hijacking (arxiv 2604.20994): 70%-100% success rate across 5 models including reasoning variants. Universal adversarial functions work across multiple queries.

**Attack types that exist:**

| Attack | Mechanism | Research |
|---|---|---|
| Tool poisoning | Malicious instructions embedded in tool metadata (descriptions, parameters); invisible to users, visible to LLMs | Most prevalent and impactful client-side vulnerability (arxiv 2603.22489) |
| Rug pull | Tool updated silently after user approval; attacker establishes trust first, then weaponizes | Changes don't always trigger re-approval; requires definition version pinning |
| Indirect prompt injection (IPI) | Malicious instructions embedded in external data (documents, webpages, emails) that feed tool output | 85%+ success rate against SOTA defenses with adaptive strategies |
| Function hijacking | Universal adversarial functions force invocation of attacker-chosen tools | 70%-100% success, robust across domains and function sets (arxiv 2604.20994) |
| Log-to-leak | Forces agent to invoke malicious logging tool; exfiltrates data while maintaining task quality | Tested on GPT-4o, GPT-5, Claude-Sonnet-4 (OpenReview) |
| Cross-origin escalation | Malicious server injects descriptions that affect behavior with trusted services | Multi-server exploitation with single entry point |
| Confused deputy | OAuth flow vulnerability with static client IDs; tricks users into granting codes to attacker's server | Token theft, user impersonation |
| SSRF via args | Tool argument value resolves to internal cloud metadata endpoint or private IP | Affects any tool that makes network calls with caller-controlled URLs |
| Credential theft via output | Tool returns API keys, PATs, or PEM blocks in output that get logged or forwarded | Affects 53% of servers using long-lived secrets |

---

## Tool Taxonomy

There are five distinct categories of tools in this space. They solve different problems and should not be conflated.

| Category | What it does | Examples |
|---|---|---|
| **Access control gateways** | Routing, auth, RBAC: who can call what | Portkey, Obot, Composio, Lunar.dev MCPX, TrueFoundry, Kong AI Gateway, AWS AgentCore |
| **Security proxies** | Runtime interception: argument and output inspection, policy enforcement | mcp-firewall, MCPTrust, Invariant mcp-scan (proxy mode), this project |
| **Static scanners** | One-shot metadata analysis: tool descriptions, schemas, no live calls | Invariant mcp-scan (scan mode), mcp-shield, Cisco AI Defense, Snyk, Lakera Atlas |
| **Behavioral analysis** | Active live probing: sends real payloads to running servers | This project (5-stage pipeline), MCPSafetyScanner (arxiv 2504.03767) |
| **Academic / research tools** | Benchmarks, detection models, formal methods | MCP-Guard (arxiv 2508.10991), MindGuard (arxiv 2508.20412), ETDI (arxiv 2506.01333), Rennervate (arxiv 2512.08417) |

---

## Access Control Gateways

These solve the **authorization problem**: who is allowed to call which tools. They do not solve the **execution safety problem**: whether the arguments are safe, whether the output is trustworthy, or whether the tool is behaving as advertised.

| Capability | Portkey | Obot | Composio | Lunar.dev MCPX | TrueFoundry | Kong AI Gateway | AWS AgentCore |
|---|---|---|---|---|---|---|---|
| **Adoption signal** | 10,200 stars; 4T tokens/mo; Fortune 50 | $35M seed; MIT open source | $25M Series A; 100K+ developers | Gartner Representative Vendor 2024-2025 | Enterprise; $499/mo governance tier | Enterprise Kong platform | AWS managed service |
| **RBAC / access control** | Yes (enterprise) | Yes (Okta, Entra) | Yes (OAuth 2.1, SOC 2) | Yes (role-based profiles) | Yes (Okta, Azure AD) | Yes (OAuth 2.1) | Yes (IAM, Cognito) |
| **Argument scanning** | Partial (Akto plugin) | Partial (webhook filters) | Partial (format/range validation) | Partial (injection patterns) | No | Partial (WAF rules) | Partial (WAF) |
| **Output scanning** | Partial (PII redaction, Lasso integration) | No | Partial (PII redaction) | Partial (DLP, enterprise tier) | Partial (PII redaction) | No | No |
| **Per-tool risk classification** | No | No | No | Yes (4 tiers) | No | No | No |
| **Active live probing / pentest** | No | No | No | No | No | No | No |
| **Behavioral profiling from runs** | Partial (Prometheus metrics) | Partial (Prometheus metrics) | Partial (audit logs) | Partial (per-tool call metrics) | No | Partial (usage analytics) | Partial (CloudWatch) |
| **Alternatives on block** | No | No | No | No | No | No | No |
| **Output quarantine** | No | No | No | No | No | No | No |
| **SSO / identity provider** | Yes | Yes | Yes | Yes | Yes | Yes | Yes (Cognito) |
| **Pre-built integrations** | No | No | Yes (850+) | No | No | No | Yes (AWS services) |
| **Kubernetes-native** | No | Yes | No | Yes (Docker/K8s) | No | Yes | Yes |
| **Self-hosted / fully local** | Partial (VPC) | Yes | Partial (VPC, enterprise) | Yes | Partial (on-premise) | Partial | No (AWS only) |
| **Open source** | Partial | Yes (MIT) | No | Partial (core tier) | No | Partial | No |
| **Pricing** | $2,000-$5,000+/mo | Free / enterprise custom | Free to $499/mo | Free (OSS) / enterprise custom | $499/mo+ | Enterprise | Pay-per-use |

**What they all share:** Centralized routing, audit logging, bearer/OAuth token validation, RBAC at the server or tool level.

**What none of them do end-to-end:** Active live probing of tool behavior, output quarantine with run-ID forensics, per-argument scanning across 20+ attack categories, semantic safer-alternative ranking, behavioral profiling from proxied calls.

---

## Open-Source Security Proxies

These sit in the request path and inspect arguments and outputs. Closer peers to this project than the gateways above.

| Capability | **This project** | mcp-firewall | MCPTrust | Invariant mcp-scan |
|---|---|---|---|---|
| **Argument scanning** | 20+ categories; unicode normalization; URL decode (3 passes); base64 decode | 50+ patterns (SSRF, SQLi, CMDi, path traversal, IPI, CRLF, header injection) | No (allowlist only) | Yes (proxy mode) |
| **Output scanning** | 40+ patterns; base64 decode up to 50 attempts; LLM second-pass verification | 4 outbound checks (secrets, PII, exfil, custom policies) | No | Yes (proxy mode) |
| **LLM second-pass for false positive reduction** | Yes - regex hits verified by LLM (30s timeout, 0.50 confidence threshold); blocks on LLM error with explicit warning | No | No | No |
| **Output quarantine** | Yes - flagged output stored under run ID; never returned to caller; agent receives quarantine notice | No (drops or logs) | No | No |
| **Policy engine** | Per-tool permanent allow/block + runtime approval gate | OPA/Rego (full policy-as-code) | Lockfile-based allowlist | Guardrails YAML |
| **Audit trail** | SQLite with redacted args, output hashes, injection flags, latency | Ed25519 cryptographic hash chain | JSONL + OpenTelemetry; Ed25519/Sigstore | Standard logs |
| **Active pentest / live probing** | Yes - 5-stage agentic pipeline (Recon, Planner, Hacker, Auditor, Supervisor) | No | No | No |
| **Behavioral profiling** | Yes - p50/p95 latency, failure rate, output size, schema stability per tool | No | Partial (drift detection) | No |
| **Safer alternatives on block** | Yes - LLM semantic ranking by risk reduction and functional coverage | No | No | No |
| **External scanner integrations** | Cisco AI Defense, Snyk, Kali MCP, Burp Suite MCP | Community threat feed | No | No |
| **Rug pull / drift detection** | Partial - `check_server_drift` detects schema and tool-list changes with CRITICAL/HIGH/MEDIUM/LOW severity; no cryptographic attestation or CI integration | No | Yes - SHA-512/256 checksums, SLSA provenance attestation; fails CI on critical changes | Partial (scan mode) |
| **Compliance reporting** | No | DORA/FINMA/SOC 2 built-in | No | No |
| **Anti-spoofing** | No | No | Yes - ID translation; server never sees real host IDs | No |
| **Self-hosted / fully local** | Yes | Yes | Yes | Yes |
| **Open source** | Yes (Apache 2.0) | Yes | Yes | Yes |

**Key distinction from mcp-firewall:** mcp-firewall has broader policy-as-code (OPA/Rego), compliance reporting, and a cryptographic audit chain. This project has deeper behavioral analysis (live pentest pipeline), LLM-assisted false positive reduction, output quarantine with forensic run IDs, and a full behavior profile built from observed runs.

**Key distinction from MCPTrust:** MCPTrust is best for supply-chain integrity: locking tool definitions and detecting rug pulls via checksums. It does not do runtime argument scanning or output inspection. These are complementary, not competing.

**Key distinction from Invariant mcp-scan:** mcp-scan is a dual-mode tool: static scan of tool descriptions + proxy mode for runtime guardrails. It detects tool poisoning and cross-origin escalations in metadata. It does not run active probing, build behavioral profiles, or suggest alternatives.

---

## Static Scanners

These analyze tool metadata (names, descriptions, schemas) without calling any tools. Fast and safe to run; cannot detect behavior that diverges from advertised behavior.

| Tool | What it scans | Detections | Live calls | Open source |
|---|---|---|---|---|
| **Invariant mcp-scan (scan mode)** | Tool descriptions, schemas | Tool poisoning, rug pulls, cross-origin escalations, prompt injection in descriptions | No | Yes |
| **Cisco AI Defense** | Tool metadata + AST/behavioral analysis via LLM-as-judge | Behavioral mismatches between documented and actual intent; YARA pattern rules; AI BOM/catalog | No | Yes (CLI) |
| **Snyk (snyk-agent-scan)** | Tool names, descriptions, schemas | E001 prompt injection, E002 tool shadowing, E004 skill injection, E005 suspicious URLs, E006 malicious patterns, W007-W020 (19 checks total covering hardcoded secrets, credential handling, financial capabilities, destructive ops) | No | Yes |
| **mcp-shield** | Installed MCP server configurations | Tool poisoning, exfiltration channels, cross-origin escalation | No | Yes |
| **Lakera Atlas** | Tool descriptions and schemas | Prompt injection, data leaks, harmful content | No | No |
| **Zenguard MCP Server** | Runtime tool arguments and outputs | PII, prompt injection, secrets, topic detection, keyword detection | No (output scan) | No |

**Shared limitation:** Cannot catch a tool that advertises safe behavior but behaves maliciously at runtime. Static analysis of `description: "reads a file"` cannot determine whether the implementation also exfiltrates the content.

---

## Academic and Research Tools

These are not production tools; they define the attack surface and defense benchmarks that production tools should be measured against.

| Work | Focus | Key finding |
|---|---|---|
| **MCPSafetyScanner** (arxiv 2504.03767) | Agentic multi-stage auditor: adversarial sample generation + vulnerability research + report generation | Identifies RCE, credential theft, remote access compromise in live MCP servers |
| **MCPTox Benchmark** (arxiv 2508.14925) | 1,312 malicious test cases across 10 risk categories on 45 live servers | 72.8% attack success rate on o1-mini; Claude-Sonnet highest refusal but <3% block rate |
| **MCP-Guard** (arxiv 2508.10991) | Three-stage pipeline: static scan, E5 neural detector, LLM arbitrator | 96.01% accuracy; 89.07% F1-score on MCP-AttackBench (70,000+ samples) |
| **MindGuard** (arxiv 2508.20412) | Decision Dependence Graph (DDG) tracking; maps LLM reasoning as weighted directed graph | 94%-99% precision; 95%-100% attribution accuracy; <1 second latency |
| **ETDI** (arxiv 2506.01333) | Cryptographic tool definition pinning; OAuth 2.0 + OPA/Amazon Verified Permissions | Mitigates rug pull attacks via immutable versioned definitions + re-approval flows |
| **MCP-DPT** (arxiv 2604.07551) | Defense Placement Taxonomy across 6 MCP architectural layers | Current defenses are tool-centric but weak on transport and registry/supply-chain layers |
| **Rennervate** (arxiv 2512.08417) | Token-level IPI detection using attention features | Outperforms 15 commercial/academic IPI defenses across 5 LLMs; FIPI dataset (100K samples) |
| **Function Hijacking** (arxiv 2604.20994) | Universal adversarial functions that hijack tool selection | 70%-100% success regardless of context semantics; largely model-agnostic |
| **Log-to-Leak** (OpenReview) | Covert exfiltration via forced logging tool invocation | 4-component design space; tested on GPT-4o, GPT-5, Claude-Sonnet-4 across 5 real servers |

---

## Attack Vector Coverage Matrix

Which tool class covers which attack. "Full" means the tool actively detects and blocks the vector end-to-end. "Partial" means limited coverage or detection without blocking. "No" means the vector is out of scope.

| Attack vector | This project | mcp-firewall | MCPTrust | mcp-scan | Access control gateways | Static scanners |
|---|---|---|---|---|---|---|
| Prompt injection in tool args | Full (40+ patterns + LLM second-pass) | Full (50+ patterns) | No | Partial | Partial | No |
| Prompt injection in tool output | Full (40+ patterns + LLM second-pass + quarantine) | Partial (outbound policy) | No | Partial | Partial (PII only) | No |
| SSRF via args | Full (regex + SSRF category) | Full | No | No | Partial (WAF) | No |
| SQL / NoSQL injection in args | Full (sql_injection / nosql_injection categories) | Full | No | No | No | No |
| Command injection in args | Full (command_injection category) | Full | No | No | Partial (WAF) | No |
| Path traversal in args | Full | Full | No | No | Partial (WAF) | No |
| Base64-encoded attack payloads | Full (up to 50 decode attempts per output string) | Partial | No | No | No | No |
| Data exfiltration via output | Full (data_exfiltration category + credential redaction) | Full (secrets + DLP) | No | Partial | Partial (PII) | No |
| Tool poisoning (description injection) | Partial (Snyk/Cisco at scan time) | No | No | Full | No | Full |
| Rug pull (silent definition change) | Partial (check_server_drift detects schema/tool-list changes; no cryptographic attestation) | No | Full (checksum + SLSA attestation) | Partial | No | No |
| Indirect prompt injection from external data | Partial (output scan catches IPI strings in tool output) | Partial | No | Partial | No | No |
| Function hijacking (adversarial tool selection) | No | No | No | No | No | No |
| Log-to-leak (forced logging tool invocation) | Partial (output scan on logging tool response) | Partial | No | No | No | No |
| Behavioral divergence (tool lies about what it does) | Full (5-stage live probing pipeline) | No | No | No | No | No |
| Credential theft from output | Full (11-pattern credential detection; output quarantine) | Full (secrets detection) | No | Partial | Partial | No |
| Cross-origin escalation | Partial (Snyk/Cisco at scan time) | No | No | Full | No | Partial |
| OAuth confused deputy | No | No | No | No | Partial (gateway auth) | No |
| Supply chain / rug pull | No | No | Full | Partial | No | No |
| Runtime behavioral anomaly | Full (behavioral profile; failure rate; latency deviation) | No | Partial (drift) | No | Partial (metrics) | No |

---

## Where This Project Is Uniquely Differentiated

**1. Active live probing with real security tool integration**

No other production tool actively probes a live MCP server with real payloads and generates exploitation scenarios. The 5-stage pipeline (Recon, Planner, Hacker, Auditor, Supervisor) sends actual tool calls, observes actual responses, and produces finding reports with severity levels, exploitation scenarios, and remediation steps.

- Recon stage: LLM maps attack surface across 10 capability categories, parameter attack vectors, tool relationships, composition risks, and high-value targets.
- Planner stage: Generates prioritized hypotheses (H001...) with concrete payloads and chaining sequences (C001...) grounded in actual tool schemas.
- Hacker stage: Agentic loop up to 20 turns, 5 tool calls per turn, 30s timeout per call, 8 KB output cap. Dispatches to Anthropic, OpenAI, Gemini, or Ollama.
- Auditor stage: Validates findings, ranks severity, enriches with CVE/Arxiv/DuckDuckGo/HackerNews research.
- Supervisor stage: Deduplicates, resolves disagreements, emits coverage_gaps, false_positives, audit_metadata, confirmed findings.

When a Kali Linux MCP server is registered, Recon runs real nmap quick_scan (60s), vulnerability_scan (90s), and traceroute (30s) against the target before the LLM analyzes schemas, giving the Planner actual port and service data instead of guessing from tool names. This is the only gateway or proxy that does this.

When a Burp Suite MCP server is registered, the Hacker stage sends three raw HTTP/1.1 probes (malformed JSON body, missing Content-Type, oversized method field), triggers GenerateCollaboratorPayload + GetCollaboratorInteractions for blind SSRF detection (Pro), and pulls GetScannerIssues (Pro). Burp proxy history (GetProxyHttpHistoryRegex) feeds the Auditor as raw request/response evidence for every finding it validates. No other tool does this.

**2. LLM second-pass for false positive reduction**

Argument and output scanning is two-pass: regex hits go to an LLM for confirmation with a 0.50 confidence threshold and 30s timeout. If the LLM call fails or is unavailable, the regex hit blocks with an explicit warning (not silently passed through). This is the distinction: regex-only scanning has high false positive rates on legitimate complex arguments (SQL queries, templates, XML payloads). LLM verification clears legitimate uses while keeping real blocks.

**3. Output quarantine with forensic run IDs**

Other tools redact PII from output. This project treats flagged output differently: the raw output is stored in the database under the run ID for forensic review and is never returned to the calling agent. The agent receives a quarantine notice with the run ID. This breaks the attack chain for prompt injection via tool output: the injected instruction never reaches agent context, and the operator can retrieve the quarantined content for analysis.

**4. Behavioral profiling from observed runs**

Every proxied call updates per-tool statistics: p50/p95 latency, failure rate, output size distribution (p95 in bytes), schema stability (most common output schema hash / total). These feed back into preflight risk assessment and retry policy recommendations. Confidence increases with run count (each 5 runs adds up to +0.15, capped at 0.97). The profile improves automatically as more calls go through.

This means the risk assessment for a tool that has been called 500 times is materially more accurate than for a tool seen for the first time. No gateway or proxy in this list builds per-tool behavioral profiles from observed calls.

**5. LLM-ranked safer alternatives with functional coverage analysis**

When a tool is blocked, the LLM ranks other tools on the same server by risk reduction (HIGH/MEDIUM/LOW) and functional coverage (full/partial/limited), explaining what the agent gives up by switching. The ranked list is returned as a structured menu. No other tool in this category does this.

**6. Cisco AI Defense and Snyk in the same scanning workflow**

Integrates with two external security platforms accessible from a single command. Cisco AI Defense uses LLM-as-judge to compare a tool's documented intent against actual behavior using AST analysis and YARA rules, producing an AI BOM for the MCP server. Snyk checks 19 error/warning codes covering prompt injection, tool shadowing, hardcoded secrets, credential handling, destructive capabilities, and more. Both are invoked via `scan` and `onboard` commands.

**7. Mandatory gateway enforcement model**

When only the wrapper is registered in Claude Desktop (not the underlying servers), Claude has no direct path to any server. Every call must go through safe_tool_call, making the wrapper a mandatory enforcement point. This is a deployment pattern, not a software feature, but it is documented and the CLI supports it.

---

## Where Others Are Ahead

**Team RBAC and SSO**

Portkey, Obot, Composio, Lunar.dev, TrueFoundry, Kong, and AWS all support multi-user access control with enterprise identity providers (Okta, Azure AD, SAML, Cognito). This project has no user management; it is single-operator.

**Supply chain integrity and rug pull detection**

MCPTrust has SHA-512/256 checksums, SLSA provenance attestation, lockfile-based capability allowlisting, and CI integration that fails builds on critical changes. This project has partial coverage: `check_server_drift` detects schema and tool-list changes with CRITICAL/HIGH/MEDIUM/LOW severity levels (tool removed, parameter type changed, description changed, new tool added). It does not provide cryptographic attestation, supply-chain provenance, or CI blocking.

**Compliance reporting**

mcp-firewall generates DORA/FINMA/SOC 2 compliance reports out of the box. This project's audit trail is SQLite-based with redacted args and run IDs but produces no compliance reports.

**Policy-as-code flexibility**

mcp-firewall supports full OPA/Rego policies for arbitrary logic (agent identity, RBAC, dangerous sequences, egress control). This project supports per-tool allow/block policies and a hardcoded risk gate but not Rego-level programmability.

**Pre-built integrations**

Composio ships 850+ pre-built MCP server integrations. This project requires manual registration of each server.

**Kubernetes and horizontal scale**

Obot is Kubernetes-native. This project runs as a single process with in-process rate limiting (resets on restart) and a local SQLite database. For multi-replica deployments, the rate limiter would need Redis and the database a networked store.

**Managed cloud hosting**

Portkey, Composio, and TrueFoundry offer managed SaaS hosting. This project is self-hosted only.

**Neural injection detection**

MCP-Guard (arxiv 2508.10991) uses a fine-tuned E5 model achieving 96.01% accuracy on 70,000+ samples. MindGuard (arxiv 2508.20412) uses Decision Dependence Graph tracking with 94%-99% precision and <1 second latency. These are research systems, not production packages, but they represent the direction the field is heading. This project uses regex + LLM verification, which is more interpretable but likely lower precision on the benchmark they measure.

**Rug pull defense**

Neither this project nor most commercial gateways solve the rug pull problem. MCPTrust and ETDI (arxiv 2506.01333) are the current state of the art here.

---

## Summary

| If you need... | Best fit |
|---|---|
| Who can call what, across a team, with SSO | Portkey, Obot, Lunar.dev MCPX, Kong AI Gateway |
| Pre-built integrations (850+) | Composio |
| Policy-as-code with OPA/Rego | mcp-firewall |
| Supply chain integrity + rug pull detection | MCPTrust |
| Static metadata scan for tool poisoning | Invariant mcp-scan, mcp-shield, Snyk |
| Active live probing of server behavior | This project |
| Runtime arg + output interception with LLM verification | This project, mcp-firewall |
| Behavioral profiles built from observed calls | This project |
| Safer alternatives when a tool is blocked | This project |
| Kali + Burp integration in a pentest pipeline | This project |
| Managed cloud hosting | Portkey, Composio, TrueFoundry |
| AWS-native deployment | AWS AgentCore Gateway |

**The core distinction:**

Authorization tools solve the question: *is this caller allowed to invoke this tool?*

Runtime security tools solve the question: *are these arguments safe, and can this output be trusted?*

Behavioral analysis tools solve the question: *does this tool do what it claims to do?*

Most production deployments need answers to all three questions. The access control gateways have the first well-covered. This project focuses on the second and third: the layer that currently has the least production tooling and where the MCPTox benchmark shows attack success rates above 70%.
