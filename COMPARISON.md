# MCP Safety Warden vs. The Market

Most MCP gateways solve the same problem: routing and access control. They sit in front of your MCP servers and decide who can call what. That is a governance problem.

This project solves a different problem: what happens at execution time. It intercepts every tool call, inspects every argument, runs the tool, inspects every output, and blocks or quarantines anything that looks dangerous — regardless of who made the call or whether they were authorized.

The distinction matters because authorization and safety are not the same thing. A fully authorized agent can still pass a prompt injection payload as an argument. A trusted server can still return output that hijacks the calling agent. Governance layers do not catch this. Runtime interception does.

---

## How the Top 5 Gateways Were Selected

Ranked by adoption: GitHub stars, funding, developer base, and enterprise market presence.

| # | Product | Signal |
|---|---|---|
| 1 | **Portkey** | 10,200 GitHub stars; 4 trillion tokens/month; Fortune 50 customers |
| 2 | **Obot** | $35M seed funding; MIT open source; Kubernetes-native |
| 3 | **Composio** | $25M Series A; 100,000+ developers; 850+ pre-built integrations |
| 4 | **Lunar.dev MCPX** | Gartner Representative Vendor (AI Gateways 2024-2025; MCP Gateways 2025) |
| 5 | **TrueFoundry** | Enterprise-grade; $499/month governance tier |

---

## Feature Comparison

| Capability | **This project** | Portkey | Obot | Composio | Lunar.dev MCPX | TrueFoundry |
|---|---|---|---|---|---|---|
| **Argument scanning before execution** (SSRF, SQL injection, command injection, path traversal, prompt injection, XXE, template injection, 20+ categories) | Yes | Partial (via Akto plugin) | Partial (custom webhook filters) | Partial (format/range validation only) | Partial (injection pattern detection) | No |
| **Output scanning + quarantine** | Yes - regex + LLM second-pass; output quarantined and never returned if flagged | Partial (PII redaction only) | No | Partial (PII redaction only) | Partial (DLP in enterprise tier only) | Partial (PII redaction only) |
| **Per-tool risk classification** | Yes - 5 classes: read_only, additive_write, mutating_write, external_action, destructive | No | No | No | Yes - 4 tiers: critical / high / medium / low | No |
| **Per-tool allow/block policies** | Yes - permanent allow, block, or clear per tool | No | Yes (RBAC) | Yes (action-level RBAC) | Yes (granular tool-level RBAC) | Yes (RBAC per MCP server) |
| **5-stage LLM pentest pipeline** | Yes - Recon, Planner, Hacker, Auditor, Supervisor; actively probes live server. Optional Kali MCP (nmap/traceroute enriches Recon) and Burp Suite MCP (raw HTTP probes + Collaborator OOB + scanner findings enrich Hacker; proxy history feeds Auditor) | No | No | No | No | No |
| **Behavioral profiling** | Yes - p50/p95 latency, failure rate, output size, schema stability per tool built from live runs | No | Partial (Prometheus metrics) | Partial (audit logs and error tracking) | Partial (Prometheus metrics per tool call) | No |
| **Safer alternative suggestions** | Yes - LLM ranks substitute tools by risk reduction and functional coverage when a tool is blocked | No | No | No | No | No |
| **Cisco AI Defense integration** | Yes | No | No | No | No | No |
| **Snyk integration** | Yes | No | No | No | No | No |
| **LLM-based tool classification** | Yes - rule-based + LLM weighted voting on every tool at inspection time | No | No | No | Partial (automated risk analysis) | No |
| **Mandatory gateway enforcement** | Yes - only the wrapper is added to Claude Desktop; all servers registered inside it; no direct path to any underlying server | No | No | No | No | No |
| **Self-hosted / fully local** | Yes - SQLite, no external dependencies, no data leaves the machine | Partial (VPC and private cloud options) | Yes (Docker / Kubernetes) | Partial (VPC option at enterprise tier) | Partial (open-source local tier) | Partial (on-premise option) |
| **Full CLI** | Yes - 16 commands covering all 17 MCP tools; --json flag on every command for scripting | No | No | No | No | No |
| **Team RBAC / SSO** | No | Yes (enterprise tier) | Yes (Okta, Entra) | Yes (OAuth 2.1, SOC 2) | Yes (role-based profiles) | Yes (Okta, Azure AD) |
| **Pre-built server integrations** | No - manual registration required | No | No | Yes - 850+ | No | No |
| **Kubernetes-native deployment** | No | No | Yes | No | No | No |
| **Pricing** | Free / open source | $2,000-$5,000+/mo for governance | Free (open source) | Free to $499/mo | Free (OSS) / Enterprise custom | $499/mo+ |

---

## Where This Project is Uniquely Differentiated

**5-stage active pentest pipeline with real security tool integration**
No other gateway actively probes the live server. The Recon -> Planner -> Hacker -> Auditor -> Supervisor pipeline sends real payloads, observes real responses, and produces a structured finding report with exploitation scenarios and remediation steps. Other gateways scan tool descriptions statically; this project tests tool behavior dynamically.

When a Kali Linux MCP server is registered, the Recon stage runs real nmap scans and traceroute against the target before the LLM analyzes schemas - giving the Planner actual port and service data instead of guesses from tool names. When a Burp Suite MCP server is registered, the Hacker stage sends raw HTTP-layer probes directly to the MCP endpoint (malformed JSON, missing headers, oversized payloads), triggers Collaborator out-of-band payloads for blind SSRF detection (Pro), and pulls automated scanner findings (Pro). Burp proxy history feeds the Auditor as raw request/response evidence for every finding it validates.

**Argument interception at 20+ categories**
Every argument value on every tool call is scanned before it is forwarded. The scan covers SSRF, SQL/NoSQL/LDAP/XPath injection, command injection, path traversal, XXE, template injection, prompt injection, deserialization payloads, null bytes, CRLF injection, header injection, Windows attack paths, and base64-encoded variants of all of the above. When an LLM key is set, regex hits go through a second-pass LLM verification to clear false positives before blocking.

**Output quarantine**
Other gateways redact PII from output. This project treats flagged output differently: it is stored in the database under a run ID for forensic review and never returned to the calling agent. The agent receives a quarantine notice instead. This prevents prompt injection attacks embedded in tool output from reaching the agent context.

**Safer alternative suggestions**
When a tool is blocked by the risk gate, the LLM ranks other tools on the same server by risk reduction and functional coverage, explaining what the agent gives up by switching. No other gateway does this.

**Behavioral profiling from live runs**
Every proxied call updates per-tool statistics: p50/p95 latency, failure rate, output size distribution, schema stability. These feed back into the preflight risk assessment and retry policy recommendations. The profile improves automatically as more calls are proxied.

**Cisco AI Defense + Snyk**
Integrates with two external security platforms that no other gateway in this list supports.

---

## Where Others Are Ahead

**Team RBAC and SSO**
Portkey, Obot, Composio, Lunar.dev, and TrueFoundry all support multi-user role-based access control with enterprise identity providers (Okta, Azure AD, SAML). This project has no user management - it is single-operator.

**Pre-built integrations**
Composio ships with 850+ pre-built MCP server integrations. This project requires manual registration of each server.

**Kubernetes and multi-replica deployment**
Obot is Kubernetes-native. This project runs as a single process with in-process rate limiting and a local SQLite database. It is not designed for horizontal scaling out of the box.

**Managed cloud hosting**
Portkey, Composio, and TrueFoundry offer managed SaaS hosting. This project is self-hosted only.

---

## Summary

If the problem is **who can access which tools across a team**, the established gateways (Portkey, Obot, Composio) are the right fit.

If the problem is **what those tools actually do when called, whether the arguments are safe, and whether the output can be trusted**, this project addresses that layer - one that none of the top five currently cover end-to-end.
