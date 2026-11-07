from typing import Any, Dict, List, Optional

from pydantic import Field

from ._tooling import ListOutput, ToolOutput

_ServerId = Field(None, description="Registered server ID, usable as server_id in other tools.")


class RegisterServerOutput(ToolOutput):
    registered: Optional[str] = Field(None, description="server_id that was registered.")
    transport: Optional[str] = Field(None, description="stdio | sse | streamable_http")
    tools_discovered: Optional[int] = Field(None, description="Number of tools found by auto_inspect.")
    tools: Optional[List[Any]] = Field(None, description="Discovered tools with their inferred classification.")
    credential_refs: Optional[Dict[str, Any]] = Field(
        None, description="Map of env/header keys whose secret values were replaced by cref_ identifiers."
    )
    credential_refs_note: Optional[str] = None
    inspect_error: Optional[str] = Field(None, description="Why auto_inspect failed; registration was rolled back.")


class InspectServerOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    tools_discovered: Optional[int] = None
    tools: Optional[List[Any]] = Field(None, description="Tools with effect_class, retry_safety, destructiveness.")
    drift: Optional[Dict[str, Any]] = Field(None, description="Changes since the previous baseline, if any.")


class DriftOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    checked_at: Optional[str] = Field(None, description="ISO-8601 timestamp of the check.")
    drift_detected: Optional[bool] = None
    overall_severity: Optional[str] = Field(None, description="NONE | LOW | MEDIUM | HIGH | CRITICAL")
    findings: Optional[List[Any]] = Field(None, description="One entry per change with tool_name and change_type.")
    tools_added: Optional[List[str]] = None
    tools_removed: Optional[List[str]] = None
    tools_modified: Optional[List[str]] = None
    provenance_rechecked: Optional[bool] = None


class OnboardServerOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    register_result: Optional[Dict[str, Any]] = Field(None, alias="register", description="register_server result.")
    security_scan: Optional[Dict[str, Any]] = Field(
        None, description="security_scan_server result, or {skipped: reason} when no LLM key is set."
    )
    registered: Optional[bool] = Field(None, description="False when only a source-only scan could run.")
    reason: Optional[str] = None
    source_scan: Optional[Dict[str, Any]] = Field(None, description="Source-only scan result (github_url fallback).")
    detail: Optional[str] = None


class DiscoverServersOutput(ToolOutput):
    count: Optional[int] = Field(None, description="Number of server entries found.")
    clients_found: Optional[List[str]] = Field(None, description="Client IDs that had at least one server.")
    discovered: Optional[List[Dict[str, Any]]] = Field(
        None,
        description=(
            "Found servers. Pass their discovery_id values to onboard_discovered_servers. env and headers are withheld."
        ),
    )


class OnboardDiscoveredOutput(ToolOutput):
    total: Optional[int] = Field(None, description="Entries considered.")
    attempted: Optional[int] = Field(None, description="Entries a registration was attempted for.")
    registered: Optional[int] = Field(None, description="Entries successfully registered.")
    results: Optional[List[Dict[str, Any]]] = Field(
        None,
        description=(
            "Per-entry outcome: status is registered | already_registered | skipped | failed | rate_limited, "
            "with server_id when registered."
        ),
    )
    message: Optional[str] = None


class ListServersOutput(ListOutput):
    servers: Optional[List[Dict[str, Any]]] = Field(
        None, description="Registered servers: server_id, transport, tool_count, registered_at."
    )


class ListServerToolsOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    total: Optional[int] = Field(None, description="Total tools on the server, before limit/offset.")
    tools: Optional[List[Dict[str, Any]]] = Field(
        None,
        description=(
            "Tools with tool_name, effect_class, retry_safety, destructiveness, risk_level "
            "(low | medium-low | medium | high | unknown), run_count and confidence."
        ),
    )


class PreflightOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    tool: Optional[str] = None
    assessment: Optional[Dict[str, Any]] = Field(
        None, description="likely_effect, risk_level, approval_recommended, latency band and output size risk."
    )
    security: Optional[Dict[str, Any]] = Field(None, description="Stored security finding for this tool, if any.")
    graph_context: Optional[Dict[str, Any]] = Field(None, description="Blast radius and risk paths from the graph.")
    graph_note: Optional[str] = None
    observed_stats: Optional[Dict[str, Any]] = Field(None, description="Measured stats; null before the first run.")
    confidence: Optional[Dict[str, Any]] = None
    evidence: Optional[List[Any]] = None
    data_source: Optional[str] = Field(None, description="observed (5+ runs) | inferred")
    warning: Optional[str] = None


class ToolProfileOutput(ToolOutput):
    tool_id: Optional[str] = None
    server_id: Optional[str] = _ServerId
    tool_name: Optional[str] = None
    profile: Optional[Dict[str, Any]] = Field(None, description="Full behavior profile with per-field confidence.")


class RetryPolicyOutput(ToolOutput):
    tool: Optional[str] = None
    retry_safety: Optional[str] = Field(None, description="safe | caution | unsafe | unknown")
    recommended_policy: Optional[str] = Field(
        None, description="retry_freely | retry_once_with_caution | no_retry | unknown_retry_with_caution"
    )
    max_retries: Optional[int] = None
    backoff_strategy: Optional[str] = Field(None, description="exponential | fixed_2s | fixed_5s | none")
    suggested_timeout_ms: Optional[int] = Field(None, description="3x observed p95 latency; null before any runs.")
    observed_failure_rate: Optional[float] = None
    confidence: Optional[float] = None
    based_on_runs: Optional[int] = None


class SaferAlternativeOutput(ToolOutput):
    tool: Optional[str] = None
    current_effect: Optional[str] = None
    current_security_flag: Optional[str] = None
    method: Optional[str] = Field(None, description="llm | rule_based")
    alternatives: Optional[List[Dict[str, Any]]] = Field(
        None, description="Candidates; pass a chosen tool name as safe_tool_call(use_alternative=...)."
    )
    read_only_tools: Optional[List[Dict[str, Any]]] = None
    message: Optional[str] = None


class ReplayTestOutput(ToolOutput):
    blocked: Optional[bool] = Field(None, description="True when approved=True is required to run the test.")
    reason: Optional[str] = None
    risk_level: Optional[str] = None
    message: Optional[str] = None
    preflight: Optional[Dict[str, Any]] = None
    verdict: Optional[str] = Field(None, description="likely_idempotent | likely_not_idempotent")
    outputs_identical: Optional[bool] = None
    call1: Optional[Dict[str, Any]] = None
    call2: Optional[Dict[str, Any]] = None
    interpretation: Optional[str] = None


class SetToolPolicyOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    tool: Optional[str] = None
    policy: Optional[str] = Field(None, description="allow | block | cleared")
    warning: Optional[str] = None
    impacting_cves: Optional[List[Any]] = None
    note: Optional[str] = None


class RunHistoryOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    tool: Optional[str] = None
    runs: Optional[List[Dict[str, Any]]] = Field(
        None, description="Most recent first: timestamp, latency_ms, success, injection warnings."
    )


class PingOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    status: Optional[str] = Field(None, description="reachable | timeout | unreachable")
    latency_ms: Optional[float] = None
    network_scan: Optional[Any] = None


class SafeToolCallOutput(ToolOutput):
    result: Optional[List[Any]] = Field(None, description="Content items returned by the wrapped tool.")
    telemetry: Optional[Dict[str, Any]] = Field(None, description="run_id, latency_ms, success, output size.")
    blocked: Optional[bool] = Field(
        None, description="True when the call was not executed. See reason and alternatives to proceed."
    )
    reason: Optional[str] = Field(
        None,
        description=(
            "Why it was blocked: approval_required | policy_blocked | drift_detected | arg_scan_blocked | "
            "graph_policy_block | alternative_also_requires_approval"
        ),
    )
    tool: Optional[str] = None
    risk_level: Optional[str] = None
    message: Optional[str] = None
    preflight: Optional[Dict[str, Any]] = None
    alternatives: Optional[List[Dict[str, Any]]] = None
    options: Optional[List[Dict[str, Any]]] = None
    quarantined: Optional[bool] = Field(None, description="True when output was withheld for injection signals.")
    security_warning: Optional[Any] = None
    executed_with: Optional[str] = Field(None, description="policy_allow | explicit_approval when gating was bypassed.")
    executed_tool: Optional[str] = None
    original_tool: Optional[str] = None
    graph_context: Optional[Dict[str, Any]] = None
    warning: Optional[str] = None


class SecurityScanOutput(ToolOutput):
    status: Optional[str] = Field(None, description="running while a background scan is in progress.")
    server_id: Optional[str] = _ServerId
    message: Optional[str] = None
    overall_risk_level: Optional[str] = Field(None, description="LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN")
    summary: Optional[str] = None
    provider: Optional[str] = None
    tool_findings: Optional[List[Dict[str, Any]]] = Field(
        None, description="Per-tool findings with name and risk_level; block HIGH ones with set_tool_policy."
    )
    server_level_risks: Optional[List[Any]] = None
    scan_status: Optional[str] = None
    valid_providers: Optional[List[str]] = None


class ScanAllOutput(ToolOutput):
    overall_risk_level: Optional[str] = None
    results: Optional[Any] = Field(None, description="Per-server scan results.")
    skipped: Optional[List[Dict[str, Any]]] = None
    valid_providers: Optional[List[str]] = None


class RiskGraphOutput(ToolOutput):
    objects: Optional[List[Dict[str, Any]]] = Field(None, description="Graph nodes with obj_id, obj_type, name.")
    relations: Optional[List[Dict[str, Any]]] = Field(None, description="Graph edges with source_id and target_id.")
    graph: Optional[Dict[str, Any]] = Field(None, description="The graph, when returned alongside a note or rebuild.")
    rebuilt: Optional[Dict[str, Any]] = Field(None, description="Counts of nodes rebuilt from stored data.")
    note: Optional[str] = None


class ToolRiskOutput(ToolOutput):
    server_id: Optional[str] = _ServerId
    tool: Optional[str] = None
    blast_radius: Optional[str] = Field(None, description="critical | high | medium | low | none")
    composite_risk_score: Optional[float] = Field(None, description="0-10.")
    confidence: Optional[float] = None
    direct_findings: Optional[List[Any]] = None
    composition_risks: Optional[List[Any]] = None
    risk_paths: Optional[List[Any]] = None
    agent_clients: Optional[List[Any]] = None
    recommended_action: Optional[str] = Field(None, description="allow | warn | require_approval | block")
    note: Optional[str] = None


class ExportGraphOutput(ToolOutput):
    format: Optional[str] = Field(None, description="png | mermaid | json")
    path: Optional[str] = Field(None, description="Written PNG file path.")
    diagram: Optional[str] = Field(None, description="Mermaid source.")
    objects: Optional[List[Dict[str, Any]]] = None
    relations: Optional[List[Dict[str, Any]]] = None


class ClientRiskOutput(ToolOutput):
    client_id: Optional[str] = None
    server_count: Optional[int] = None
    servers: Optional[Any] = None
    cross_server_exfiltration_paths: Optional[List[Any]] = None
    tool_shadowing: Optional[List[Any]] = None
    cve_blast_radius: Optional[List[Any]] = None
    composite_risk: Optional[str] = Field(None, description="none | medium | high | critical")
    summary: Optional[Any] = None


class CveBlastRadiusOutput(ToolOutput):
    cve_blast_radius: Optional[List[Dict[str, Any]]] = Field(
        None, description="Shared CVEs: vuln_id, severity, affected_servers, client_id, blast_radius (server count)."
    )
    count: Optional[int] = None


class AuditLogOutput(ToolOutput):
    total: Optional[int] = Field(None, description="Matching entries before limit/offset.")
    entries: Optional[List[Dict[str, Any]]] = Field(
        None,
        description=(
            "Newest first: timestamp, tool, client, server_id, target_tool, args (secrets redacted), "
            "outcome (ok | error | blocked | quarantined) and detail."
        ),
    )
