import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from ..core import database as db
from ..core.security_utils import sanitise_for_prompt as _sanitise_for_prompt, strip_json_fence as _strip_json_fence
from ..scan.classifier import classify_tool
from ..scan.args import SSRF_RE, scan_args_for_threats
from ..scan.auxiliary import burp_proxy_evidence
from ..graph import store as _graph_store, explain as _graph_explain
from ..proxy import client as cm
from ._app import mcp, _check_mgmt_rate_limit

_log = logging.getLogger(__name__)


def _latency_band(p95_ms: Optional[float]) -> str:
    if p95_ms is None:
        return "unknown"
    if p95_ms < 200: return "fast (<200ms)"
    if p95_ms < 1000: return "moderate (200ms-1s)"
    if p95_ms < 5000: return "slow (1s-5s)"
    return "very_slow (>5s)"


def _risk_level(effect: str, destructiveness: str) -> str:
    if effect == "destructive" or destructiveness == "high":
        return "high"
    if effect in ("external_action", "mutating_write") or destructiveness == "medium": return "medium"
    if effect == "additive_write": return "medium-low"
    if effect == "read_only": return "low"
    return "unknown"


def _preflight_assessment(profile: Dict, tool_name: str, server_id: str) -> dict:
    effect  = profile.get("effect_class", "unknown")
    destr   = profile.get("destructiveness", "unknown")
    retry   = profile.get("retry_safety", "unknown")
    runs    = profile.get("run_count", 0)
    conf    = profile.get("confidence", {})
    risk    = _risk_level(effect, destr)

    sec_finding = db.get_tool_security_finding(server_id, tool_name)
    sec_block = None
    if sec_finding:
        sec_block = {
            "risk_level": sec_finding.get("risk_level"),
            "risk_tags": sec_finding.get("risk_tags", []),
            "finding": sec_finding.get("finding"),
            "exploitation_scenario": sec_finding.get("exploitation_scenario"),
            "remediation": sec_finding.get("remediation"),
        }
        sec_risk_upper = (sec_finding.get("risk_level") or "").upper()
        if sec_risk_upper in ("HIGH", "CRITICAL"):
            risk = "high"
        elif sec_risk_upper == "MEDIUM" and risk not in ("high",):
            risk = "medium"

    graph_context = None
    graph_note = None
    try:
        gc = _graph_explain.explain_tool_risk(server_id, tool_name)
        if "error" not in gc:
            blast = gc.get("blast_radius", "none")
            cve_impacted = gc.get("cve_impacted", False)
            if blast in ("critical", "high") and risk not in ("high",):
                risk = "high"
            elif blast == "medium" and risk not in ("high", "medium"):
                risk = "medium"
            if cve_impacted and risk not in ("high",):
                risk = "high"
            graph_context = {
                "blast_radius": blast,
                "composite_risk_score": gc.get("composite_risk_score"),
                "confidence": gc.get("confidence"),
                "risk_paths": gc.get("risk_paths", []),
                "composition_risks": [
                    c for c in gc.get("composition_risks", []) if not c.get("mitigated")
                ],
                "agent_clients": gc.get("agent_clients", []),
                "interaction_risks": gc.get("interaction_risks", []),
                "recommended_action": gc.get("recommended_action"),
                "cve_impacted": cve_impacted,
                "impacting_cves": gc.get("impacting_cves", []),
            }
        if graph_context is None:
            graph_note = "Graph not yet populated - call get_risk_graph(rebuild=True) for full risk context."
    except Exception as _ge:
        _log.debug("graph context for preflight failed: %s", _ge)
        graph_note = "Graph context unavailable."

    return {
        "server_id": server_id,
        "tool": tool_name,
        "assessment": {
            "likely_effect": effect,
            "likely_retry_safety": retry,
            "likely_destructiveness": destr,
            "risk_level": risk,
            "approval_recommended": risk in ("high", "medium"),
            "open_world_exposure": profile.get("open_world", False),
            "expected_latency_band": _latency_band(profile.get("latency_p95_ms")),
            "output_size_risk": profile.get("output_risk", "unknown"),
        },
        "security": sec_block,
        "graph_context": graph_context,
        "graph_note": graph_note,
        "observed_stats": {
            "run_count": runs,
            "failure_rate": profile.get("failure_rate"),
            "latency_p50_ms": profile.get("latency_p50_ms"),
            "latency_p95_ms": profile.get("latency_p95_ms"),
            "output_size_p95_bytes": profile.get("output_size_p95_bytes"),
            "schema_stability": profile.get("schema_stability"),
        } if runs > 0 else None,
        "confidence": conf,
        "evidence": profile.get("evidence", []),
        "data_source": "observed" if runs >= 5 else "inferred",
        "warning": (
            f"Low confidence ({conf.get('effect_class', 0):.0%}) - only {runs} run(s) observed. "
            "Proxy more calls to improve accuracy."
            if conf.get("effect_class", 0) < 0.5 else None
        ),
    }


_SAFER_ALT_PROMPT = """\
Identify which tools from the CANDIDATES list could substitute for the RISKY TOOL
with meaningfully lower security risk, while preserving as much functional coverage as possible.

RISKY TOOL
==========
Name: {tool_name}
Description: {description}
Effect class: {effect_class}
Destructiveness: {destructiveness}
Risk flags: {security_tags}
Security finding: {security_flag}

CANDIDATE TOOLS ON THIS SERVER
================================
{candidates_json}

DEFINITIONS
============
effect_class order, lowest to highest risk:
  read_only < additive_write < mutating_write < external_action < destructive

risk_reduction:
  HIGH   - candidate is two or more steps lower in effect_class than the risky tool
  MEDIUM - candidate is one step lower in effect_class
  LOW    - same effect_class but fewer or better-constrained risk flags

functional_coverage:
  full    - candidate can fully replace the risky tool for all known use cases
  partial - candidate covers the most important use cases but not all
  limited - candidate covers only a narrow subset; significant capability loss

TASK
====
For each candidate that provides meaningful risk reduction:
1. Confirm it appears in the CANDIDATES list. Do not suggest tools not listed.
2. Assess what functional coverage it provides relative to the risky tool's description.
3. Rank by risk_reduction descending, then functional_coverage descending.
4. Include at most 5 candidates. Exclude candidates with no meaningful risk reduction.
5. If no candidate qualifies, return an empty array.

Return ONLY valid JSON. No markdown. No text outside the JSON array.

[
  {{
    "tool": "<tool_name - must appear in CANDIDATES list>",
    "effect_class": "<effect_class of this candidate>",
    "risk_reduction": "<HIGH|MEDIUM|LOW>",
    "functional_coverage": "<full|partial|limited>",
    "why_safer": "<one sentence: which specific risk flag or effect_class difference makes this safer>",
    "what_it_achieves": "<one sentence: what the agent accomplishes by using this instead>",
    "what_it_loses": "<one sentence: what capability is lost or degraded vs. the original>",
    "confidence": <0.0-1.0>
  }}
]

RULES
=====
- Do not suggest a tool with a higher or equal risk level than the risky tool.
- Do not suggest a tool whose description makes it unrelated to the risky tool's purpose.
- If security_flag is set, prefer candidates that eliminate that specific risk class.
- confidence reflects certainty in the functional assessment, not the risk reduction.
  Risk reduction is objective (effect_class step count); functional coverage requires inference.
- Do not fabricate descriptions or capabilities not present in the CANDIDATES list.
"""


def _llm_suggest_alternatives(
    tool_name: str,
    tool_desc: str,
    effect_class: str,
    destructiveness: str,
    security_flag: Optional[str],
    security_tags: list,
    candidates: List[Dict],
    provider: str,
    model_id: Optional[str],
    api_key: Optional[str],
) -> List[Dict]:
    from ..scan.scanner import call_llm
    slim = [
        {
            "name": _sanitise_for_prompt(t["tool_name"], 100),
            "description": _sanitise_for_prompt(t.get("description") or "", 150),
            "effect_class": t.get("_effect_class", "unknown"),
            "security_flag": t.get("_security_flag"),
        }
        for t in candidates
    ]
    prompt = _SAFER_ALT_PROMPT.format(
        tool_name      = _sanitise_for_prompt(tool_name, 100),
        description    = _sanitise_for_prompt(tool_desc, 300) if tool_desc else "(none)",
        effect_class   = effect_class,
        destructiveness= destructiveness,
        security_flag  = security_flag or "none",
        security_tags  = ", ".join(security_tags) if security_tags else "none",
        candidates_json= json.dumps(slim, indent=2),
    )
    try:
        raw = call_llm(provider, model_id, api_key, prompt)
        raw = _strip_json_fence(raw.strip())
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except Exception as exc:
        _log.debug("alternatives LLM call failed (provider=%s): %s", provider, exc)
        return []


@mcp.tool()
def list_servers() -> str:
    """
    List all registered servers with transport type and tool count.

    Use this first when you don't know which servers are available, before calling
    safe_tool_call, security_scan_server, or list_server_tools.
    NEXT: list_server_tools(server_id) to see available tools on a specific server.
    """
    servers = db.list_servers()
    return json.dumps(
        [
            {
                "server_id": s["server_id"],
                "transport": s["transport"],
                "tool_count": s.get("tool_count", 0),
                "registered_at": s["registered_at"],
            }
            for s in servers
        ],
        indent=2,
    )


@mcp.tool()
def list_server_tools(server_id: str) -> str:
    """
    List all known tools for a server with summarized risk profiles (effect class, retry safety, risk level).

    Use this before safe_tool_call to choose which tool to call and assess risk.
    Returns error with hint to run inspect_server if no tools are found.

    BEFORE: inspect_server (to populate tool profiles).
    AFTER: safe_tool_call to execute a tool, or set_tool_policy('block') for any HIGH-risk tools.
    """
    tools = db.list_tools(server_id)
    if not tools:
        return json.dumps({
            "error": f"No tools found for '{server_id}'.",
            "hint": "Run inspect_server first.",
        })

    profiles = db.get_profiles_batch([t["tool_id"] for t in tools])
    rows = []
    for t in tools:
        p = profiles.get(t["tool_id"])
        effect = p["effect_class"] if p else "unknown"
        destr  = p["destructiveness"] if p else "unknown"
        tool_obj = _graph_store.get_object(t["tool_id"])
        tool_meta = (tool_obj or {}).get("metadata", {})
        row: Dict[str, Any] = {
            "tool_name": t["tool_name"],
            "description": (t["description"] or "")[:100],
            "effect_class": effect,
            "retry_safety": p["retry_safety"] if p else "unknown",
            "destructiveness": destr,
            "risk_level": _risk_level(effect, destr),
            "run_count": p["run_count"] if p else 0,
            "confidence": p["confidence"].get("effect_class", 0) if p else 0,
        }
        if tool_meta.get("cve_impacted"):
            row["cve_impacted"] = True
            row["impacting_cves"] = tool_meta.get("impacting_cves", [])
        rows.append(row)

    return json.dumps({"server_id": server_id, "tools": rows}, indent=2)


@mcp.tool()
async def preflight_tool_call(
    server_id: str,
    tool_name: str,
    args: Optional[dict] = None,
    auto_scan_provider: Optional[str] = None,
    auto_scan_model: Optional[str] = None,
    auto_scan_api_key: Optional[str] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> str:
    """
    Get a risk assessment for a tool WITHOUT executing it.

    DO NOT call this before safe_tool_call - safe_tool_call runs preflight internally.
    Only use preflight_tool_call when you need to show the user risk details before
    deciding whether to proceed, separate from actually calling the tool.

    Returns: effect class, retry safety, risk level, approval_recommended flag,
    latency band, output size risk, confidence, evidence trail, and security findings.

    BEFORE: inspect_server (tool must be registered and known).
    AFTER: if approval_recommended=True, either get user confirmation then call
    safe_tool_call(approved=True), or call suggest_safer_alternative first.

    auto_scan_provider: LLM to auto-trigger a one-time security scan if none exists.
    Auto-detected from ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY if omitted.
    Accepts "anthropic", "openai", "gemini", "cisco", "snyk" - not mcpsafety+ providers
    (use security_scan_server with confirm_authorized=True for those).
    Scan runs once per server and is cached; subsequent preflight calls reuse the result.
    """
    from ..scan.scanner import detect_llm_provider as _detect_llm_provider, run_cisco_scan, run_snyk_scan, run_security_scan
    from ._app import _preflight_scan_locks, _PREFLIGHT_SCAN_TIMEOUT_S

    tool = db.get_tool(server_id, tool_name)
    if not tool:
        return json.dumps({
            "error": f"Tool '{tool_name}' not found on server '{server_id}'.",
            "hint": "Run inspect_server first.",
        })

    effective_scan_provider = auto_scan_provider or _detect_llm_provider()
    if effective_scan_provider and not db.get_latest_security_scan(server_id):
        if effective_scan_provider.startswith("mcpsafety+"):
            _log.warning(
                "Auto-scan skipped for mcpsafety+ provider on server '%s'. "
                "Use security_scan_server with confirm_authorized=True instead.",
                server_id,
            )
        else:
            if server_id not in _preflight_scan_locks:
                if len(_preflight_scan_locks) > 1000:
                    stale = [k for k, lk in list(_preflight_scan_locks.items()) if not lk.locked()]
                    for k in stale:
                        _preflight_scan_locks.pop(k, None)
                _preflight_scan_locks[server_id] = asyncio.Lock()
            async with _preflight_scan_locks[server_id]:
                if not db.get_latest_security_scan(server_id):
                    try:
                        server = cm.resolve_server_crefs(db.get_server(server_id))
                        tools  = db.list_tools(server_id)
                        if effective_scan_provider == "cisco":
                            findings = await asyncio.wait_for(
                                run_cisco_scan(server_id=server_id, server_config=server, cisco_api_key=auto_scan_api_key),
                                timeout=_PREFLIGHT_SCAN_TIMEOUT_S,
                            )
                        elif effective_scan_provider == "snyk":
                            findings = await asyncio.wait_for(
                                run_snyk_scan(server_id=server_id, server_config=server, snyk_token=auto_scan_api_key),
                                timeout=_PREFLIGHT_SCAN_TIMEOUT_S,
                            )
                        else:
                            loop = asyncio.get_running_loop()
                            findings = await asyncio.wait_for(
                                loop.run_in_executor(
                                    None,
                                    lambda: run_security_scan(
                                        server_id=server_id, tools=tools,
                                        provider=effective_scan_provider,
                                        model_id=auto_scan_model,
                                        api_key=auto_scan_api_key,
                                    ),
                                ),
                                timeout=_PREFLIGHT_SCAN_TIMEOUT_S,
                            )
                        from ._hooks import _gh_on_scan_stored
                        db.store_security_scan(server_id, findings)
                        _gh_on_scan_stored(server_id, findings)
                    except Exception as exc:
                        _log.warning("preflight auto-scan skipped for '%s': %s", server_id, exc)

    effective_llm = llm_provider or _detect_llm_provider()
    profile = db.get_profile(tool["tool_id"])
    if profile is None:
        loop = asyncio.get_running_loop()
        profile = await loop.run_in_executor(
            None,
            lambda: classify_tool(
                tool_name, tool.get("description", ""), tool.get("schema", {}), tool.get("annotations", {}),
                effective_llm, llm_model, llm_api_key,
            ),
        )
        profile.pop("_security_finding", None)
        db.upsert_profile(tool["tool_id"], profile)
    return json.dumps(_preflight_assessment(profile, tool_name, server_id), indent=2)


@mcp.tool()
def get_tool_profile(server_id: str, tool_name: str) -> str:
    """
    Get the full raw behavior profile for a tool with all observed metrics and confidence scores.

    Returns latency percentiles, failure rate, output size stats, schema stability,
    and per-field confidence. More detailed than the summary in list_server_tools.

    BEFORE: safe_tool_call (at least a few runs build observed stats; before that, data is inferred).
    Use this to debug unexpected risk classifications or review learned behavioral data.
    """
    tool = db.get_tool(server_id, tool_name)
    if not tool: return json.dumps({"error": f"Tool '{tool_name}' not found on server '{server_id}'."})
    profile = db.get_profile(tool["tool_id"])
    if not profile: return json.dumps({"error": "No profile yet. Run inspect_server or safe_tool_call first."})
    return json.dumps({"tool_id": tool["tool_id"], "server_id": server_id,
                       "tool_name": tool_name, "profile": profile}, indent=2)


@mcp.tool()
def get_retry_policy(
    server_id: str,
    tool_name: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> str:
    """
    Get the recommended retry policy for a tool: max retries, backoff strategy, and suggested timeout.

    Returns policy name ("retry_freely", "no_retry", "retry_once_with_caution"), max_retries,
    backoff_strategy, and suggested_timeout_ms derived from observed p95 latency.

    BEFORE: inspect_server (tool must be known). More accurate after several safe_tool_call runs.
    AFTER: implement retry logic around safe_tool_call using max_retries and backoff_strategy.
    To verify actual idempotency before relying on retry_safety="safe", run run_replay_test.
    """
    from ..scan.scanner import detect_llm_provider as _detect_llm_provider
    tool = db.get_tool(server_id, tool_name)
    if not tool: return json.dumps({"error": f"Tool '{tool_name}' not found."})
    effective_llm = llm_provider or _detect_llm_provider()
    profile = db.get_profile(tool["tool_id"])
    if profile is None:
        profile = classify_tool(
            tool_name, tool.get("description", ""), tool.get("schema", {}), tool.get("annotations", {}),
            effective_llm, llm_model, llm_api_key,
        )
        profile.pop("_security_finding", None)
        db.upsert_profile(tool["tool_id"], profile)
    retry  = profile.get("retry_safety", "unknown")
    p95    = profile.get("latency_p95_ms")
    runs   = profile.get("run_count", 0)

    if retry == "safe": policy, max_retries, backoff = "retry_freely", 3, "exponential"
    elif retry == "unsafe": policy, max_retries, backoff = "no_retry", 0, "none"
    elif retry == "caution": policy, max_retries, backoff = "retry_once_with_caution", 1, "fixed_2s"
    else: policy, max_retries, backoff = "unknown_retry_with_caution", 1, "fixed_5s"

    return json.dumps({
        "tool": tool_name,
        "retry_safety": retry,
        "recommended_policy": policy,
        "max_retries": max_retries,
        "backoff_strategy": backoff,
        "suggested_timeout_ms": int(p95 * 3) if p95 else None,
        "observed_failure_rate": profile.get("failure_rate") if runs > 0 else None,
        "confidence": profile.get("confidence", {}).get("retry_safety", 0),
        "based_on_runs": runs,
    }, indent=2)


@mcp.tool()
def suggest_safer_alternative(
    server_id: str,
    tool_name: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> str:
    """
    Find lower-risk alternatives to a tool on the same server, ranked by risk reduction.

    Call this when safe_tool_call returns blocked=True and you want safer substitutes.
    Returns alternatives with risk_reduction (HIGH/MEDIUM/LOW), functional_coverage,
    why_safer, and what_it_loses for informed trade-off decisions.

    LLM path (default): semantic matching using effect_class ordering and security findings.
    Auto-detects provider from ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY.
    Rule-based fallback: name-stem matching for read-only tools; used when no LLM is available.

    BEFORE: safe_tool_call (blocked=True shows which tool needs an alternative).
    AFTER: safe_tool_call(use_alternative="<tool_name>") with the chosen alternative.
    Shortcut: pass use_alternative directly to safe_tool_call without calling this first.
    """
    from ..scan.scanner import detect_llm_provider as _detect_llm_provider
    tool = db.get_tool(server_id, tool_name)
    if not tool: return json.dumps({"error": f"Tool '{tool_name}' not found."})

    effective_llm = llm_provider or _detect_llm_provider()
    profile = db.get_profile(tool["tool_id"])
    if profile is None:
        profile = classify_tool(
            tool["tool_name"], tool.get("description", ""), tool.get("schema", {}), tool.get("annotations", {}),
            effective_llm, llm_model, llm_api_key,
        )
        profile.pop("_security_finding", None)
        db.upsert_profile(tool["tool_id"], profile)
    current_effect = profile.get("effect_class", "unknown")
    current_destr  = profile.get("destructiveness", "unknown")
    current_sec    = db.get_tool_security_finding(server_id, tool_name)
    current_sec_risk = current_sec.get("risk_level") if current_sec else None
    current_sec_tags = current_sec.get("risk_tags", []) if current_sec else []

    if current_effect == "read_only" and current_sec_risk != "HIGH":
        return json.dumps({
            "tool": tool_name,
            "message": "Already low-risk (read-only, no security flags). No alternative needed.",
            "alternatives": [],
        })

    all_tools = db.list_tools(server_id)
    findings_map = db.get_tool_security_findings_map(server_id)
    candidates = []
    for t in all_tools:
        if t["tool_name"] == tool_name:
            continue
        p = db.get_profile(t["tool_id"])
        s = findings_map.get(t["tool_name"])
        alt_obj = _graph_store.get_object(t["tool_id"])
        alt_meta = (alt_obj or {}).get("metadata", {})
        candidates.append({
            **t,
            "_effect_class": (p or {}).get("effect_class", "unknown"),
            "_security_flag": s.get("risk_level") if s else None,
            "_cve_impacted": alt_meta.get("cve_impacted", False),
            "_impacting_cves": alt_meta.get("impacting_cves", []),
        })

    cve_index = {c["tool_name"]: c for c in candidates if c.get("_cve_impacted")}

    if effective_llm:
        llm_alts = _llm_suggest_alternatives(
            tool_name, tool.get("description", ""), current_effect, current_destr,
            current_sec_risk, current_sec_tags, candidates,
            effective_llm, llm_model, llm_api_key,
        )
        if llm_alts:
            for alt in llm_alts:
                cve_c = cve_index.get(alt.get("tool", ""))
                if cve_c:
                    alt["warning"] = "cve_impacted"
                    alt["impacting_cves"] = cve_c.get("_impacting_cves", [])
            return json.dumps({
                "tool": tool_name,
                "current_effect": current_effect,
                "current_security_flag": current_sec_risk,
                "method": "llm",
                "alternatives": llm_alts,
            }, indent=2)

    stem = tool_name.split("_", 1)[-1] if "_" in tool_name else tool_name

    def _candidate_is_secure_read_only(c: dict) -> bool:
        return c.get("_effect_class") == "read_only" and c.get("_security_flag") != "HIGH" and not c.get("_cve_impacted")

    def _alt_entry(c: dict, why_safer: str) -> dict:
        entry: Dict[str, Any] = {
            "tool": c["tool_name"],
            "description": (c["description"] or "")[:100],
            "effect_class": c.get("_effect_class", "unknown"),
            "why_safer": why_safer,
        }
        if c.get("_cve_impacted"):
            entry["warning"] = "cve_impacted"
            entry["impacting_cves"] = c.get("_impacting_cves", [])
        return entry

    alternatives = [
        _alt_entry(c, "read-only, no security flags, similar name")
        for c in candidates
        if stem.lower() in c["tool_name"].lower()
        and _candidate_is_secure_read_only(c)
    ]

    if alternatives:
            return json.dumps({
            "tool": tool_name,
            "current_effect": current_effect,
            "current_security_flag": current_sec_risk,
            "method": "rule_based",
            "alternatives": alternatives,
        }, indent=2)

    read_only_clean = [
        {"tool": c["tool_name"], "description": (c["description"] or "")[:80]}
        for c in candidates
        if _candidate_is_secure_read_only(c)
    ]
    return json.dumps({
        "tool": tool_name,
        "current_effect": current_effect,
        "current_security_flag": current_sec_risk,
        "method": "rule_based",
        "message": "No direct alternative found. Available safe read-only tools on this server:",
        "read_only_tools": read_only_clean[:10],
    }, indent=2)


@mcp.tool()
async def run_replay_test(
    server_id: str,
    tool_name: str,
    args: Optional[dict] = None,
    approved: bool = False,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> str:
    """
    Test idempotency by calling a tool TWICE with identical args and comparing outputs.

    WARNING: this executes the tool twice and has real side effects for non-read-only tools.
    The response will indicate if approved=True is required before the test can run.

    Use this to verify whether a tool is truly safe to retry on failure, confirming or
    refuting the retry_safety classification returned by get_retry_policy.

    BEFORE: get_retry_policy (check current retry_safety classification).
    Only worth running if retry_safety is "safe" or "unknown" - skip for "unsafe".
    AFTER: if idempotent=True confirmed, rely on get_retry_policy for max_retries/backoff.
    """
    from ..scan.scanner import detect_llm_provider as _detect_llm_provider
    rl = _check_mgmt_rate_limit(f"replay:{server_id}")
    if rl:
        return json.dumps({"error": rl})

    tool = db.get_tool(server_id, tool_name)
    if not tool: return json.dumps({"error": f"Tool '{tool_name}' not found on server '{server_id}'."})

    profile = db.get_profile(tool["tool_id"])
    if profile is None:
        _classify_provider = llm_provider or _detect_llm_provider()
        loop = asyncio.get_running_loop()
        profile = await loop.run_in_executor(
            None,
            lambda: classify_tool(
                tool_name, tool.get("description", ""), tool.get("schema", {}), tool.get("annotations", {}),
                llm_provider=_classify_provider, llm_model=llm_model, llm_api_key=llm_api_key,
            ),
        )
        profile.pop("_security_finding", None)
        db.upsert_profile(tool["tool_id"], profile)
    assessment  = _preflight_assessment(profile, tool_name, server_id)
    effect      = profile.get("effect_class", "unknown")
    destructive = profile.get("destructiveness", "unknown")
    risk_level  = assessment["assessment"]["risk_level"]

    needs_approval = (
        effect != "read_only"
        or destructive in ("high", "medium")
        or assessment["assessment"]["approval_recommended"]
    )

    if needs_approval and not approved:
        return json.dumps({
            "blocked": True,
            "reason": "approval_required",
            "risk_level": risk_level,
            "message": (
                f"'{tool_name}' will be called TWICE (risk: {risk_level}, effect: {effect}). "
                "Re-call with approved=True to proceed."
            ),
            "preflight": assessment,
        }, indent=2)

    try:
        result = await cm.run_replay_test(server_id, tool_name, args or {})
        server = db.get_server(server_id)
        if server:
            burp_traffic = await burp_proxy_evidence(server)
            if burp_traffic:
                result["burp_proxy_traffic"] = burp_traffic
        return json.dumps(result, indent=2)
    except (ValueError, RuntimeError) as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("run_replay_test failed for %s::%s: %s", server_id, tool_name, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})


@mcp.tool()
def set_tool_policy(
    server_id: str,
    tool_name: str,
    policy: Optional[str] = None,
) -> str:
    """
    Set a permanent execution policy for a tool, overriding the normal preflight flow.

    Use "block" after security_scan_server reveals a HIGH-risk tool you never want called.
    Use "allow" for trusted internal tools where you want to skip risk checks for speed.
    Use null to restore the normal safe_tool_call preflight behavior.

    policy: "allow" - always execute without preflight check.
            "block" - never execute; safe_tool_call returns blocked=True immediately.
            null    - clear policy; resume normal risk-gated preflight flow.

    BEFORE: security_scan_server or get_security_scan (to identify HIGH-risk tools).
    AFTER: safe_tool_call respects the new policy immediately.
    """
    tool = db.get_tool(server_id, tool_name)
    if not tool:
        return json.dumps({"error": f"Tool '{tool_name}' not found on server '{server_id}'."})
    if policy == "clear":
        policy = None
    if policy is not None and policy not in ("allow", "block"):
        return json.dumps({"error": "policy must be 'allow', 'block', or null to clear."})
    db.set_tool_policy(server_id, tool_name, policy)
    resp: Dict[str, Any] = {
        "server_id": server_id,
        "tool": tool_name,
        "policy": policy if policy is not None else "cleared",
    }
    if policy == "allow":
        tool_obj = _graph_store.get_object(tool["tool_id"])
        tool_meta = (tool_obj or {}).get("metadata", {})
        if tool_meta.get("cve_impacted"):
            resp["warning"] = "cve_impacted"
            resp["impacting_cves"] = tool_meta.get("impacting_cves", [])
            resp["note"] = "This tool has known CVEs. allow policy bypasses preflight - proceed with caution."
    return json.dumps(resp, indent=2)


@mcp.tool()
def get_run_history(server_id: str, tool_name: str, limit: int = 20) -> str:
    """
    Get recent execution history for a tool: timestamps, latency, success/fail, and injection warnings.

    Use this to debug failures, audit executions, or review calls that were quarantined
    (quarantined=True) by safe_tool_call due to injection signals in the output.

    BEFORE: safe_tool_call (calls must have been made to have history).
    AFTER: if injection_warning runs are found, consider set_tool_policy('block').
    """
    tool = db.get_tool(server_id, tool_name)
    if not tool:
        return json.dumps({"error": f"Tool '{tool_name}' not found on server '{server_id}'."})
    limit = max(1, min(limit, 200))
    runs = db.get_runs(tool["tool_id"], limit)
    return json.dumps({"server_id": server_id, "tool": tool_name, "runs": runs}, indent=2)


@mcp.tool()
async def ping_server(server_id: str) -> str:
    """
    Check if a registered server is reachable. Returns status and round-trip latency.

    Use before safe_tool_call if you suspect the server is down, or to diagnose connection errors.
    For remote (SSE/HTTP) servers, also runs a fast network recon scan via kali_recon.

    BEFORE: register_server (server must be registered).
    AFTER: if unreachable, fix local setup then call inspect_server to refresh the tool list.
    """
    from ..scan.auxiliary import kali_recon
    try:
        result = await cm.ping_server(server_id)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("ping_server failed for %s: %s", server_id, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})

    server = db.get_server(server_id)
    if server and server.get("transport") in ("sse", "streamable_http"):
        network_scan = await kali_recon(server, fast=True)
        if network_scan:
            result["network_scan"] = network_scan

    return json.dumps({"server_id": server_id, **result}, indent=2)


async def _call_and_format(
    server_id: str,
    tool_name: str,
    args: dict,
    extra: Optional[Dict[str, Any]] = None,
    *,
    args_scan_override: bool = False,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    tool_description: str = "",
) -> str:
    if args_scan_override:
        _log.warning("args_scan_override=True used for %s::%s - arg scan bypassed", server_id, tool_name)

    if args and not args_scan_override:
        threat = await scan_args_for_threats(
            tool_name, args, tool_description,
            llm_provider, llm_model, llm_api_key,
        )
        if threat:
            needs_review = threat.pop("needs_review", False)
            msg = (
                "Argument scan detected potentially dangerous patterns. "
                "Review the flagged value and re-call with args_scan_override=True to proceed if this is a false positive."
                if needs_review else
                "Argument confirmed as a security threat by LLM analysis. "
                "Re-call with args_scan_override=True to override (use with caution)."
            )
            return json.dumps({
                **{k: v for k, v in threat.items() if k != "reason"},
                "blocked": True,
                "reason": "arg_scan_blocked",
                "tool": tool_name,
                "llm_reason": threat.get("reason", ""),
                "message": msg,
            }, indent=2)

    try:
        content, telemetry = await cm.call_tool_with_telemetry(server_id, tool_name, args)
        result_items = []
        for item in content:
            if hasattr(item, "model_dump"): result_items.append(item.model_dump())
            elif hasattr(item, "text"): result_items.append({"type": "text", "text": item.text})
            else: result_items.append(str(item))
        if telemetry.get("injection_warning"):
            return json.dumps({
                "quarantined": True,
                "security_warning": telemetry["injection_warning"],
                "message": (
                    "Tool output was quarantined and not returned. "
                    f"Raw output stored under run_id={telemetry['run_id']} for forensic review."
                ),
                "telemetry": telemetry,
            }, indent=2)
        response: Dict[str, Any] = {"result": result_items, "telemetry": telemetry}
        if extra: response.update(extra)
        if telemetry.get("output_truncated"): response["warning"] = "Output exceeded limit and was truncated."
        return json.dumps(response, indent=2)
    except cm.DriftDetectedError as exc:
        _log.warning(
            "drift detected on call to %s::%s: change_type=%s",
            server_id, tool_name, exc.change_type,
        )
        return json.dumps({
            "blocked": True,
            "reason": "drift_detected",
            "tool": tool_name,
            "change_type": exc.change_type,
            "drift": exc.detail,
            "message": (
                "Tool definition changed since last inspect. "
                "Run inspect_server to review and re-establish baseline."
            ),
        }, indent=2)
    except (ValueError, RuntimeError) as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("tool call failed for %s::%s: %s", server_id, tool_name, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})


@mcp.tool()
async def safe_tool_call(
    server_id: str,
    tool_name: str,
    args: Optional[dict] = None,
    approved: bool = False,
    use_alternative: Optional[str] = None,
    show_more_options: bool = False,
    args_scan_override: bool = False,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> str:
    """
    Execute a tool through the safety proxy. This is the ONLY correct way to call tools on registered servers.
    Do NOT call preflight_tool_call before this - preflight runs automatically inside.

    First call: low-risk tools execute immediately. Medium/high risk returns blocked=True with alternatives.

    When blocked:
      approved=True: proceed despite risk (confirm with user first)
      use_alternative="<tool_name>": execute a safer alternative from the alternatives list
      show_more_options=True: see all options including abort

    When blocked by "policy_blocked": use set_tool_policy(policy=None) to clear if intentional.
    When blocked by "drift_detected": run inspect_server to re-establish the tool baseline.
    When blocked by "arg_scan_blocked": review the flagged argument; args_scan_override=True only if confirmed safe.
    When result has quarantined=True: output contained injection signals; check get_run_history for details.

    BEFORE: register_server or onboard_server (server must be registered and tools inspected).
    """
    import os as _os
    from ..scan.scanner import detect_llm_provider as _detect_llm_provider

    if use_alternative:
        alt_tool = db.get_tool(server_id, use_alternative)
        if not alt_tool:
            return json.dumps({"error": f"Alternative tool '{use_alternative}' not found on server '{server_id}'."})
        alt_profile = db.get_profile(alt_tool["tool_id"])
        if alt_profile is None:
            loop = asyncio.get_running_loop()
            alt_profile = await loop.run_in_executor(
                None,
                lambda: classify_tool(
                    use_alternative, alt_tool.get("description", ""), alt_tool.get("schema", {}), alt_tool.get("annotations", {}),
                    llm_provider or _detect_llm_provider(), llm_model, llm_api_key,
                ),
            )
            alt_profile.pop("_security_finding", None)
            db.upsert_profile(alt_tool["tool_id"], alt_profile)
        alt_assessment = _preflight_assessment(alt_profile, use_alternative, server_id)
        if alt_assessment["assessment"]["approval_recommended"] and not approved:
            return json.dumps({
                "blocked": True,
                "reason": "alternative_also_requires_approval",
                "tool": use_alternative,
                "risk_level": alt_assessment["assessment"]["risk_level"],
                "message": f"'{use_alternative}' also requires approval. Re-call with approved=True to proceed.",
                "preflight": alt_assessment,
            }, indent=2)
        return await _call_and_format(
            server_id, use_alternative, args or {},
            {"executed_tool": use_alternative, "original_tool": tool_name},
            args_scan_override=args_scan_override,
            llm_provider=llm_provider or _detect_llm_provider(),
            llm_model=llm_model, llm_api_key=llm_api_key,
            tool_description=alt_tool.get("description", ""),
        )

    if show_more_options:
        return json.dumps({
            "tool": tool_name,
            "options": [
                {
                    "choice": "B",
                    "action": "Proceed with original tool despite risk",
                    "how": "Re-call safe_tool_call with approved=True",
                },
                {
                    "choice": "C",
                    "action": "Abort",
                    "how": "Do not call this tool",
                },
            ],
        }, indent=2)

    tool = db.get_tool(server_id, tool_name)
    if not tool:
        return json.dumps({
            "error": f"Tool '{tool_name}' not found on server '{server_id}'.",
            "hint": "Run inspect_server first.",
        })

    policy = db.get_tool_policy(server_id, tool_name)
    if policy == "block":
        return json.dumps({
            "blocked": True,
            "reason": "policy_blocked",
            "tool": tool_name,
            "message": f"'{tool_name}' is permanently blocked by policy. Use set_tool_policy to change.",
        }, indent=2)
    if policy == "allow":
        return await _call_and_format(
            server_id, tool_name, args or {}, {"executed_with": "policy_allow"},
            args_scan_override=args_scan_override,
            llm_provider=llm_provider or _detect_llm_provider(),
            llm_model=llm_model, llm_api_key=llm_api_key,
            tool_description=tool.get("description", ""),
        )

    profile = db.get_profile(tool["tool_id"])
    if profile is None:
        loop = asyncio.get_running_loop()
        profile = await loop.run_in_executor(
            None,
            lambda: classify_tool(
                tool_name, tool.get("description", ""), tool.get("schema", {}), tool.get("annotations", {}),
                llm_provider or _detect_llm_provider(), llm_model, llm_api_key,
            ),
        )
        profile.pop("_security_finding", None)
        db.upsert_profile(tool["tool_id"], profile)
    assessment = _preflight_assessment(profile, tool_name, server_id)
    risk_level = assessment["assessment"]["risk_level"]

    _graph_policy = _os.environ.get("MCP_GRAPH_POLICY", "warn").lower()
    _graph_ctx = assessment.get("graph_context") or {}
    _blast = _graph_ctx.get("blast_radius", "none")
    _cve_impacted = _graph_ctx.get("cve_impacted", False)
    _graph_ctx_out: Dict[str, Any] = {
        "blast_radius": _blast,
        "composite_risk_score": _graph_ctx.get("composite_risk_score"),
        "risk_paths": (_graph_ctx.get("risk_paths") or [])[:3],
        "recommended_action": _graph_ctx.get("recommended_action"),
    }
    if _cve_impacted:
        _graph_ctx_out["cve_impacted"] = True
        _graph_ctx_out["impacting_cves"] = _graph_ctx.get("impacting_cves", [])
    _graph_extra: Dict[str, Any] = (
        {"graph_context": _graph_ctx_out}
        if _graph_policy != "off" and (_blast not in ("none", "") or _cve_impacted)
        else {}
    )

    if _graph_policy == "block" and _blast in ("critical", "high") and not approved:
        return json.dumps(
            {
                "blocked": True,
                "reason": "graph_policy_block",
                "tool": tool_name,
                "blast_radius": _blast,
                "composite_risk_score": _graph_ctx.get("composite_risk_score"),
                "risk_paths": (_graph_ctx.get("risk_paths") or [])[:5],
                "interaction_risks": _graph_ctx.get("interaction_risks", []),
                "message": (
                    f"'{tool_name}' blocked by graph policy (MCP_GRAPH_POLICY=block): "
                    f"blast_radius={_blast}. Pass approved=True to override."
                ),
            },
            indent=2,
        )

    if not assessment["assessment"]["approval_recommended"]:
        return await _call_and_format(
            server_id, tool_name, args or {},
            _graph_extra or None,
            args_scan_override=args_scan_override,
            llm_provider=llm_provider or _detect_llm_provider(),
            llm_model=llm_model, llm_api_key=llm_api_key,
            tool_description=tool.get("description", ""),
        )

    if approved:
        return await _call_and_format(
            server_id, tool_name, args or {},
            {"executed_with": "explicit_approval", "risk_level": risk_level, **_graph_extra},
            args_scan_override=args_scan_override,
            llm_provider=llm_provider or _detect_llm_provider(),
            llm_model=llm_model, llm_api_key=llm_api_key,
            tool_description=tool.get("description", ""),
        )

    effective_provider = llm_provider or _detect_llm_provider()
    alternatives: List[Dict[str, Any]] = []
    if effective_provider:
        try:
            all_tools = db.list_tools(server_id)
            findings_map = db.get_tool_security_findings_map(server_id)
            candidates = []
            for t in all_tools:
                if t["tool_name"] == tool_name: continue
                p = db.get_profile(t["tool_id"])
                s = findings_map.get(t["tool_name"])
                candidates.append({
                    **t,
                    "_effect_class": (p or {}).get("effect_class", "unknown"),
                    "_security_flag": s.get("risk_level") if s else None,
                })
            sec = assessment.get("security") or {}
            loop = asyncio.get_running_loop()
            alternatives = await loop.run_in_executor(
                None,
                lambda: _llm_suggest_alternatives(
                    tool_name, tool.get("description", ""),
                    assessment["assessment"]["likely_effect"],
                    assessment["assessment"]["likely_destructiveness"],
                    sec.get("risk_level"), sec.get("risk_tags", []),
                    candidates, effective_provider, llm_model, llm_api_key,
                ),
            )
        except Exception as exc:
            _log.debug("alternatives suggestion failed for '%s::%s': %s", server_id, tool_name, exc)

    choices: List[Dict[str, Any]] = [
        {
            "option": i + 1,
            "tool": alt["tool"],
            "risk_reduction": alt.get("risk_reduction"),
            "functional_coverage": alt.get("functional_coverage"),
            "what_it_loses": alt.get("what_it_loses"),
            "why_safer": alt.get("why_safer"),
            "how": f"Re-call safe_tool_call with use_alternative='{alt['tool']}'",
        }
        for i, alt in enumerate(alternatives)
    ]
    choices.append({
        "option": len(choices) + 1,
        "tool": "More options",
        "how": "Re-call safe_tool_call with show_more_options=True",
    })

    _graph_note = assessment.get("graph_note")
    return json.dumps({
        "blocked": True,
        "reason": "approval_required",
        "tool": tool_name,
        "risk_level": risk_level,
        "preflight": assessment,
        "alternatives": choices,
        **(_graph_extra if _graph_extra else {}),
        **({"graph_note": _graph_note} if _graph_note else {}),
    }, indent=2)
