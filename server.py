import asyncio
import collections
import hmac
import json
import logging
import os as _os
import time
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

import database as db
import client_manager as cm
from classifier import classify_tool
from scanner import ALL_PROVIDERS, call_llm, detect_llm_provider as _detect_llm_provider, run_cisco_scan, run_snyk_scan, run_security_scan
from mcpsafety_scanner import (
    run_mcpsafety_scan, run_mcpsafety_scan_multi, SSRF_RE, scan_args_for_threats,
    kali_recon, burp_proxy_evidence,
)
from security_utils import sanitise_for_prompt as _sanitise_for_prompt, strip_json_fence as _strip_json_fence

_log = logging.getLogger(__name__)

# Shell interpreters that, combined with an eval flag (-c, /c), enable arbitrary code execution.
_SHELL_INTERPS = frozenset({
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
    "cmd", "powershell", "pwsh",
})
_SHELL_EVAL_FLAGS = frozenset({"-c", "/c", "/k", "-e", "-enc", "-encodedcommand", "-command"})

_LLM_SHORTHANDS: frozenset = frozenset({"anthropic", "openai", "gemini", "ollama"})


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Rejects HTTP requests whose Authorization header does not match MCP_AUTH_TOKEN."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        super().__init__(app)
        self._token_bytes = token.encode()

    async def dispatch(self, request, call_next):
        auth = request.headers.get("Authorization", "")
        candidate = auth[7:].encode() if auth.startswith("Bearer ") else b""
        expected = self._token_bytes
        padded = candidate.ljust(len(expected), b"\x00")[:len(expected)]
        if not hmac.compare_digest(padded, expected) or len(candidate) != len(expected):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return await call_next(request)


def create_http_app(transport: str = "streamable_http") -> ASGIApp:
    """Return the FastMCP ASGI app, optionally wrapped with BearerAuthMiddleware.

    transport: "streamable_http" (default) or "sse"
    """
    token = _os.environ.get("MCP_AUTH_TOKEN", "")
    base = mcp.streamable_http_app() if transport == "streamable_http" else mcp.sse_app()
    if token:
        return BearerAuthMiddleware(base, token)
    _log.warning(
        "MCP_AUTH_TOKEN is not set - HTTP transport is open to any client. "
        "Set this variable or place an auth proxy in front."
    )
    return base


_MGMT_RATE_LIMIT_MAX      = 10
_MGMT_RATE_LIMIT_WINDOW_S = 60
_GLOBAL_RATE_LIMIT_MAX    = 100
_MGMT_DICT_MAX_ENTRIES    = 5_000
_mgmt_call_times: Dict[str, collections.deque] = {}
_global_call_times: collections.deque = collections.deque(maxlen=_GLOBAL_RATE_LIMIT_MAX)


def _check_mgmt_rate_limit(key: str) -> Optional[str]:
    now = time.monotonic()

    # Global limit - prevents server-ID rotation bypass
    while _global_call_times and now - _global_call_times[0] > _MGMT_RATE_LIMIT_WINDOW_S:
        _global_call_times.popleft()
    if len(_global_call_times) >= _GLOBAL_RATE_LIMIT_MAX:
        return (
            f"Server-wide rate limit exceeded ({_GLOBAL_RATE_LIMIT_MAX} calls/{_MGMT_RATE_LIMIT_WINDOW_S}s). "
            f"Retry after {int(_MGMT_RATE_LIMIT_WINDOW_S - (now - _global_call_times[0]))}s."
        )

    if len(_mgmt_call_times) >= _MGMT_DICT_MAX_ENTRIES and key not in _mgmt_call_times:
        _mgmt_call_times.pop(next(iter(_mgmt_call_times)), None)
    times = _mgmt_call_times.setdefault(key, collections.deque(maxlen=_MGMT_RATE_LIMIT_MAX))
    while times and now - times[0] > _MGMT_RATE_LIMIT_WINDOW_S:
        times.popleft()
    if len(times) >= _MGMT_RATE_LIMIT_MAX:
        return f"Rate limit exceeded for {key}. Retry after {int(_MGMT_RATE_LIMIT_WINDOW_S - (now - times[0]))}s."

    _global_call_times.append(now)
    times.append(now)
    return None


_MAX_SERVER_ID_LEN = 256
_MAX_COMMAND_LEN   = 1024
_MAX_URL_LEN       = 2048
_MAX_ARGS_COUNT    = 50
_MAX_ARG_LEN       = 1024
_MAX_ENV_VARS      = 50
_MAX_HEADER_PAIRS  = 20

mcp = FastMCP(
    "mcpsafetywarden",
    instructions=(
        "This server wraps other MCP servers and provides behavioral analysis of their tools. "
        "Typical flow: onboard_server -> safe_tool_call. "
        "Profiles improve automatically as more calls are made through safe_tool_call."
    ),
)



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
        sec_risk = sec_finding.get("risk_level")
        if sec_risk == "HIGH":
            risk = "high"
        elif sec_risk == "MEDIUM" and risk not in ("high",):
            risk = "medium"

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


@mcp.tool()
async def register_server(
    server_id: str,
    transport: str,
    command: Optional[str] = None,
    args: Optional[list] = None,
    url: Optional[str] = None,
    env: Optional[dict] = None,
    headers: Optional[dict] = None,
    auto_inspect: bool = True,
    classify_provider: Optional[str] = None,
    classify_model: Optional[str] = None,
    classify_api_key: Optional[str] = None,
) -> str:
    """
    Register an MCP server to wrap and profile.

transport options:
        "stdio"           - local process (supply command + args)
      "sse"             - legacy SSE remote server (supply url)
      "streamable_http" - modern hosted MCP servers (supply url; most common for cloud-hosted servers)

    headers: HTTP headers for sse/streamable_http, e.g. {"Authorization": "Bearer sk-..."}
    auto_inspect: immediately connect and discover tools (default true)
classify_provider:
        LLM to use for deep tool classification during inspect
      ("anthropic"|"openai"|"gemini"). Falls back to rule-based if omitted or on error.

    Security note: classify_api_key is accepted as a convenience for testing. In production,
    prefer setting the provider's API key via the corresponding environment variable instead
    of passing it as a parameter (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY).

Examples:
        stdio: command="python", args=["my_server.py"]
      streamable_http: url="https://mcp.example.com/mcp", headers={"Authorization": "Bearer TOKEN"}
    """
    rl = _check_mgmt_rate_limit(f"register:{server_id}")
    if rl:
        return json.dumps({"error": rl})

    if transport not in ("stdio", "sse", "streamable_http"):
        return json.dumps({"error": f"transport must be 'stdio', 'sse', or 'streamable_http', got '{transport}'"})
    if transport == "stdio" and not command:
        return json.dumps({"error": "command is required for stdio transport"})
    if transport in ("sse", "streamable_http") and not url:
        return json.dumps({"error": "url is required for sse/streamable_http transport"})

    # '::' is the tool_id separator; it must not appear in server_id.
    if "::" in server_id:
        return json.dumps({"error": "server_id must not contain '::'."})

    if len(server_id) > _MAX_SERVER_ID_LEN:
        return json.dumps({"error": f"server_id exceeds maximum length of {_MAX_SERVER_ID_LEN}."})
    if command and len(command) > _MAX_COMMAND_LEN:
        return json.dumps({"error": f"command exceeds maximum length of {_MAX_COMMAND_LEN}."})
    if url and len(url) > _MAX_URL_LEN:
        return json.dumps({"error": f"url exceeds maximum length of {_MAX_URL_LEN}."})
    if args and len(args) > _MAX_ARGS_COUNT:
        return json.dumps({"error": f"args list exceeds maximum of {_MAX_ARGS_COUNT} entries."})
    if args and any(len(str(a)) > _MAX_ARG_LEN for a in args):
        return json.dumps({"error": f"An arg value exceeds maximum length of {_MAX_ARG_LEN}."})
    if env and len(env) > _MAX_ENV_VARS:
        return json.dumps({"error": f"env dict exceeds maximum of {_MAX_ENV_VARS} entries."})
    if headers and len(headers) > _MAX_HEADER_PAIRS:
        return json.dumps({"error": f"headers dict exceeds maximum of {_MAX_HEADER_PAIRS} entries."})

    if url and SSRF_RE.search(url):
        return json.dumps({"error": "URL targets a private or restricted address and cannot be registered."})

    if transport == "stdio" and command:
        cmd_base = _os.path.basename(command).lower()
        if cmd_base.endswith(".exe"):
            cmd_base = cmd_base[:-4]
        if cmd_base in _SHELL_INTERPS and any(str(a).lower() in _SHELL_EVAL_FLAGS for a in (args or [])):
            return json.dumps({"error": "Registering a shell interpreter with an eval flag (-c, /c, -e) is not permitted."})

    _log.info("register_server server_id=%s transport=%s auto_inspect=%s", server_id, transport, auto_inspect)

    db.upsert_server(server_id, transport, command, args or [], url, env or {}, headers or {})
    result: Dict[str, Any] = {"registered": server_id, "transport": transport}

    if auto_inspect:
        try:
            tools = await cm.inspect_server_tools(
                server_id,
                llm_provider=classify_provider or _detect_llm_provider(),
                llm_model=classify_model,
                llm_api_key=classify_api_key,
            )
            result["tools_discovered"] = len(tools)
            result["tools"] = [
                {"name": t["name"], "effect_class": t["effect_class"], "confidence": t["confidence"]}
                for t in tools
            ]
        except (ValueError, RuntimeError) as exc:
            result["inspect_error"] = str(exc)
            result["hint"] = "Server registered. Fix the error then run inspect_server."
        except Exception as exc:
            _log.error("register_server auto-inspect failed for %s: %s", server_id, exc, exc_info=True)
            result["inspect_error"] = "Inspection failed. Check server logs."
            result["hint"] = "Server registered. Fix the error then run inspect_server."

    return json.dumps(result, indent=2)


@mcp.tool()
async def inspect_server(
    server_id: str,
    classify_provider: Optional[str] = None,
    classify_model: Optional[str] = None,
    classify_api_key: Optional[str] = None,
) -> str:
    """
    Connect to a registered MCP server, retrieve its tool list, classify each tool,
    and update stored profiles. Call this to refresh after server updates.

classify_provider:
        LLM to use for deep tool classification ("anthropic"|"openai"|"gemini").
        Auto-detected from env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY)
        if omitted. Falls back to rule-based if no key is found or the LLM call fails.
    """
    rl = _check_mgmt_rate_limit(f"inspect:{server_id}")
    if rl:
        return json.dumps({"error": rl})

    effective_provider = classify_provider or _detect_llm_provider()
    _log.info("inspect_server server_id=%s provider=%s", server_id, effective_provider or "rule_based")
    try:
        tools = await cm.inspect_server_tools(
            server_id,
            llm_provider=effective_provider,
            llm_model=classify_model,
            llm_api_key=classify_api_key,
        )
        return json.dumps(
            {"server_id": server_id, "tools_discovered": len(tools), "tools": tools},
            indent=2,
        )
    except (ValueError, RuntimeError) as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("inspect_server failed for %s: %s", server_id, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})


@mcp.tool()
def list_servers() -> str:
    """List all registered MCP servers with their tool counts."""
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
    """List all known tools for a server with their summarised behavior profiles."""
    tools = db.list_tools(server_id)
    if not tools:
            return json.dumps({
            "error": f"No tools found for '{server_id}'.",
            "hint": "Run inspect_server first.",
        })

    rows = []
    for t in tools:
        p = db.get_profile(t["tool_id"])
        rows.append({
            "name": t["tool_name"],
            "description": (t["description"] or "")[:100],
            "effect_class": p["effect_class"]   if p else "unknown",
            "retry_safety": p["retry_safety"]   if p else "unknown",
            "destructiveness":p["destructiveness"] if p else "unknown",
            "run_count": p["run_count"]       if p else 0,
            "confidence": p["confidence"].get("effect_class", 0) if p else 0,
        })

    return json.dumps({"server_id": server_id, "tools": rows}, indent=2)


@mcp.tool()
async def preflight_tool_call(
    server_id: str,
    tool_name: str,
    args: Optional[dict] = None,  # noqa: ARG001 (reserved for future arg-aware analysis)
    auto_scan_provider: Optional[str] = None,
    auto_scan_model: Optional[str] = None,
    auto_scan_api_key: Optional[str] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> str:
    """
    Get a behavioral risk assessment for a tool BEFORE executing it.

    Returns: effect class, retry safety, risk level, approval recommendation,
    latency band, output size risk, confidence, and evidence trail.

    auto_scan_provider: LLM provider to use if no security scan exists yet for this server.
    Auto-detected from env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY) if omitted.
    Accepts "anthropic", "openai", "gemini", "cisco", or "snyk". mcpsafety+ providers are NOT
    accepted here - use security_scan_server with confirm_authorized=True instead.
    Scan runs once on first preflight, result is stored and reused on all subsequent calls.
    Scan failure is non-fatal.
    """
    tool = db.get_tool(server_id, tool_name)
    if not tool:
        return json.dumps({
            "error": f"Tool '{tool_name}' not found on server '{server_id}'.",
            "hint": "Run inspect_server first.",
        })

    effective_scan_provider = auto_scan_provider or _detect_llm_provider()
    if effective_scan_provider and not db.get_latest_security_scan(server_id):
        # mcpsafety+ actively probes the live server and requires explicit authorization
        # (confirm_authorized=True). This auto-scan path must not bypass that requirement.
        if effective_scan_provider.startswith("mcpsafety+"):
            _log.warning(
                "Auto-scan skipped for mcpsafety+ provider on server '%s'. "
                "Use security_scan_server with confirm_authorized=True instead.",
                server_id,
            )
        else:
            try:
                server = db.get_server(server_id)
                tools  = db.list_tools(server_id)
                if effective_scan_provider == "cisco":
                    findings = await run_cisco_scan(server_id=server_id, server_config=server, cisco_api_key=auto_scan_api_key)
                elif effective_scan_provider == "snyk":
                    findings = await run_snyk_scan(server_id=server_id, server_config=server, snyk_token=auto_scan_api_key)
                else:
                    loop = asyncio.get_running_loop()
                    findings = await loop.run_in_executor(
                        None,
                        lambda: run_security_scan(
                            server_id=server_id, tools=tools,
                            provider=effective_scan_provider,
                            model_id=auto_scan_model,
                            api_key=auto_scan_api_key,
                        ),
                    )
                db.store_security_scan(server_id, findings)
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
        db.upsert_profile(tool["tool_id"], profile)
    return json.dumps(_preflight_assessment(profile, tool_name, server_id), indent=2)  # type: ignore[arg-type]




@mcp.tool()
def get_tool_profile(server_id: str, tool_name: str) -> str:
    """Get the full behavior profile for a tool including all observed metrics."""
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
    """Recommended retry policy for a tool based on its behavior profile."""
    tool = db.get_tool(server_id, tool_name)
    if not tool: return json.dumps({"error": f"Tool '{tool_name}' not found."})
    effective_llm = llm_provider or _detect_llm_provider()
    profile = db.get_profile(tool["tool_id"])
    if profile is None:
        profile = classify_tool(
            tool_name, tool.get("description", ""), tool.get("schema", {}), tool.get("annotations", {}),
            effective_llm, llm_model, llm_api_key,
        )
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
def suggest_safer_alternative(
    server_id: str,
    tool_name: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> str:
    """
    Find lower-risk alternatives to a tool on the same server.

    LLM path (default): auto-detects an available LLM provider from env vars
    (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY) and performs semantic
    matching across all server tools - finds functionally similar substitutes
    even when names differ, ranks by risk reduction, and explains what the agent
    gives up by switching. Pass llm_provider to override the auto-detected provider.

    Rule-based fallback: used when no LLM provider is available or the LLM returns
    nothing - looks for read-only tools with a similar name stem and no HIGH security flag.
    """
    tool = db.get_tool(server_id, tool_name)
    if not tool: return json.dumps({"error": f"Tool '{tool_name}' not found."})

    effective_llm = llm_provider or _detect_llm_provider()
    profile = db.get_profile(tool["tool_id"])
    if profile is None:
        profile = classify_tool(
            tool["tool_name"], tool.get("description", ""), tool.get("schema", {}), tool.get("annotations", {}),
            effective_llm, llm_model, llm_api_key,
        )
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
        candidates.append({
            **t,
            "_effect_class": (p or {}).get("effect_class", "unknown"),
            "_security_flag": s.get("risk_level") if s else None,
        })

    effective_provider = llm_provider or _detect_llm_provider()
    if effective_provider:
        llm_alts = _llm_suggest_alternatives(
            tool_name, tool.get("description", ""), current_effect, current_destr,
            current_sec_risk, current_sec_tags, candidates,
            effective_provider, llm_model, llm_api_key,
        )
        if llm_alts:
            return json.dumps({
                "tool": tool_name,
                "current_effect": current_effect,
                "current_security_flag": current_sec_risk,
                "method": "llm",
                "alternatives": llm_alts,
            }, indent=2)

    stem = tool_name.split("_", 1)[-1] if "_" in tool_name else tool_name

    def _candidate_is_secure_read_only(c: dict) -> bool:
        return c.get("_effect_class") == "read_only" and c.get("_security_flag") != "HIGH"

    alternatives = [
        {
            "tool": c["tool_name"],
            "description": (c["description"] or "")[:100],
            "effect_class": "read_only",
            "why_safer": "read-only, no security flags, similar name",
        }
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
) -> str:
    """
    Test idempotency by calling a tool twice with the same args and comparing outputs.
    WARNING: executes the tool TWICE - requires approved=True for any tool that is not
    read_only, or that has a HIGH/MEDIUM security flag or approval_recommended.
    """
    rl = _check_mgmt_rate_limit(f"replay:{server_id}")
    if rl:
        return json.dumps({"error": rl})

    tool = db.get_tool(server_id, tool_name)
    if not tool: return json.dumps({"error": f"Tool '{tool_name}' not found on server '{server_id}'."})

    profile = db.get_profile(tool["tool_id"])
    if profile is None:
        loop = asyncio.get_running_loop()
        profile = await loop.run_in_executor(
            None,
            lambda: classify_tool(
                tool_name, tool.get("description", ""), tool.get("schema", {}), tool.get("annotations", {}),
            ),
        )
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
"message":
                (
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
async def security_scan_server(
    server_id: str,
    provider: str,
    model_id: Optional[str] = None,
    api_key: Optional[str] = None,
    confirm_authorized: bool = False,
    allow_destructive_probes: bool = False,
    skip_web_research: bool = True,
    scan_timeout_s: int = 300,
) -> str:
    """
    Run a live security audit on a registered server's tools.

provider options:
        "anthropic"  - 5-stage pentest pipeline: Recon -> Planner -> Hacker (live probing) ->
        "openai"       Auditor (CVE/Arxiv research) -> Supervisor (final report + coverage gaps).
        "gemini"       Shorthand for mcpsafety+<provider>. Requires live server connection.
        "ollama"       api_key = LLM provider API key (falls back to env var).
                       Ollama: set OLLAMA_MODEL + optionally OLLAMA_BASE_URL (default localhost:11434).
      "cisco"        - AST + taint analysis + YARA rules offline; optional Cisco cloud ML engine.
                       api_key = Cisco AI Defense key (optional, enables cloud ML engine)
                       Set MCP_SCANNER_LLM_API_KEY for Cisco's internal LLM analysis
      "snyk"         - prompt injection, tool shadowing, toxic data flows, hardcoded secrets.
                       api_key = Snyk token (optional but needed for E001 prompt-injection detection)
                       Falls back to SNYK_TOKEN env var

mcpsafety options (apply to "anthropic", "openai", "gemini", "ollama"):
        confirm_authorized:      MUST be True - confirms you own and are authorized to test this server
      allow_destructive_probes: enable path traversal, command injection, credential file probes
                                 (default False - safe edge-case inputs only)
      skip_web_research:         skip DuckDuckGo/HackerNews/Arxiv CVE research (prevents leaking findings)
      scan_timeout_s:            hard timeout for the entire scan in seconds (default 300, max 3600)

    Results are stored and automatically included in future preflight_tool_call responses.
    """
    if provider in _LLM_SHORTHANDS:
        provider = f"mcpsafety+{provider}"

    if provider not in ALL_PROVIDERS:
        return json.dumps({
            "error": f"Unknown provider '{provider}'.",
            "valid_providers": sorted(_LLM_SHORTHANDS) + ALL_PROVIDERS,
        })

    server = db.get_server(server_id)
    if not server:
        return json.dumps({"error": f"Server '{server_id}' not registered."})

    rl = _check_mgmt_rate_limit(f"scan:{server_id}")
    if rl:
        return json.dumps({"error": rl})

    tools = db.list_tools(server_id)
    if not tools:
            return json.dumps({
            "error": f"No tools found for '{server_id}'.",
            "hint": "Run inspect_server first.",
        })

    scan_timeout_s = max(30, min(scan_timeout_s, 3600))

    _log.info(
        "security_scan_server server_id=%s provider=%s timeout=%ds",
        server_id, provider, scan_timeout_s,
    )

    try:
        if provider == "cisco":
                findings = await run_cisco_scan(
                server_id=server_id,
                server_config=server,
                cisco_api_key=api_key,
            )
        elif provider == "snyk":
                findings = await run_snyk_scan(
                server_id=server_id,
                server_config=server,
                snyk_token=api_key,
            )
        else:
            llm_provider = provider.split("+", 1)[1]
            findings = await run_mcpsafety_scan(
                server_id=server_id,
                tools=tools,
                server_config=server,
                llm_provider=llm_provider,
                model_id=model_id,
                api_key=api_key,
                confirm_authorized=confirm_authorized,
                allow_destructive_probes=allow_destructive_probes,
                skip_web_research=skip_web_research,
                scan_timeout_s=scan_timeout_s,
            )

        scan_id = db.store_security_scan(server_id, findings)
        findings["scan_id"] = scan_id
        findings.pop("provider", None)
        findings.pop("model", None)
        return json.dumps(findings, indent=2)

    except (ValueError, RuntimeError) as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("security_scan_server failed for %s provider=%s: %s", server_id, provider, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})


@mcp.tool()
def get_security_scan(server_id: str) -> str:
    """Retrieve the latest security scan report for a registered server."""
    scan = db.get_latest_security_scan(server_id)
    if not scan:
            return json.dumps({
            "error": f"No security scan found for '{server_id}'.",
            "hint": "Run security_scan_server first.",
        })
    return json.dumps(scan, indent=2)


@mcp.tool()
async def scan_all_servers(
    provider: str,
    model_id: Optional[str] = None,
    api_key: Optional[str] = None,
    confirm_authorized: bool = False,
    allow_destructive_probes: bool = False,
    skip_web_research: bool = True,
    scan_timeout_s: int = 300,
    server_ids: Optional[List[str]] = None,
) -> str:
    """
    Run the 5-stage MCPSafety pipeline against all registered servers (or a specified subset).

    Scans servers sequentially and returns a combined report with per-server results and
    an aggregate overall_risk_level reflecting the worst finding across all servers.
    Each server's result is also stored and will appear in future preflight_tool_call responses.

    provider:      "anthropic" | "openai" | "gemini" | "ollama"
                   (same providers as security_scan_server; cisco/snyk not supported here)
    server_ids:    optional list of server IDs to scan; scans all registered servers if omitted
    confirm_authorized: MUST be True - confirms you own and are authorized to test all listed servers
    allow_destructive_probes: enable path traversal, command injection, credential file probes
    skip_web_research: skip DuckDuckGo/HackerNews/Arxiv research (prevents leaking findings externally)
    scan_timeout_s: timeout per server in seconds (default 300, max 3600)
    """
    if provider in _LLM_SHORTHANDS:
        provider = f"mcpsafety+{provider}"

    if not provider.startswith("mcpsafety+"):
        return json.dumps({
            "error": f"scan_all_servers only supports mcpsafety+ providers. Got '{provider}'.",
            "valid_providers": sorted(_LLM_SHORTHANDS),
        })

    llm_provider = provider.split("+", 1)[1]
    if llm_provider not in ("anthropic", "openai", "gemini", "ollama"):
        return json.dumps({"error": f"Unknown LLM provider '{llm_provider}'."})

    rl = _check_mgmt_rate_limit("scan_all")
    if rl:
        return json.dumps({"error": rl})

    all_server_rows = db.list_servers(include_credentials=True)
    if server_ids:
        sid_set = set(server_ids)
        all_server_rows = [s for s in all_server_rows if s["server_id"] in sid_set]
    if not all_server_rows:
        return json.dumps({"error": "No registered servers found.", "hint": "Run register_server or onboard_server first."})

    servers_payload = []
    skipped = []
    for row in all_server_rows:
        sid = row["server_id"]
        tools = db.list_tools(sid)
        if not tools:
            skipped.append({"server_id": sid, "reason": "no tools registered - run inspect_server first"})
            continue
        servers_payload.append({"server_id": sid, "tools": tools, "server_config": row})

    if not servers_payload:
        return json.dumps({
            "error": "No servers with registered tools.",
            "skipped": skipped,
            "hint": "Run inspect_server for each server first.",
        })

    scan_timeout_s = max(30, min(scan_timeout_s, 3600))
    _log.info(
        "scan_all_servers: %d servers provider=%s timeout=%ds",
        len(servers_payload), provider, scan_timeout_s,
    )

    try:
        combined = await run_mcpsafety_scan_multi(
            servers=servers_payload,
            llm_provider=llm_provider,
            model_id=model_id,
            api_key=api_key,
            confirm_authorized=confirm_authorized,
            allow_destructive_probes=allow_destructive_probes,
            skip_web_research=skip_web_research,
            scan_timeout_s=scan_timeout_s,
        )
    except (ValueError, RuntimeError) as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("scan_all_servers failed provider=%s: %s", provider, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})

    for sid, result in combined.get("server_results", {}).items():
        try:
            db.store_security_scan(sid, result)
        except Exception as db_exc:
            _log.warning("scan_all_servers: failed to store scan for '%s': %s", sid, db_exc)

    if skipped:
        combined["skipped_servers"] = skipped

    return json.dumps(combined, indent=2)


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
                "blocked": True,
                "reason": "arg_scan_blocked",
                "tool": tool_name,
                **{k: v for k, v in threat.items() if k != "reason"},
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
    End-to-end safe tool execution with automatic risk gating and alternative selection.

    First call: runs preflight. Low risk executes immediately. Medium/high risk returns
    a numbered alternatives list ending with a "More options" entry.

    use_alternative: re-call with the name of a listed alternative to execute it instead.
    show_more_options: re-call with True to see proceed-anyway and abort options.
    approved: re-call with True to execute the original tool despite its risk level.
    """
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
        db.upsert_profile(tool["tool_id"], profile)
    assessment = _preflight_assessment(profile, tool_name, server_id)
    risk_level = assessment["assessment"]["risk_level"]

    if not assessment["assessment"]["approval_recommended"]:
        return await _call_and_format(
            server_id, tool_name, args or {},
            args_scan_override=args_scan_override,
            llm_provider=llm_provider or _detect_llm_provider(),
            llm_model=llm_model, llm_api_key=llm_api_key,
            tool_description=tool.get("description", ""),
        )

    if approved:
        return await _call_and_format(
            server_id, tool_name, args or {},
            {"executed_with": "explicit_approval", "risk_level": risk_level},
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

    return json.dumps({
        "blocked": True,
        "reason": "approval_required",
        "tool": tool_name,
        "risk_level": risk_level,
        "preflight": assessment,
        "alternatives": choices,
    }, indent=2)


@mcp.tool()
async def onboard_server(
    server_id: str,
    transport: str,
    command: Optional[str] = None,
    args: Optional[list] = None,
    url: Optional[str] = None,
    env: Optional[dict] = None,
    headers: Optional[dict] = None,
    scan_provider: Optional[str] = None,
    scan_model: Optional[str] = None,
    scan_api_key: Optional[str] = None,
    confirm_scan_authorized: bool = False,
) -> str:
    """
    One-shot server onboarding: register + security scan + inspect in sequence.
    Equivalent to calling register_server then security_scan_server manually.

    confirm_scan_authorized: set True to confirm you own this server and authorize
    active security probing (required for mcpsafety+ providers).
    """
    reg_json = await register_server(
        server_id=server_id, transport=transport,
        command=command, args=args, url=url, env=env, headers=headers,
        auto_inspect=True,
        classify_provider=scan_provider,
        classify_model=scan_model,
        classify_api_key=scan_api_key,
    )
    reg_result = json.loads(reg_json)
    result: Dict[str, Any] = {"server_id": server_id, "register": reg_result, "security_scan": None}

    if "error" in reg_result:
        return json.dumps(result, indent=2)

    effective_provider = scan_provider or _detect_llm_provider()
    if not effective_provider:
        result["security_scan"] = {
            "skipped": "No LLM provider detected. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY.",
        }
        return json.dumps(result, indent=2)

    try:
        scan_json = await security_scan_server(
            server_id=server_id, provider=effective_provider,
            model_id=scan_model, api_key=scan_api_key,
            confirm_authorized=confirm_scan_authorized,
        )
        result["security_scan"] = json.loads(scan_json)
    except Exception as exc:
        _log.error("onboard_server scan failed for %s: %s", server_id, exc, exc_info=True)
        result["security_scan"] = {"error": "Scan failed. Check server logs."}

    return json.dumps(result, indent=2)


@mcp.tool()
def set_tool_policy(
    server_id: str,
    tool_name: str,
    policy: Optional[str] = None,
) -> str:
    """
    Set a permanent execution policy for a tool.

    policy: "allow" - always execute without preflight (trusted tool).
            "block" - never execute regardless of approval.
            null    - clear any existing policy, resume normal preflight flow.
    """
    tool = db.get_tool(server_id, tool_name)
    if not tool:
        return json.dumps({"error": f"Tool '{tool_name}' not found on server '{server_id}'."})
    if policy is not None and policy not in ("allow", "block"):
        return json.dumps({"error": "policy must be 'allow', 'block', or null to clear."})
    db.set_tool_policy(server_id, tool_name, policy)
    return json.dumps({
        "server_id": server_id,
        "tool": tool_name,
        "policy": policy if policy is not None else "cleared",
    }, indent=2)


@mcp.tool()
def get_run_history(server_id: str, tool_name: str, limit: int = 20) -> str:
    """Recent execution history for a tool: timestamps, latency, success/fail, injection warnings."""
    tool = db.get_tool(server_id, tool_name)
    if not tool:
        return json.dumps({"error": f"Tool '{tool_name}' not found on server '{server_id}'."})
    limit = max(1, min(limit, 200))
    runs = db.get_runs(tool["tool_id"], limit)
    return json.dumps({"server_id": server_id, "tool": tool_name, "runs": runs}, indent=2)


@mcp.tool()
async def ping_server(server_id: str) -> str:
    """Check if a registered server is reachable. Returns status and round-trip latency."""
    try:
        result = await cm.ping_server(server_id)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("ping_server failed for %s: %s", server_id, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})

    server = db.get_server(server_id)
    if server:
        network_scan = await kali_recon(server, fast=True)
        if network_scan:
            result["network_scan"] = network_scan

    return json.dumps({"server_id": server_id, **result}, indent=2)


if __name__ == "__main__":
    transport = _os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        mcp.run()
    else:
        import uvicorn
        host = _os.environ.get("MCP_HOST", "127.0.0.1")
        port = int(_os.environ.get("MCP_PORT", "8000"))
        t = "streamable_http" if transport in ("http", "streamable_http") else "sse"
        uvicorn.run(create_http_app(t), host=host, port=port)
