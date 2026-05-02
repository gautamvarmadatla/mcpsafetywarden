import asyncio
import collections
import hmac
import json
import logging
import os as _os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from . import database as db
from . import client_manager as cm
from . import discovery as _discovery
from .classifier import classify_tool
from .scanner import ALL_PROVIDERS, call_llm, detect_llm_provider as _detect_llm_provider, run_cisco_scan, run_snyk_scan, run_security_scan, auto_detect_providers as _auto_detect_providers, merge_findings as _merge_findings
from .drift import compare_db_snapshots as _compare_tool_snapshots, check_server_drift as _check_drift
from .mcpsafety_scanner import run_mcpsafety_scan, run_mcpsafety_scan_multi, run_deterministic_scan
from .arg_scanner import SSRF_RE, scan_args_for_threats
from .aux_integrations import kali_recon, burp_proxy_evidence
from .security_utils import sanitise_for_prompt as _sanitise_for_prompt, strip_json_fence as _strip_json_fence, looks_like_secret as _looks_like_secret
from .graph import store as _graph_store, builder as _graph_builder, explain as _graph_explain, provenance as _graph_provenance

_log = logging.getLogger(__name__)

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
        if len(candidate) != len(expected) or not hmac.compare_digest(candidate, expected):
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


_PREFLIGHT_SCAN_TIMEOUT_S = 60
_preflight_scan_locks: Dict[str, asyncio.Lock] = {}

_MGMT_RATE_LIMIT_MAX      = 10
_MGMT_RATE_LIMIT_WINDOW_S = 60
_GLOBAL_RATE_LIMIT_MAX    = 100
_MGMT_DICT_MAX_ENTRIES    = 5_000
_mgmt_call_times: Dict[str, collections.deque] = {}
_global_call_times: collections.deque = collections.deque(maxlen=_GLOBAL_RATE_LIMIT_MAX)
_bg_scan_status: Dict[str, str] = {}


def _gh_on_registered(server_id: str, transport: str, command: Optional[str], url: Optional[str]) -> None:
    try:
        _graph_builder.on_server_registered(server_id, transport, command, url)
    except Exception as _ge:
        _log.debug("graph hook on_server_registered failed: %s", _ge)


def _gh_on_tools_inspected(
    server_id: str,
    tools: List[Dict[str, Any]],
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> None:
    try:
        tool_ids = [
            t.get("tool_id") or f"{server_id}::{t.get('tool_name') or t.get('name', '')}"
            for t in tools
        ]
        profiles = db.get_profiles_batch([tid for tid in tool_ids if tid])
        enriched = [
            {**t, **(profiles.get(
                t.get("tool_id") or f"{server_id}::{t.get('tool_name') or t.get('name', '')}",
                {},
            ) or {})}
            for t in tools
        ]
        _graph_builder.on_tools_inspected(
            server_id, enriched,
            llm_provider=llm_provider, llm_model=llm_model, llm_api_key=llm_api_key,
        )
    except Exception as _ge:
        _log.debug("graph hook on_tools_inspected failed: %s", _ge)


def _gh_on_credentials_detected(server_id: str, cref_map: Dict[str, Any]) -> None:
    env_keys = list((cref_map.get("env") or {}).keys())
    header_keys = list((cref_map.get("headers") or {}).keys())
    if not env_keys and not header_keys:
        return
    try:
        _graph_builder.on_credentials_detected(server_id, env_keys, header_keys)
    except Exception as _ge:
        _log.debug("graph hook on_credentials_detected failed: %s", _ge)


def _gh_cleanup_server(server_id: str) -> None:
    try:
        _graph_builder.cleanup_server_graph(server_id)
    except Exception as _ge:
        _log.debug("graph hook cleanup_server failed for %s: %s", server_id, _ge)


def _gh_on_scan_stored(server_id: str, findings: Dict[str, Any]) -> None:
    try:
        _graph_builder.on_scan_stored(server_id, findings)
    except Exception as _ge:
        _log.debug("graph hook on_scan_stored failed: %s", _ge)


def _gh_on_composition_analysis(
    server_id: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> None:
    try:
        _graph_builder.on_composition_analysis(server_id, llm_provider, llm_model, llm_api_key)
    except Exception as _ge:
        _log.debug("graph hook on_composition_analysis failed: %s", _ge)


def _gh_on_provenance_detected(server_id: str, prov_info: Dict[str, Any]) -> None:
    try:
        _graph_builder.on_provenance_detected(server_id, prov_info)
    except Exception as _ge:
        _log.debug("graph hook on_provenance_detected failed: %s", _ge)


def _gh_on_server_discovered(
    discovery_id: str, client: str, client_name: str, server_name: str,
    registered_server_id: Optional[str] = None,
) -> None:
    try:
        _graph_builder.on_server_discovered(discovery_id, client, client_name, server_name, registered_server_id)
    except Exception as _ge:
        _log.debug("graph hook on_server_discovered failed: %s", _ge)


def _try_link_stdio_to_client(server_id: str, command: Optional[str], args: Optional[list]) -> None:
    """Match a manually registered stdio server against discovery configs and link it to its client."""
    if not command:
        return
    try:
        candidates = _discovery.discover_mcp_servers()
        cmd_base = _os.path.basename(command).lower()
        if cmd_base.endswith(".exe"):
            cmd_base = cmd_base[:-4]
        args_norm = [str(a) for a in (args or [])]
        for entry in candidates:
            if not entry.get("command"):
                continue
            e_base = _os.path.basename(entry["command"]).lower()
            if e_base.endswith(".exe"):
                e_base = e_base[:-4]
            if e_base != cmd_base:
                continue
            if [str(a) for a in (entry.get("args") or [])] != args_norm:
                continue
            did = entry["discovery_id"]
            db.upsert_discovered_server({
                **entry,
                "registered_server_id": server_id,
            })
            db.mark_discovered_registered(did, server_id)
            _gh_on_server_discovered(
                did, entry["client"], entry["client_name"], entry["server_name"], server_id,
            )
            _log.info("Linked server '%s' to client '%s' via stdio fingerprint match", server_id, entry["client"])
    except Exception as exc:
        _log.debug("_try_link_stdio_to_client failed for %s: %s", server_id, exc)


def _gh_on_cross_server_analysis(server_id: str) -> None:
    try:
        conn = db.get_connection()
        try:
            rows = conn.execute(
                "SELECT DISTINCT client FROM discovered_servers WHERE registered_server_id = ?",
                (server_id,),
            ).fetchall()
            client_ids = [r["client"] for r in rows]
        finally:
            conn.close()
        for cid in client_ids:
            _graph_builder.on_cross_server_analysis(cid)
    except Exception as exc:
        _log.debug("_gh_on_cross_server_analysis failed for %s: %s", server_id, exc)


def _check_mgmt_rate_limit(key: str) -> Optional[str]:
    now = time.monotonic()

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
        "Security proxy that wraps MCP servers to enforce risk gating, behavioral profiling, "
        "and security scanning before any tool is called. "
        "All tool calls to wrapped servers MUST go through safe_tool_call, never directly. "

        "ENTRY POINT - pick the right starting point based on what you have: "
        "- User mentions a server by name/URL but it is not registered -> onboard_server (one-shot preferred) or register_server. "
        "- User asks what servers are available on this machine -> discover_servers -> onboard_discovered_servers. "
        "- Server is already registered and user wants to call a tool -> safe_tool_call directly. "
        "- User has a GitHub URL but no local setup (server not running) -> security_scan_server(github_url=...) for source-only scan, then user fixes local setup, then onboard_server. "
        "- User wants a security audit of an already-registered server -> security_scan_server(server_id=...). "
        "- User wants to check for drift since last scan -> check_server_drift. "

        "FLOWS after entry: "
        "(1) discover_servers -> onboard_discovered_servers -> safe_tool_call. "
        "(2) onboard_server -> review scan in response -> set_tool_policy('block') for HIGH-risk tools -> safe_tool_call. "
        "(3) register_server -> security_scan_server -> get_security_scan (poll every 30s) -> set_tool_policy('block') -> safe_tool_call. "
        "(4) safe_tool_call blocked -> safe_tool_call(approved=True) | safe_tool_call(use_alternative=X) | suggest_safer_alternative. "
        "(5) check_server_drift severity MEDIUM+ -> security_scan_server -> get_security_scan -> update policies. "

        "NEVER: "
        "- Call preflight_tool_call before safe_tool_call (safe_tool_call runs it internally). "
        "- Skip security_scan_server for an untrusted server that was just registered. "
        "- Call wrapped server tools directly - always use safe_tool_call. "
        "- Pass provider= to security_scan_server unless the user explicitly names one (omit it to auto-detect from env keys). "
        "- Call set_tool_policy after a source-only scan (no server is registered, policies do not apply)."
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


async def _is_ssrf_hostname(url: str) -> bool:
    import socket
    from urllib.parse import urlparse
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        loop = asyncio.get_event_loop()
        infos = await loop.run_in_executor(None, lambda: socket.getaddrinfo(hostname, None))
        for info in infos:
            if SSRF_RE.search(info[4][0]):
                return True
    except Exception:
        pass
    return False


async def _do_register(
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
    github_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Core registration logic shared by register_server and onboard_discovered_servers."""
    if transport not in ("stdio", "sse", "streamable_http"):
        return {"error": f"transport must be 'stdio', 'sse', or 'streamable_http', got '{transport}'"}
    if transport == "stdio" and not command:
        return {"error": "command is required for stdio transport"}
    if transport in ("sse", "streamable_http") and not url:
        return {"error": "url is required for sse/streamable_http transport"}
    if "::" in server_id:
        return {"error": "server_id must not contain '::'."}
    if len(server_id) > _MAX_SERVER_ID_LEN:
        return {"error": f"server_id exceeds maximum length of {_MAX_SERVER_ID_LEN}."}
    if command and len(command) > _MAX_COMMAND_LEN:
        return {"error": f"command exceeds maximum length of {_MAX_COMMAND_LEN}."}
    if url and len(url) > _MAX_URL_LEN:
        return {"error": f"url exceeds maximum length of {_MAX_URL_LEN}."}
    if args and len(args) > _MAX_ARGS_COUNT:
        return {"error": f"args list exceeds maximum of {_MAX_ARGS_COUNT} entries."}
    if args and any(len(str(a)) > _MAX_ARG_LEN for a in args):
        return {"error": f"An arg value exceeds maximum length of {_MAX_ARG_LEN}."}
    if env and len(env) > _MAX_ENV_VARS:
        return {"error": f"env dict exceeds maximum of {_MAX_ENV_VARS} entries."}
    if headers and len(headers) > _MAX_HEADER_PAIRS:
        return {"error": f"headers dict exceeds maximum of {_MAX_HEADER_PAIRS} entries."}

    _parsed_host = url and __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url).hostname or ""
    _is_loopback = _parsed_host in ("localhost", "127.0.0.1") or _parsed_host.startswith("127.")
    if url and not _is_loopback and SSRF_RE.search(url):
        return {"error": "URL targets a private or restricted address and cannot be registered."}
    if url and not _is_loopback and await _is_ssrf_hostname(url):
        return {"error": "URL targets a private or restricted address and cannot be registered."}

    if transport == "stdio" and command:
        cmd_base = _os.path.basename(command).lower()
        if cmd_base.endswith(".exe"):
            cmd_base = cmd_base[:-4]
        if cmd_base in _SHELL_INTERPS and any(str(a).lower() in _SHELL_EVAL_FLAGS for a in (args or [])):
            return {"error": "Registering a shell interpreter with an eval flag (-c, /c, -e) is not permitted."}

    _log.info("_do_register server_id=%s transport=%s auto_inspect=%s", server_id, transport, auto_inspect)

    old_cref_ids: List[str] = []
    existing = db.get_server(server_id)
    if existing:
        for _d in (existing.get("headers") or {}, existing.get("env") or {}):
            for v in _d.values():
                if isinstance(v, str) and v.startswith("cref_"):
                    old_cref_ids.append(v)

    cref_map: Dict[str, Dict[str, str]] = {}
    safe_env: Dict[str, str] = {}
    for k, v in (env or {}).items():
        if isinstance(v, str) and _looks_like_secret(v):
            ref = db.create_credential_ref(v)
            safe_env[k] = ref
            cref_map.setdefault("env", {})[k] = ref
        else:
            safe_env[k] = v

    safe_headers: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        if isinstance(v, str) and _looks_like_secret(v):
            ref = db.create_credential_ref(v)
            safe_headers[k] = ref
            cref_map.setdefault("headers", {})[k] = ref
        else:
            safe_headers[k] = v

    db.upsert_server(server_id, transport, command, args or [], url, safe_env, safe_headers, github_url)
    _gh_on_registered(server_id, transport, command, url)
    _gh_on_credentials_detected(server_id, cref_map)
    if transport == "stdio":
        _try_link_stdio_to_client(server_id, command, args)

    try:
        _prov = await asyncio.get_running_loop().run_in_executor(
            None, lambda: _graph_provenance.build_provenance_info(
                server_id, command, args or [], url=url, transport=transport,
                github_url=github_url,
            )
        )
        _gh_on_provenance_detected(server_id, _prov)
    except Exception as _pe:
        _log.debug("provenance detection skipped for %s: %s", server_id, _pe)

    still_in_use = set(safe_headers.values()) | set(safe_env.values())
    db.delete_credential_refs([c for c in old_cref_ids if c not in still_in_use])

    result: Dict[str, Any] = {"registered": server_id, "transport": transport}
    if cref_map:
        result["credential_refs"] = cref_map
        result["credential_refs_note"] = (
            f"{sum(len(v) for v in cref_map.values())} secret(s) detected and stored securely. "
            "Original values replaced with cref_ identifiers shown above. "
            "The model context never holds the real credentials."
        )

    if auto_inspect:
        _stdio_hint = (
            "stdio server requires local setup before it can be inspected. "
            "Use onboard_server with github_url to run a source-only scan instead."
        )
        try:
            tools = await cm.inspect_server_tools(
                server_id,
                llm_provider=classify_provider or _detect_llm_provider(),
                llm_model=classify_model,
                llm_api_key=classify_api_key,
            )
            _gh_on_tools_inspected(
                server_id, tools,
                llm_provider=classify_provider or _detect_llm_provider(),
                llm_model=classify_model,
                llm_api_key=classify_api_key,
            )
            _gh_on_cross_server_analysis(server_id)
            result["tools_discovered"] = len(tools)
            result["tools"] = [
                {"name": t["name"], "effect_class": t["effect_class"], "confidence": t["confidence"]}
                for t in tools
            ]
        except (ValueError, RuntimeError) as exc:
            db.delete_server(server_id)
            _gh_cleanup_server(server_id)
            _crefs_for_server = [v for v in still_in_use if isinstance(v, str) and v.startswith("cref_")]
            db.delete_credential_refs(_crefs_for_server)
            return {
                "error": f"Registration aborted - inspection failed: {exc}",
                "inspect_error": str(exc),
                "hint": _stdio_hint if transport == "stdio" else "Fix the server and try again.",
            }
        except Exception as exc:
            _log.error("_do_register auto-inspect failed for %s: %s", server_id, exc, exc_info=True)
            db.delete_server(server_id)
            _gh_cleanup_server(server_id)
            _crefs_for_server = [v for v in still_in_use if isinstance(v, str) and v.startswith("cref_")]
            db.delete_credential_refs(_crefs_for_server)
            return {
                "error": "Registration aborted - inspection failed.",
                "inspect_error": str(exc),
                "hint": _stdio_hint if transport == "stdio" else "Fix the server and try again.",
            }

    return result


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
    github_url: Optional[str] = None,
) -> str:
    """
    Register a server so it can be wrapped, profiled, and called via safe_tool_call.
    Prefer onboard_server for a single trusted server - it does register + security scan + inspect in one call.
    Use register_server directly only when you want to control the steps separately.

    transport: "stdio" (local process, supply command+args) | "sse" (legacy remote, supply url) | "streamable_http" (modern hosted, supply url)
    auto_inspect: connect immediately and discover tools (default true). Set false only if the server is not yet running.
    headers: auth headers for remote servers, e.g. {"Authorization": "Bearer TOKEN"}.
        Secret values (Bearer tokens, API keys) are automatically detected and replaced with
        opaque cref_ identifiers before anything is stored. The response includes a
        credential_refs map showing which keys were substituted. Real credentials never
        appear in model context or conversation history.
    github_url: optional repo URL; enables source code analysis in subsequent security scans.

    NEXT STEPS after success:
    - Run security_scan_server to audit the tools before trusting this server.
    - Then use safe_tool_call to execute tools with automatic risk gating.
    - If auto_inspect failed (stdio server not yet running): fix local setup, then call inspect_server.
    """
    rl = _check_mgmt_rate_limit(f"register:{server_id}")
    if rl:
        return json.dumps({"error": rl})
    result = await _do_register(
        server_id=server_id, transport=transport, command=command, args=args,
        url=url, env=env, headers=headers, auto_inspect=auto_inspect,
        classify_provider=classify_provider, classify_model=classify_model,
        classify_api_key=classify_api_key, github_url=github_url,
    )
    if "error" in result:
        return json.dumps(result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def inspect_server(
    server_id: str,
    classify_provider: Optional[str] = None,
    classify_model: Optional[str] = None,
    classify_api_key: Optional[str] = None,
) -> str:
    """
    Re-connect to a registered server, enumerate its tools, classify each one, and update stored profiles.

    Use this when register_server was called with auto_inspect=False (server was not yet running),
    or after a server update to refresh tool definitions and risk classifications.

    BEFORE: register_server or onboard_server (server must be registered).
    AFTER: run security_scan_server if untrusted; use list_server_tools to review discovered tools.
    Drift from the previous baseline is reported automatically if a prior snapshot exists.

    classify_provider: LLM for tool classification ("anthropic"|"openai"|"gemini").
    Auto-detected from ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY if omitted.
    Falls back to rule-based classification if no LLM key is found.
    """
    rl = _check_mgmt_rate_limit(f"inspect:{server_id}")
    if rl:
        return json.dumps({"error": rl})

    effective_provider = classify_provider or _detect_llm_provider()
    _log.info("inspect_server server_id=%s provider=%s", server_id, effective_provider or "rule_based")

    old_tools = {t["tool_name"]: t for t in db.list_tools(server_id)}

    try:
        tools = await cm.inspect_server_tools(
            server_id,
            llm_provider=effective_provider,
            llm_model=classify_model,
            llm_api_key=classify_api_key,
        )
        _gh_on_tools_inspected(server_id, tools)

        try:
            _srv = db.get_server(server_id)
            if _srv:
                _prov = await asyncio.get_running_loop().run_in_executor(
                    None, lambda: _graph_provenance.build_provenance_info(
                        server_id, _srv.get("command"), _srv.get("args") or [],
                        url=_srv.get("url"), transport=_srv.get("transport"),
                        github_url=_srv.get("github_url"),
                    )
                )
                _gh_on_provenance_detected(server_id, _prov)
        except Exception as _pe:
            _log.debug("provenance refresh skipped for %s: %s", server_id, _pe)

        result: Dict[str, Any] = {
            "server_id": server_id,
            "tools_discovered": len(tools),
            "tools": tools,
        }
        if old_tools:
            new_tools = {t["tool_name"]: t for t in db.list_tools(server_id)}
            drift = _compare_tool_snapshots(
                server_id, old_tools, new_tools,
                datetime.now(timezone.utc).isoformat(),
            )
            if drift["drift_detected"]:
                result["drift"] = drift
                _log.warning(
                    "inspect_server: drift detected for %s severity=%s findings=%d",
                    server_id, drift["overall_severity"], len(drift["findings"]),
                )
        return json.dumps(result, indent=2)
    except (ValueError, RuntimeError) as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("inspect_server failed for %s: %s", server_id, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})


@mcp.tool()
async def check_server_drift(
    server_id: str,
    update_baseline: bool = True,
) -> str:
    """
    Detect tool schema and tool-list changes since the last inspect_server baseline.

    Run this periodically or whenever a server may have been updated.
    CRITICAL/HIGH drift means safe_tool_call may fail for affected tools.
    MEDIUM drift (description changed) is a prompt-injection risk - re-scan after.

    Severities:
      CRITICAL: tool removed (safe_tool_call will error for that tool)
      HIGH: parameter removed or type changed
      MEDIUM: description changed (prompt-injection risk) or new required param
      LOW: new optional param or new tool added

    update_baseline: True (default) updates baseline after reporting, so repeated calls
    track incremental changes. Set False to audit without modifying the baseline.

    BEFORE: inspect_server (to establish initial baseline).
    AFTER severity CRITICAL/HIGH: inspect_server to re-establish baseline.
    AFTER severity MEDIUM+: security_scan_server to re-audit for prompt-injection in new descriptions.
    """
    rl = _check_mgmt_rate_limit(f"drift:{server_id}")
    if rl:
        return json.dumps({"error": rl})
    try:
        result = await _check_drift(server_id, update_baseline=update_baseline)
        if result.get("drift_detected"):
            server_rec = db.get_server(server_id)
            if server_rec:
                try:
                    loop = asyncio.get_running_loop()
                    prov = await loop.run_in_executor(
                        None,
                        lambda: _graph_provenance.build_provenance_info(
                            server_id,
                            command=server_rec.get("command"),
                            args=server_rec.get("args") or [],
                            url=server_rec.get("url"),
                            transport=server_rec.get("transport", "stdio"),
                            github_url=server_rec.get("github_url"),
                        ),
                    )
                    _gh_on_provenance_detected(server_id, prov)
                    result["provenance_rechecked"] = True
                except Exception as _pe:
                    _log.debug("provenance re-check after drift failed for %s: %s", server_id, _pe)
        return json.dumps(result, indent=2)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("check_server_drift failed for %s: %s", server_id, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})


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


def _build_supply_chain_findings(server_id: str) -> Dict[str, Any]:
    sc_findings = []
    for fid in [
        f"finding::dep_cve::{server_id}",
        f"finding::dep_typosquat::{server_id}",
        f"finding::cert_changed::{server_id}",
        f"finding::dns_changed::{server_id}",
        f"finding::private_ip::{server_id}",
    ]:
        obj = _graph_store.get_object(fid)
        if obj:
            meta = obj.get("metadata", {})
            sc_findings.append({
                "finding_type": obj["name"],
                "risk_level": meta.get("risk_level", "UNKNOWN"),
                "risk_tags": meta.get("risk_tags", []),
                "remediation": meta.get("remediation", ""),
                "exploitation_scenario": meta.get("exploitation_scenario", ""),
                "details": {
                    k: v for k, v in meta.items()
                    if k not in ("risk_level", "risk_tags", "remediation", "exploitation_scenario")
                },
            })

    prov_obj = _graph_store.get_object(f"provenance::{server_id}")
    provenance_summary = None
    if prov_obj:
        pm = prov_obj.get("metadata", {})
        provenance_summary = {
            "package": prov_obj["name"],
            "ecosystem": pm.get("ecosystem"),
            "verified": pm.get("verified"),
            "attestation_status": (pm.get("attestation") or {}).get("attestation_status"),
            "version_drift": pm.get("version_drift"),
            "local_environment": pm.get("local_environment"),
        }

    return {
        "supply_chain_findings": sc_findings,
        "supply_chain_risk_count": len(sc_findings),
        "provenance_summary": provenance_summary,
    }


async def _execute_scan_core(
    server_id: str,
    server: Dict,
    tools: List[Dict],
    providers_to_run: List[str],
    model_id: Optional[str],
    api_key: Optional[str],
    confirm_authorized: bool,
    allow_destructive_probes: bool,
    skip_web_research: bool,
    scan_timeout_s: int,
    github_url: Optional[str] = None,
) -> Dict[str, Any]:
    effective_github_url = github_url or server.get("github_url")

    prov_obj = _graph_store.get_object(f"provenance::{server_id}")
    local_source_path: Optional[str] = None
    if prov_obj:
        loc = prov_obj.get("metadata", {}).get("location", "")
        if loc and _os.path.isdir(loc):
            local_source_path = loc

    async def _run_one(prov: str) -> Dict[str, Any]:
        try:
            if prov == "cisco":
                return await run_cisco_scan(server_id=server_id, server_config=server, cisco_api_key=api_key)
            if prov == "snyk":
                return await run_snyk_scan(server_id=server_id, server_config=server, snyk_token=api_key)
            llm_prov = prov.split("+", 1)[1]
            return await run_mcpsafety_scan(
                server_id=server_id, tools=tools, server_config=server,
                llm_provider=llm_prov, model_id=model_id, api_key=api_key,
                confirm_authorized=confirm_authorized,
                allow_destructive_probes=allow_destructive_probes,
                skip_web_research=skip_web_research,
                scan_timeout_s=scan_timeout_s,
                github_url=effective_github_url,
                local_source_path=local_source_path,
            )
        except Exception as exc:
            _log.error("security_scan_server provider=%s failed: %s", prov, exc, exc_info=True)
            return {"error": str(exc), "provider": prov}

    if len(providers_to_run) == 1:
        findings = await _run_one(providers_to_run[0])
        if "error" in findings and "overall_risk_level" not in findings:
            return json.dumps(findings, indent=2)
    else:
        results = await asyncio.gather(*[_run_one(p) for p in providers_to_run])
        findings = _merge_findings(server_id, list(results))

    sc = _build_supply_chain_findings(server_id)
    findings["supply_chain_findings"] = sc["supply_chain_findings"]
    findings["supply_chain_risk_count"] = sc["supply_chain_risk_count"]
    findings["provenance_summary"] = sc["provenance_summary"]

    scan_id = db.store_security_scan(server_id, findings)
    _gh_on_scan_stored(server_id, findings)
    _llm_prov = next(
        (p.split("+", 1)[1] for p in providers_to_run if p.startswith("mcpsafety+")),
        None,
    )
    _gh_on_composition_analysis(server_id, _llm_prov, model_id, api_key)
    findings["scan_id"] = scan_id
    if "providers" not in findings:
        findings["providers"] = [findings.pop("provider", providers_to_run[0])]
    else:
        findings.pop("provider", None)
    findings.pop("model", None)
    return findings


@mcp.tool()
async def security_scan_server(
    server_id: Optional[str] = None,
    provider: Optional[str] = None,
    model_id: Optional[str] = None,
    api_key: Optional[str] = None,
    confirm_authorized: bool = False,
    allow_destructive_probes: bool = False,
    skip_web_research: bool = True,
    scan_timeout_s: int = 900,
    background: bool = True,
    github_url: Optional[str] = None,
) -> str:
    """
    Run a security audit on a registered server's tools, or a standalone source-only scan.

    REQUIRED for any untrusted server before using safe_tool_call.
    BEFORE: register_server or onboard_server (or pass github_url for source-only mode, no registration needed).
    AFTER (server_id mode): get_security_scan(server_id) -> set_tool_policy('block') for HIGH-risk tools.
    AFTER (source-only mode): get_security_scan(github_url) to retrieve results -> review findings ->
        fix local setup -> re-run onboard_server. set_tool_policy does not apply (no registered server).

    Two modes:
        server_id provided - full audit of a registered server's tools plus optional source scan.
        server_id omitted  - standalone source-only scan via github_url, no registration needed.
            Use this when onboard_server fails inspection (stdio server not yet running locally).
            Results are stored under github_url as the key - retrieve with get_security_scan(github_url).
            Review findings, fix local setup, then re-run onboard_server.

    Runs in the background by default (background=True) - returns immediately and stores
    results for get_security_scan to retrieve. Set background=False only for CLI or direct
    Python calls where blocking until completion is desired.

    IMPORTANT: Always omit provider (leave it null) unless the user explicitly names one.
    Omitting provider triggers auto-detect: uses any available LLM key from the environment
    (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY) plus any installed scanners automatically.
    Never ask the user which provider to use - just omit it and let auto-detect handle it.

provider options:
        null / omitted  - AUTO-DETECT (recommended default): uses all available scanners/LLM keys.
        "all"           - same as auto-detect but explicit.
        "anthropic"     - MCPSafety+ 5-stage pentest pipeline (shorthand for mcpsafety+anthropic).
        "openai"          Shorthand for mcpsafety+<provider>. api_key = LLM provider API key.
        "gemini"
        "ollama"          Set OLLAMA_MODEL + optionally OLLAMA_BASE_URL.
        "cisco"         - YARA + Readiness (always offline); LLM/Behavioral if MCP_SCANNER_LLM_API_KEY
                          set; cloud engine if MCP_SCANNER_API_KEY set. api_key = Cisco cloud key.
        "snyk"          - 19 metadata checks: prompt injection, tool shadowing, hardcoded secrets.
                          api_key = Snyk token (falls back to SNYK_TOKEN env var).

mcpsafety options (apply to "anthropic", "openai", "gemini", "ollama", "all", auto):
        confirm_authorized:       Required for LLM-based and active-probe scans (default False). Rule-based
                                  deterministic scan runs without it when no LLM provider is available.
        allow_destructive_probes: enable path traversal / command injection probes (default False)
        skip_web_research:        skip CVE/Arxiv research to avoid leaking findings (default True)
        scan_timeout_s:           hard timeout per scan in seconds (default 900, max 3600)
        background:               True = return immediately, poll get_security_scan for results (default).
                                  False = block until complete (safe for CLI/Python direct calls).

    github_url: required when server_id is omitted. Also used to override the stored GitHub URL
        for an existing registered server. The mcpsafety+ pipeline fetches and analyzes source
        code for secrets, taint flows, and suspicious patterns.

    Results are stored (keyed by server_id or github_url) and returned directly.
    """
    if provider in _LLM_SHORTHANDS:
        provider = f"mcpsafety+{provider}"

    if provider is not None and provider not in ALL_PROVIDERS:
        return json.dumps({
            "error": f"Unknown provider '{provider}'.",
            "valid_providers": sorted(_LLM_SHORTHANDS) + ALL_PROVIDERS,
        })

    if server_id is None:
        if not github_url:
            return json.dumps({
                "error": "server_id or github_url is required.",
                "hint": "Pass github_url to run a standalone source-only scan without a registered server.",
            })
        rl = _check_mgmt_rate_limit(f"scan:{github_url}")
        if rl:
            return json.dumps({"error": rl})
        server = {"server_id": github_url, "github_url": github_url}
        server_id = github_url
        tools = []
    else:
        server = cm.resolve_server_crefs(db.get_server(server_id))
        if not server:
            return json.dumps({"error": f"Server '{server_id}' not registered."})

        rl = _check_mgmt_rate_limit(f"scan:{server_id}")
        if rl:
            return json.dumps({"error": rl})

        tools = db.list_tools(server_id)
        if not tools and not github_url:
            return json.dumps({
                "error": f"No tools found for '{server_id}'.",
                "hint": (
                    "Run inspect_server first, or pass github_url to run a source-only scan. "
                    "stdio servers that require local setup cannot be inspected remotely - "
                    "use github_url to scan source code directly without spawning the server."
                ),
            })

    scan_timeout_s = max(30, min(scan_timeout_s, 3600))

    if provider is None or provider == "all":
        providers_to_run = _auto_detect_providers()
        if not providers_to_run:
            findings = run_deterministic_scan(server_id=server_id, tools=tools)
            scan_id = db.store_security_scan(server_id, findings)
            _gh_on_scan_stored(server_id, findings)
            findings["scan_id"] = scan_id
            return json.dumps(findings, indent=2)
    else:
        providers_to_run = [provider]

    if not confirm_authorized:
        return json.dumps({
            "error": "Authorization required.",
            "hint": "Set confirm_authorized=True to confirm you own or are authorized to test this server.",
        })

    _log.info("security_scan_server server_id=%s providers=%s timeout=%ds background=%s",
              server_id, providers_to_run, scan_timeout_s, background)

    if background:
        if _bg_scan_status.get(server_id) == "running":
            return json.dumps({
                "status": "running",
                "message": f"Scan already in progress for '{server_id}'. Call get_security_scan('{server_id}') to check results.",
            })

        async def _bg_task():
            _bg_scan_status[server_id] = "running"
            try:
                await _execute_scan_core(
                    server_id=server_id, server=server, tools=tools,
                    providers_to_run=providers_to_run, model_id=model_id, api_key=api_key,
                    confirm_authorized=confirm_authorized,
                    allow_destructive_probes=allow_destructive_probes,
                    skip_web_research=skip_web_research,
                    scan_timeout_s=scan_timeout_s,
                    github_url=github_url,
                )
                _bg_scan_status[server_id] = "completed"
            except Exception as exc:
                _log.error("background scan failed for %s: %s", server_id, exc, exc_info=True)
                _bg_scan_status[server_id] = f"failed: {exc}"
                db.store_security_scan(server_id, {
                    "overall_risk_level": "UNKNOWN",
                    "summary": f"Background scan failed: {exc}",
                    "provider": providers_to_run[0] if providers_to_run else "unknown",
                    "tool_findings": [],
                    "server_level_risks": [],
                })

        if len(_bg_scan_status) > 1000:
            done = [k for k, v in list(_bg_scan_status.items()) if v != "running"]
            for k in done:
                _bg_scan_status.pop(k, None)
        _bg_scan_status[server_id] = "running"
        asyncio.create_task(_bg_task())
        return json.dumps({
            "status": "running",
            "server_id": server_id,
            "message": f"Scan started in background. Call get_security_scan('{server_id}') in ~2-3 minutes to retrieve results.",
        })

    try:
        findings = await _execute_scan_core(
            server_id=server_id, server=server, tools=tools,
            providers_to_run=providers_to_run, model_id=model_id, api_key=api_key,
            confirm_authorized=confirm_authorized,
            allow_destructive_probes=allow_destructive_probes,
            skip_web_research=skip_web_research,
            scan_timeout_s=scan_timeout_s,
            github_url=github_url,
        )
        return json.dumps(findings, indent=2)

    except (ValueError, RuntimeError) as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        _log.error("security_scan_server failed for %s: %s", server_id, exc, exc_info=True)
        return json.dumps({"error": "Internal error. Check server logs."})


@mcp.tool()
def get_security_scan(server_id: str) -> str:
    """
    Retrieve the latest stored security scan report for a server.

    If a background scan is running (security_scan_server with background=True),
    returns status="running" - poll again in ~30 seconds until status is absent.

    BEFORE: security_scan_server (to start or have completed a scan).
    AFTER: check tool_findings for HIGH-risk tools, then set_tool_policy('block') as needed.
    """
    status = _bg_scan_status.get(server_id)
    if status == "running":
        return json.dumps({
            "status": "running",
            "server_id": server_id,
            "message": "Scan in progress. Call get_security_scan again in ~30 seconds.",
        })
    scan = db.get_latest_security_scan(server_id)
    if not scan:
        return json.dumps({
            "error": f"No security scan found for '{server_id}'.",
            "hint": "Run security_scan_server first.",
        })
    result = dict(scan)
    if status and status.startswith("failed"):
        result["scan_status"] = status
    return json.dumps(result, indent=2)


@mcp.tool()
async def scan_all_servers(
    provider: str,
    model_id: Optional[str] = None,
    api_key: Optional[str] = None,
    confirm_authorized: bool = False,
    allow_destructive_probes: bool = False,
    skip_web_research: bool = True,
    scan_timeout_s: int = 900,
    server_ids: Optional[List[str]] = None,
) -> str:
    """
    Run the MCPSafety 5-stage security pipeline against all registered servers in one call.

    Prefer this over looping security_scan_server individually. Results are stored per-server
    and appear in subsequent preflight_tool_call and safe_tool_call responses.
    Returns a combined report with per-server results and an aggregate overall_risk_level.

    BEFORE: inspect_server for each server (tools must be known). Check list_servers first.
    AFTER: set_tool_policy('block') for HIGH-risk tools; then use safe_tool_call normally.

    provider: "anthropic" | "openai" | "gemini" | "ollama"
    (same providers as security_scan_server; cisco/snyk not supported here)
    server_ids: optional list of server IDs to scan; scans all registered servers if omitted
    confirm_authorized: MUST be True - confirms you own and are authorized to test all listed servers
    allow_destructive_probes: enable path traversal, command injection, credential file probes
    skip_web_research: skip DuckDuckGo/HackerNews/Arxiv research (prevents leaking findings externally)
    scan_timeout_s: timeout per server in seconds (default 900, max 3600)
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
            sc = _build_supply_chain_findings(sid)
            if sc.get("supply_chain_findings"):
                result.setdefault("findings", [])
                result["findings"].extend(sc["supply_chain_findings"])
                result["supply_chain_risk_count"] = sc.get("supply_chain_risk_count", 0)
                result["provenance_summary"] = sc.get("provenance_summary")
            db.store_security_scan(sid, result)
            _gh_on_scan_stored(sid, result)
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
    confirm_scan_authorized: bool = True,
    github_url: Optional[str] = None,
) -> str:
    """
    One-shot server onboarding: register + inspect + security scan in a single call.

    This is the preferred entry point for adding a new server. Equivalent to register_server
    then security_scan_server, but handles inspection failures with a source-only fallback.
    Use register_server directly only when you need to control the steps separately.

    If inspection fails (stdio server not running) and github_url is provided, runs a
    source-only scan without registering - review results, fix local setup, then re-run.
    If inspection fails and no github_url is given, onboarding is aborted with a clear error.

    confirm_scan_authorized: True by default (calling onboard_server is itself authorization).
    Set False only to skip active security probing.
    github_url: enables source code analysis in the scan pipeline; required when local inspection fails.
    headers/env: secret values (Bearer tokens, API keys) are automatically detected and replaced
    with opaque cref_ identifiers before storage. The response register.credential_refs shows which
    keys were substituted. Real credentials never appear in model context or conversation history.

    AFTER success: review security_scan in the response for HIGH-risk tools.
    AFTER: set_tool_policy('block') for HIGH-risk tools, then use safe_tool_call.
    """
    reg_json = await register_server(
        server_id=server_id, transport=transport,
        command=command, args=args, url=url, env=env, headers=headers,
        auto_inspect=True,
        classify_provider=scan_provider,
        classify_model=scan_model,
        classify_api_key=scan_api_key,
        github_url=github_url,
    )
    reg_result = json.loads(reg_json)
    result: Dict[str, Any] = {"server_id": server_id, "register": reg_result, "security_scan": None}

    if "error" in reg_result and "inspect_error" not in reg_result:
        return json.dumps(result, indent=2)

    if "inspect_error" in reg_result:
        if not github_url:
            return json.dumps({
                "server_id": server_id,
                "error": "Onboarding aborted - server could not be inspected and no github_url was provided.",
                "hint": (
                    "Fix the local setup so the server can be inspected, or pass github_url "
                    "to run a source-only scan. Review the scan results before setting up locally "
                    "and re-running onboard_server."
                ),
            })
        effective_provider = scan_provider or _detect_llm_provider()
        if not effective_provider:
            return json.dumps({
                "server_id": server_id,
                "error": "Onboarding aborted - inspection failed.",
                "source_scan": {"skipped": "No LLM provider detected. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY."},
            })
        try:
            scan_json = await security_scan_server(
                server_id=None,
                provider=effective_provider,
                model_id=scan_model,
                api_key=scan_api_key,
                confirm_authorized=confirm_scan_authorized,
                github_url=github_url,
                background=False,
            )
            return json.dumps({
                "server_id": server_id,
                "registered": False,
                "reason": "Inspection failed - server not registered until tools can be discovered.",
                "source_scan": json.loads(scan_json),
                "next_step": (
                    "Review the scan results above. If clean, fix local setup and re-run "
                    "onboard_server to complete registration."
                ),
            }, indent=2)
        except Exception as exc:
            _log.error("onboard_server source scan failed for %s: %s", server_id, exc, exc_info=True)
            return json.dumps({
                "server_id": server_id,
                "error": "Onboarding aborted - inspection failed and source scan errored.",
                "detail": str(exc),
            })

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
            github_url=github_url,
            background=False,
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


@mcp.tool()
async def discover_servers(
    client: Optional[str] = None,
    include_project: bool = True,
    include_community_paths: bool = True,
) -> str:
    """
    Scan the local machine for MCP servers configured in known MCP client apps.

    Checks 20 MCP clients: VS Code, Claude Desktop, Cursor, Windsurf, Zed, Continue, Goose,
    Cline, Roo Code, Amazon Q, Kiro, GitHub Copilot, Amp, Gemini CLI, OpenCode, Antigravity,
    Codex CLI, 5ire, Witsy, and more.

    Does NOT register or execute anything - read-only config file scan.
    Results are cached in the database; use discovery_id values to onboard specific servers.

    client: filter to a specific client ID (e.g. "cursor", "claude-desktop", "vscode")
    include_project: also scan project-level config files in the current working directory
    include_community_paths: include paths that are community-verified (not from official docs)

    NEXT: onboard_discovered_servers(all_found=True) to register all found servers,
    or onboard_discovered_servers(discovery_ids=[...]) to register specific ones.
    AFTER onboarding: security_scan_server per server before trusting with safe_tool_call.
    """
    rl = _check_mgmt_rate_limit("discover:scan")
    if rl:
        return json.dumps({"error": rl})

    registered_ids = {s["server_id"] for s in db.list_servers()}

    try:
        _loop = asyncio.get_running_loop()
        found = await _loop.run_in_executor(
            None,
            lambda: _discovery.discover_mcp_servers(
                client_filter=client,
                include_project=include_project,
                include_community=include_community_paths,
                registered_server_ids=registered_ids,
            ),
        )
    except Exception as exc:
        _log.error("discover_servers failed: %s", exc, exc_info=True)
        return json.dumps({"error": "Discovery scan failed. Check server logs."})

    for entry in found:
        try:
            db.upsert_discovered_server(entry)
            _gh_on_server_discovered(
                entry["discovery_id"], entry["client"], entry["client_name"], entry["server_name"],
            )
        except Exception as exc:
            _log.warning("discover_servers: failed to cache entry %s: %s", entry.get("discovery_id"), exc)

    public = []
    for entry in found:
        pub = {k: v for k, v in entry.items() if k not in ("env", "headers")}
        public.append(pub)

    clients_found = sorted({e["client"] for e in public})
    return json.dumps({
        "count": len(public),
        "clients_found": clients_found,
        "discovered": public,
    }, indent=2)


@mcp.tool()
async def onboard_discovered_servers(
    discovery_ids: Optional[List[str]] = None,
    client: Optional[str] = None,
    all_found: bool = False,
    auto_inspect: bool = True,
    classify_provider: Optional[str] = None,
    classify_model: Optional[str] = None,
    classify_api_key: Optional[str] = None,
    github_url: Optional[str] = None,
) -> str:
    """
    Register previously discovered servers into the Safety Warden pipeline (register + inspect).

    Must call discover_servers first to populate the discovery cache.
    Skips already-registered servers and servers with only activation_state_only data (5ire).
    Does NOT run security scans - call security_scan_server after for untrusted servers.

    discovery_ids: specific discovery_id values from the discover_servers response
    client: all discovered servers from one client (e.g. "cursor", "claude-desktop", "vscode")
    all_found: register every unregistered server found in the last discover_servers scan
    auto_inspect: connect and enumerate tools after registration (default true)
    classify_provider: LLM for tool classification ("anthropic"|"openai"|"gemini")

    BEFORE: discover_servers (to find and cache servers).
    AFTER: security_scan_server for each registered server before trusting with safe_tool_call.
    """
    rl = _check_mgmt_rate_limit("discover:onboard")
    if rl:
        return json.dumps({"error": rl})

    if not discovery_ids and not client and not all_found:
        return json.dumps({"error": "Provide discovery_ids, client, or set all_found=true."})

    if discovery_ids:
        entries = [db.get_discovered_server(did) for did in discovery_ids]
        entries = [e for e in entries if e is not None]
    elif client:
        entries = db.list_discovered_servers(client=client)
    else:
        entries = db.list_discovered_servers()

    if not entries:
        return json.dumps({"message": "No discovered servers found. Run discover_servers first.", "registered": 0})

    results = []
    for entry in entries:
        did = entry["discovery_id"]
        server_name = entry["server_name"]
        suggested_id = _discovery.make_server_id(entry["client"], server_name)

        if entry.get("registered_server_id"):
            results.append({"discovery_id": did, "server_name": server_name, "status": "already_registered", "server_id": entry["registered_server_id"]})
            continue

        if entry.get("activation_state_only"):
            results.append({"discovery_id": did, "server_name": server_name, "status": "skipped", "reason": "activation_state_only - full server definition not available in config file"})
            continue

        if not entry.get("command") and not entry.get("url"):
            results.append({"discovery_id": did, "server_name": server_name, "status": "skipped", "reason": "no command or url in discovered config"})
            continue

        rl_entry = _check_mgmt_rate_limit(f"register:{suggested_id}")
        if rl_entry:
            results.append({"discovery_id": did, "server_name": server_name, "status": "rate_limited", "reason": rl_entry})
            continue

        try:
            reg_result = await _do_register(
                server_id=suggested_id,
                transport=entry["transport"],
                command=entry.get("command"),
                args=entry.get("args") or [],
                url=entry.get("url"),
                env=entry.get("env") or {},
                headers=entry.get("headers") or {},
                auto_inspect=auto_inspect,
                classify_provider=classify_provider,
                classify_model=classify_model,
                classify_api_key=classify_api_key,
                github_url=github_url,
            )
        except Exception as exc:
            _log.error("onboard_discovered_servers: _do_register raised for %s: %s", suggested_id, exc, exc_info=True)
            results.append({"discovery_id": did, "server_name": server_name, "status": "failed", "error": str(exc)})
            continue

        if "error" in reg_result:
            results.append({"discovery_id": did, "server_name": server_name, "status": "failed", "error": reg_result["error"], "hint": reg_result.get("hint")})
        else:
            db.mark_discovered_registered(did, suggested_id)
            _gh_on_server_discovered(did, entry["client"], entry["client_name"], server_name, suggested_id)
            entry_result: Dict[str, Any] = {
                "discovery_id": did,
                "server_name": server_name,
                "status": "registered",
                "server_id": suggested_id,
                "tools_discovered": reg_result.get("tools_discovered", 0),
                "source": entry.get("client"),
                "config_path": entry.get("config_path"),
            }
            if reg_result.get("credential_refs"):
                entry_result["credential_refs"] = reg_result["credential_refs"]
                entry_result["credential_refs_note"] = reg_result.get("credential_refs_note")
            results.append(entry_result)

    registered_count = sum(1 for r in results if r["status"] == "registered")
    attempted_count = sum(1 for r in results if r["status"] in ("registered", "failed"))
    return json.dumps({
        "total": len(results),
        "attempted": attempted_count,
        "registered": registered_count,
        "results": results,
    }, indent=2)


@mcp.tool()
def get_risk_graph(server_id: Optional[str] = None, rebuild: bool = False) -> str:
    """
    Return the inventory graph of MCP servers, tools, security findings, and their relationships.

    The graph exposes connections that preflight_tool_call and safe_tool_call use for
    blast-radius context. On first call the graph may be empty - pass rebuild=True to
    populate it from all data Safety Warden has already stored.

    server_id: scope the graph to one server; omit for the full workspace graph.
    rebuild:   True = rebuild from existing Safety Warden tables before returning.

    Returns objects (nodes) and relations (edges). Node types: mcp_server, tool, finding,
    agent_client, mcp_config, credential_surface, mitre_technique. Relation types: exposes,
    affected_by, can_exfiltrate, declares, uses_credential, maps_to.

    NEXT: explain_tool_risk(server_id, tool_name) to walk risk paths for a specific tool.
    NEXT: export_graph(format="mermaid") for a diagram.
    """
    try:
        if rebuild:
            counts = _graph_builder.rebuild_from_db()
            graph = _graph_store.get_full_graph(server_id)
            return json.dumps({"rebuilt": counts, "graph": graph}, indent=2)

        graph = _graph_store.get_full_graph(server_id)
        if not graph["objects"]:
            if server_id and _graph_store.get_full_graph()["objects"]:
                return json.dumps({
                    "note": f"No graph nodes found for server '{server_id}'. Run inspect_server to populate.",
                    "graph": graph,
                }, indent=2)
            counts = _graph_builder.rebuild_from_db()
            graph = _graph_store.get_full_graph(server_id)
            return json.dumps({
                "note": "Graph was empty - rebuilt from existing Safety Warden data",
                "rebuilt": counts,
                "graph": graph,
            }, indent=2)

        return json.dumps(graph, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def explain_tool_risk(server_id: str, tool_name: str) -> str:
    """
    Walk the risk graph for a specific tool and return blast radius, risk paths, and recommended action.

    Returns:
      blast_radius: critical | high | medium | low | none
      direct_findings: security scan findings that affect this tool
      composition_risks: dangerous tool combinations (e.g. read + external_post = exfiltration)
      risk_paths: human-readable paths from findings to the tool
      agent_clients: which AI clients have this server configured
      recommended_action: allow | warn | require_approval | block

    BEFORE: get_risk_graph (to ensure graph is populated).
    AFTER: set_tool_policy('block') if recommended_action is 'block'.
    """
    try:
        result = _graph_explain.explain_tool_risk(server_id, tool_name)
        if "error" in result:
            _graph_builder.rebuild_from_db()
            result = _graph_explain.explain_tool_risk(server_id, tool_name)
            if "error" in result:
                result["hint"] = (
                    f"Tool '{tool_name}' may not have been inspected yet. "
                    "Run inspect_server to populate tool data, then retry."
                )
            else:
                result["note"] = "Graph rebuilt from existing data before analysis"
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def export_graph(format: str = "png", server_id: Optional[str] = None, output_path: Optional[str] = None) -> str:
    """
    Export the risk graph in the requested format.

    format: "png" (default) - PNG image rendered via mmdc (requires: npm install -g @mermaid-js/mermaid-cli).
            "mermaid" - Mermaid LR diagram source for pasting into mermaid.live.
            "json" - structured objects and relations list.

    server_id: scope export to one server; omit for full workspace graph.
    output_path: file path for PNG output; defaults to <server_id>_graph.png in the current directory.

    Graph is rebuilt automatically before export.
    """
    try:
        _graph_builder.rebuild_from_db()
        if format == "png":
            path = _graph_explain.export_as_png(server_id, output_path)
            return json.dumps({"format": "png", "path": path}, indent=2)
        if format == "mermaid":
            diagram = _graph_explain.export_as_mermaid(server_id)
            return json.dumps({"format": "mermaid", "diagram": diagram}, indent=2)
        if format != "json":
            return json.dumps({"error": f"Unsupported format {format!r}. Supported: 'png', 'mermaid', 'json'"}, indent=2)
        graph = _graph_store.get_full_graph(server_id)
        return json.dumps({"format": "json", **graph}, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def explain_client_risk(client_id: str) -> str:
    """
    Analyze cross-server risks for all MCP servers registered under one agent client.

    Detects risks that are invisible when looking at servers individually:
      cross_server_exfiltration: read tool on server-A + external tool on server-B - data can
        leave the system even if each server individually looks safe.
      tool_shadowing: same tool name on multiple servers - attacker controlling one can intercept
        calls intended for another.
      shared_cve_blast_radius: a single supply-chain CVE affects tools across multiple servers.

    client_id: agent client identifier (e.g. "claude-desktop", "cursor", "vscode").
      Run discover_servers first to populate the client-server linkage, or register_server
      will auto-link stdio servers that match a known config file entry.

    BEFORE: discover_servers or onboard_discovered_servers (to establish client-server links).
    BEFORE: inspect_server for each server (tools must be known for exfil path analysis).
    AFTER: set_tool_policy('block') on any external tools that appear in exfil paths.
    AFTER: security_scan_server on servers with HIGH composite_risk.
    """
    try:
        result = _graph_explain.explain_client_risk(client_id)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def analyze_cve_blast_radius(
    client_id: Optional[str] = None,
    vuln_id: Optional[str] = None,
) -> str:
    """
    Report CVEs that affect multiple servers, showing the blast radius across the client's workspace.

    A single supply-chain vulnerability (e.g. a CVE in the 'requests' library) may be present
    in several MCP servers simultaneously. This tool surfaces those shared exposures so you can
    prioritize patching by blast radius rather than server-by-server.

    client_id: scope to servers under one client; omit to query across all clients.
    vuln_id: filter to a specific CVE / GHSA / vulnerability ID.

    BEFORE: inspect_server for each server (provenance must be built to detect CVEs).
    AFTER: security_scan_server on the affected servers for deeper analysis.
    """
    try:
        cve_nodes = _graph_store.get_objects_by_type("cve_blast_radius")
        if client_id:
            prefix = f"cve_blast::{client_id}::"
            cve_nodes = [n for n in cve_nodes if n["obj_id"].startswith(prefix)]
        if vuln_id:
            cve_nodes = [n for n in cve_nodes if n["name"] == vuln_id or n.get("metadata", {}).get("vuln_id") == vuln_id]

        results = []
        for n in cve_nodes:
            meta = n.get("metadata", {})
            results.append({
                "vuln_id": meta.get("vuln_id", n["name"]),
                "severity": meta.get("severity", "UNKNOWN"),
                "affected_servers": meta.get("affected_servers", []),
                "client_id": meta.get("client_id", ""),
                "blast_radius": len(meta.get("affected_servers", [])),
            })
        results.sort(
            key=lambda x: ({"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x["severity"], 0), x["blast_radius"]),
            reverse=True,
        )

        if not results:
            hint = (
                "No shared CVEs found. Ensure inspect_server has been run for each server "
                "and provenance detection completed."
            )
            if client_id:
                hint += f" Also confirm '{client_id}' has at least 2 linked servers via discover_servers."
            return json.dumps({"cve_blast_radius": [], "count": 0, "hint": hint}, indent=2)

        return json.dumps({"cve_blast_radius": results, "count": len(results)}, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


def main():
    transport = _os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        mcp.run()
    else:
        import uvicorn
        host = _os.environ.get("MCP_HOST", "127.0.0.1")
        try:
            port = int(_os.environ.get("MCP_PORT", "8000"))
        except ValueError:
            _log.error("Invalid MCP_PORT=%r, defaulting to 8000", _os.environ.get("MCP_PORT"))
            port = 8000
        t = "streamable_http" if transport in ("http", "streamable_http") else "sse"
        uvicorn.run(create_http_app(t), host=host, port=port)

if __name__ == "__main__":
    main()
