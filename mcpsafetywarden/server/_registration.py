import asyncio
import json
import logging
import os as _os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..core import database as db
from ..core.security_utils import looks_like_secret as _looks_like_secret
from ..proxy import client as cm
from ..proxy import discovery as _discovery
from ..proxy.drift import compare_db_snapshots as _compare_tool_snapshots, check_server_drift as _check_drift
from ..graph import provenance as _graph_provenance
from ._app import (
    mcp,
    _check_mgmt_rate_limit,
    _SHELL_INTERPS,
    _SHELL_EVAL_FLAGS,
    _MAX_SERVER_ID_LEN,
    _MAX_COMMAND_LEN,
    _MAX_URL_LEN,
    _MAX_ARGS_COUNT,
    _MAX_ARG_LEN,
    _MAX_ENV_VARS,
    _MAX_HEADER_PAIRS,
)
from ._hooks import (
    _gh_on_registered,
    _gh_on_tools_inspected,
    _gh_on_credentials_detected,
    _gh_cleanup_server,
    _gh_on_provenance_detected,
    _gh_on_server_discovered,
    _gh_on_cross_server_analysis,
)
from ..scan.args import SSRF_RE

_log = logging.getLogger(__name__)


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
            db.upsert_discovered_server(
                {
                    **entry,
                    "registered_server_id": server_id,
                }
            )
            db.mark_discovered_registered(did, server_id)
            _gh_on_server_discovered(
                did,
                entry["client"],
                entry["client_name"],
                entry["server_name"],
                server_id,
            )
            _log.info("Linked server '%s' to client '%s' via stdio fingerprint match", server_id, entry["client"])
    except Exception as exc:
        _log.debug("_try_link_stdio_to_client failed for %s: %s", server_id, exc)


def _probe_http_transport(url: str) -> str:
    """Return 'streamable_http' or 'sse' by probing the URL per the MCP backwards-compat spec.

    POST → 2xx means streamable_http.
    POST → 404/405, then GET → text/event-stream means sse.
    Defaults to streamable_http when inconclusive.
    """
    try:
        req = urllib.request.Request(
            url,
            data=b"{}",
            method="POST",
            headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
            if 200 <= resp.status < 300:
                return "streamable_http"
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 405):
            try:
                get_req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
                with urllib.request.urlopen(get_req, timeout=5) as gresp:  # nosec B310
                    if "text/event-stream" in gresp.headers.get("Content-Type", ""):
                        return "sse"
            except Exception:
                pass
    except Exception:
        pass
    return "streamable_http"


def _resolve_transport(transport: Optional[str], command: Optional[str], url: Optional[str]) -> Optional[str]:
    """Infer transport from available parameters; returns None if inputs are ambiguous."""
    if transport:
        return transport
    if command and not url:
        return "stdio"
    if url and not command:
        detected = _probe_http_transport(url)
        _log.debug("auto-detected transport for %s: %s", url, detected)
        return detected
    return None


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
            None,
            lambda: _graph_provenance.build_provenance_info(
                server_id,
                command,
                args or [],
                url=url,
                transport=transport,
                github_url=github_url,
            ),
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
            from ..scan.scanner import detect_llm_provider as _detect_llm_provider

            tools = await cm.inspect_server_tools(
                server_id,
                llm_provider=classify_provider or _detect_llm_provider(),
                llm_model=classify_model,
                llm_api_key=classify_api_key,
            )
            _gh_on_tools_inspected(
                server_id,
                tools,
                llm_provider=classify_provider or _detect_llm_provider(),
                llm_model=classify_model,
                llm_api_key=classify_api_key,
            )
            _gh_on_cross_server_analysis(server_id)
            result["tools_discovered"] = len(tools)
            result["tools"] = [
                {"name": t["name"], "effect_class": t["effect_class"], "confidence": t["confidence"]} for t in tools
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
    transport: Optional[str] = None,
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
    resolved = _resolve_transport(transport, command, url)
    if not resolved:
        return json.dumps(
            {"error": "cannot infer transport: provide --command (stdio) or --url (http), or pass transport explicitly"}
        )
    result = await _do_register(
        server_id=server_id,
        transport=resolved,
        command=command,
        args=args,
        url=url,
        env=env,
        headers=headers,
        auto_inspect=auto_inspect,
        classify_provider=classify_provider,
        classify_model=classify_model,
        classify_api_key=classify_api_key,
        github_url=github_url,
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

    from ..scan.scanner import detect_llm_provider as _detect_llm_provider

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
                    None,
                    lambda: _graph_provenance.build_provenance_info(
                        server_id,
                        _srv.get("command"),
                        _srv.get("args") or [],
                        url=_srv.get("url"),
                        transport=_srv.get("transport"),
                        github_url=_srv.get("github_url"),
                    ),
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
                server_id,
                old_tools,
                new_tools,
                datetime.now(timezone.utc).isoformat(),
            )
            if drift["drift_detected"]:
                result["drift"] = drift
                _log.warning(
                    "inspect_server: drift detected for %s severity=%s findings=%d",
                    server_id,
                    drift["overall_severity"],
                    len(drift["findings"]),
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
async def onboard_server(
    server_id: str,
    transport: Optional[str] = None,
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
    from ..scan.scanner import detect_llm_provider as _detect_llm_provider
    from ._scan import security_scan_server

    reg_json = await register_server(
        server_id=server_id,
        transport=transport,
        command=command,
        args=args,
        url=url,
        env=env,
        headers=headers,
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
            return json.dumps(
                {
                    "server_id": server_id,
                    "error": "Onboarding aborted - server could not be inspected and no github_url was provided.",
                    "hint": (
                        "Fix the local setup so the server can be inspected, or pass github_url "
                        "to run a source-only scan. Review the scan results before setting up locally "
                        "and re-running onboard_server."
                    ),
                }
            )
        effective_provider = scan_provider or _detect_llm_provider()
        if not effective_provider:
            return json.dumps(
                {
                    "server_id": server_id,
                    "error": "Onboarding aborted - inspection failed.",
                    "source_scan": {
                        "skipped": "No LLM provider detected. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY."
                    },
                }
            )
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
            return json.dumps(
                {
                    "server_id": server_id,
                    "registered": False,
                    "reason": "Inspection failed - server not registered until tools can be discovered.",
                    "source_scan": json.loads(scan_json),
                    "next_step": (
                        "Review the scan results above. If clean, fix local setup and re-run "
                        "onboard_server to complete registration."
                    ),
                },
                indent=2,
            )
        except Exception as exc:
            _log.error("onboard_server source scan failed for %s: %s", server_id, exc, exc_info=True)
            return json.dumps(
                {
                    "server_id": server_id,
                    "error": "Onboarding aborted - inspection failed and source scan errored.",
                    "detail": str(exc),
                }
            )

    effective_provider = scan_provider or _detect_llm_provider()
    if not effective_provider:
        result["security_scan"] = {
            "skipped": "No LLM provider detected. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY.",
        }
        return json.dumps(result, indent=2)

    try:
        scan_json = await security_scan_server(
            server_id=server_id,
            provider=effective_provider,
            model_id=scan_model,
            api_key=scan_api_key,
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
                entry["discovery_id"],
                entry["client"],
                entry["client_name"],
                entry["server_name"],
            )
        except Exception as exc:
            _log.warning("discover_servers: failed to cache entry %s: %s", entry.get("discovery_id"), exc)

    public = []
    for entry in found:
        pub = {k: v for k, v in entry.items() if k not in ("env", "headers")}
        public.append(pub)

    clients_found = sorted({e["client"] for e in public})
    return json.dumps(
        {
            "count": len(public),
            "clients_found": clients_found,
            "discovered": public,
        },
        indent=2,
    )


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
            results.append(
                {
                    "discovery_id": did,
                    "server_name": server_name,
                    "status": "already_registered",
                    "server_id": entry["registered_server_id"],
                }
            )
            continue

        if entry.get("activation_state_only"):
            results.append(
                {
                    "discovery_id": did,
                    "server_name": server_name,
                    "status": "skipped",
                    "reason": "activation_state_only - full server definition not available in config file",
                }
            )
            continue

        if not entry.get("command") and not entry.get("url"):
            results.append(
                {
                    "discovery_id": did,
                    "server_name": server_name,
                    "status": "skipped",
                    "reason": "no command or url in discovered config",
                }
            )
            continue

        rl_entry = _check_mgmt_rate_limit(f"register:{suggested_id}")
        if rl_entry:
            results.append(
                {"discovery_id": did, "server_name": server_name, "status": "rate_limited", "reason": rl_entry}
            )
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
            results.append(
                {
                    "discovery_id": did,
                    "server_name": server_name,
                    "status": "failed",
                    "error": reg_result["error"],
                    "hint": reg_result.get("hint"),
                }
            )
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
    return json.dumps(
        {
            "total": len(results),
            "attempted": attempted_count,
            "registered": registered_count,
            "results": results,
        },
        indent=2,
    )
