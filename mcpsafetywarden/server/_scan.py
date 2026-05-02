import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from ..core import database as db
from ..scan.scanner import ALL_PROVIDERS, run_cisco_scan, run_snyk_scan, run_security_scan, auto_detect_providers as _auto_detect_providers, merge_findings as _merge_findings
from ..scan.mcpsafety import run_mcpsafety_scan, run_mcpsafety_scan_multi, run_deterministic_scan
from ..graph import store as _graph_store
from ..proxy import client as cm
from ._app import mcp, _check_mgmt_rate_limit, _bg_scan_status, _LLM_SHORTHANDS
from ._hooks import _gh_on_scan_stored, _gh_on_composition_analysis

_log = logging.getLogger(__name__)


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
        import os as _os
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
