import asyncio
import json
import logging
import urllib.parse as _urlparse
from typing import Any, Dict, List, Optional, Tuple

from . import database as db
from .client_manager import open_streams as _open_streams

_log = logging.getLogger(__name__)


def _find_aux_server(*name_keywords: str) -> Optional[Dict[str, Any]]:
    """Find a registered server whose server_id contains any keyword (case-insensitive)."""
    try:
        for srv in db.list_servers(include_credentials=True):
            sid = srv.get("server_id", "").lower()
            if any(kw.lower() in sid for kw in name_keywords):
                return srv
    except Exception:
        pass
    return None


async def _call_aux_tool(
    server_config: Dict[str, Any],
    tool_name: str,
    args: Dict[str, Any],
    timeout: float = 25.0,
) -> str:
    """Call one tool on an auxiliary server. Returns text output; never raises."""
    from mcp import ClientSession

    async def _do() -> str:
        async with _open_streams(server_config) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, args)
                content = getattr(result, "content", [])
                parts = []
                for c in content:
                    if hasattr(c, "text"):
                        parts.append(c.text)
                    elif hasattr(c, "model_dump"):
                        parts.append(json.dumps(c.model_dump()))
                return "\n".join(parts)

    try:
        return await asyncio.wait_for(_do(), timeout=timeout)
    except asyncio.TimeoutError:
        return f"[AUX TIMEOUT: {tool_name} did not respond in {timeout:.0f}s]"
    except Exception as exc:
        return f"[AUX ERROR: {tool_name} - {exc}]"


def _aux_tool_exists(server_id: str, tool_name: str) -> bool:
    """Return True if tool_name is stored in the DB for server_id."""
    try:
        return any(t["tool_name"] == tool_name for t in db.list_tools(server_id))
    except Exception:
        return False


def _extract_host_port(server_config: Dict[str, Any]) -> Tuple[Optional[str], Optional[int]]:
    """Parse (host, port) from server_config['url']. Returns (None, None) for stdio."""
    url = server_config.get("url", "")
    if not url:
        return None, None
    try:
        p = _urlparse.urlparse(url)
        return p.hostname, p.port or (443 if p.scheme == "https" else 80)
    except Exception:
        return None, None


async def kali_recon(target_config: Dict[str, Any], fast: bool = False) -> Dict[str, Any]:
    """
    Run Kali nmap quick_scan + vulnerability_scan + traceroute against the target host.
    Returns a dict keyed by tool name, or {} if Kali MCP is not registered or target is stdio.
    fast=True skips vulnerability_scan (which can take 60-90s) for latency-sensitive callers.
    """
    kali = _find_aux_server("kali")
    if not kali:
        return {}
    host, port = _extract_host_port(target_config)
    if not host:
        return {}

    sid = kali["server_id"]
    results: Dict[str, Any] = {"nmap_target": f"{host}:{port}"}

    scan_tools = [("quick_scan", 60.0)] if fast else [("quick_scan", 60.0), ("vulnerability_scan", 90.0)]
    for tool_name, t_out in scan_tools:
        if _aux_tool_exists(sid, tool_name):
            _log.info("Kali Recon: %s %s", tool_name, host)
            out = await _call_aux_tool(kali, tool_name, {"target": host}, timeout=t_out)
            if out and not out.startswith("[AUX"):
                results[tool_name] = out

    if _aux_tool_exists(sid, "traceroute"):
        _log.info("Kali Recon: traceroute %s", host)
        out = await _call_aux_tool(kali, "traceroute", {"target": host}, timeout=30.0)
        if out and not out.startswith("[AUX"):
            results["traceroute"] = out

    _log.info("Kali recon done for %s (%d scans)", host, len(results) - 1)
    return results


async def _burp_hacker(target_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Send HTTP-layer attack probes via Burp MCP against the target MCP endpoint.
    Also triggers Collaborator OOB probes and pulls automated scanner findings.
    Pro-only tools (Collaborator, GetScannerIssues) are tried and silently skipped on failure.
    Returns normalized finding dicts, or [] if Burp not registered or target is not HTTP.
    """
    burp = _find_aux_server("burp")
    if not burp:
        return []
    host, port = _extract_host_port(target_config)
    if not host:
        return []

    sid = burp["server_id"]
    findings: List[Dict[str, Any]] = []
    url = target_config.get("url", "")
    uses_https = url.startswith("https")
    path = _urlparse.urlparse(url).path or "/"

    if _aux_tool_exists(sid, "send_http1_request"):
        probes = [
            (
                "malformed_json",
                f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                "Content-Type: application/json\r\nContent-Length: 7\r\n\r\n{broke",
            ),
            (
                "missing_content_type",
                f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 44\r\n\r\n"
                '{"jsonrpc":"2.0","method":"tools/list","id":1}',
            ),
            (
                "oversized_method",
                f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                "Content-Type: application/json\r\nContent-Length: 980\r\n\r\n"
                + '{{"jsonrpc":"2.0","method":"{}","id":1}}'.format("A" * 950),
            ),
        ]
        for probe_name, raw_req in probes:
            _log.info("Burp Hacker: HTTP probe %s -> %s:%d", probe_name, host, port)
            out = await _call_aux_tool(
                burp, "send_http1_request",
                {"content": raw_req, "targetHostname": host, "targetPort": port, "usesHttps": uses_https},
                timeout=20.0,
            )
            if out and not out.startswith("[AUX") and "denied by Burp Suite" not in out:
                findings.append({
                    "tool": "send_http1_request",
                    "finding": f"HTTP probe response: {probe_name}",
                    "severity": "INFO",
                    "evidence": out[:500],
                    "source": "burp_suite",
                })

    if _aux_tool_exists(sid, "generate_collaborator_payload"):
        _log.info("Burp Hacker: generating Collaborator payload")
        collab_out = await _call_aux_tool(burp, "generate_collaborator_payload", {"customData": "mcp-scan"}, timeout=15.0)
        if collab_out and not collab_out.startswith("[AUX"):
            collab_host = None
            collab_payload_id = None
            for line in collab_out.splitlines():
                if line.startswith("Payload:") and collab_host is None:
                    collab_host = line.split(":", 1)[1].strip()
                elif line.startswith("Payload ID:"):
                    collab_payload_id = line.split(":", 1)[1].strip()
            if collab_host and _aux_tool_exists(sid, "send_http1_request"):
                oob_body = json.dumps({
                    "jsonrpc": "2.0", "method": "tools/list",
                    "params": {"url": f"http://{collab_host}"}, "id": 99,
                })
                oob_req = (
                    f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(oob_body)}\r\n\r\n{oob_body}"
                )
                await _call_aux_tool(
                    burp, "send_http1_request",
                    {"content": oob_req, "targetHostname": host, "targetPort": port, "usesHttps": uses_https},
                    timeout=20.0,
                )
            await asyncio.sleep(5)
            if _aux_tool_exists(sid, "get_collaborator_interactions"):
                interact_args = {"payloadId": collab_payload_id} if collab_payload_id else {}
                interactions = await _call_aux_tool(burp, "get_collaborator_interactions", interact_args, timeout=15.0)
                if interactions and not interactions.startswith("[AUX") and "No interactions detected" not in interactions:
                    _has_callbacks = False
                    for _chunk in interactions.split("\n\n"):
                        _chunk = _chunk.strip()
                        if not _chunk:
                            continue
                        try:
                            _item = json.loads(_chunk)
                            if isinstance(_item, dict) and _item.get("type"):
                                _has_callbacks = True
                                break
                        except (json.JSONDecodeError, ValueError):
                            pass
                    if _has_callbacks:
                        findings.append({
                            "tool": "get_collaborator_interactions",
                            "finding": "Out-of-band callback received - possible blind SSRF or injection",
                            "severity": "HIGH",
                            "evidence": interactions[:500],
                            "source": "burp_collaborator",
                        })

    if _aux_tool_exists(sid, "get_scanner_issues"):
        _log.info("Burp Hacker: fetching scanner issues")
        issues_raw = await _call_aux_tool(burp, "get_scanner_issues", {"count": 50, "offset": 0}, timeout=20.0)
        if issues_raw and not issues_raw.startswith("[AUX"):
            for chunk in issues_raw.split("\n\n"):
                chunk = chunk.strip()
                if not chunk or chunk == "Reached end of items":
                    continue
                try:
                    issue = json.loads(chunk)
                    if isinstance(issue, dict):
                        findings.append({
                            "tool": "get_scanner_issues",
                            "finding": issue.get("name") or issue.get("issueName") or "Scanner issue",
                            "severity": {"INFORMATION": "LOW", "FALSE_POSITIVE": "LOW"}.get(
                                str(issue.get("severity", "MEDIUM")).upper(),
                                str(issue.get("severity", "MEDIUM")).upper(),
                            ),
                            "evidence": (issue.get("detail") or issue.get("issueDetail") or str(issue))[:300],
                            "source": "burp_scanner",
                        })
                except (json.JSONDecodeError, ValueError):
                    pass

    _log.info("Burp hacker: %d findings from %s:%d", len(findings), host, port)
    return findings


async def burp_proxy_evidence(target_config: Dict[str, Any]) -> str:
    """
    Pull Burp proxy HTTP history for the target host as auditor/replay evidence.
    Returns raw text (capped at 4 KB), or '' if Burp not registered or target is not HTTP.
    """
    burp = _find_aux_server("burp")
    if not burp:
        return ""
    host, _ = _extract_host_port(target_config)
    if not host:
        return ""
    sid = burp["server_id"]
    if not _aux_tool_exists(sid, "get_proxy_http_history_regex"):
        return ""
    _log.info("Burp Auditor: pulling proxy history for %s", host)
    raw = await _call_aux_tool(
        burp, "get_proxy_http_history_regex",
        {"regex": host, "count": 50, "offset": 0},
        timeout=20.0,
    )
    if not raw or raw.startswith("[AUX") or "access denied by Burp Suite" in raw or "Reached end of items" == raw.strip():
        return ""
    return raw[:4096]
