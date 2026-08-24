"""Web dashboard for mcpsafetywarden - FastAPI backend + static SPA."""

import asyncio
import json
import logging
import threading
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import dashboard_db as _db

_log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"
CLIENT_HEADER = "x-warden-client"

api = FastAPI(title="mcpsafetywarden", version="1.0", docs_url=None, redoc_url=None)


@api.middleware("http")
async def guard_writes(request: Request, call_next):
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path.startswith("/api/"):
        if request.headers.get(CLIENT_HEADER) != "dashboard":
            return JSONResponse(status_code=403, content={"detail": "Write requests must come from the dashboard."})
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host", ""):
            return JSONResponse(status_code=403, content={"detail": "Cross-origin write rejected."})
    return await call_next(request)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@api.get("/api/health")
def health():
    return _db.get_health()


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------


@api.get("/api/overview")
def overview():
    return _db.get_overview()


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------


@api.get("/api/servers")
def servers(
    transport: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    return _db.list_servers(transport=transport, risk_level=risk_level)


@api.get("/api/servers/{server_id}")
def server_detail(server_id: str):
    s = _db.get_server(server_id)
    if not s:
        raise HTTPException(404, f"Server '{server_id}' not found")
    return s


@api.get("/api/servers/{server_id}/tools")
def server_tools(
    server_id: str,
    effect_class: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, le=200),
):
    return _db.list_tools(server_id=server_id, effect_class=effect_class, page=page, limit=limit)


@api.get("/api/servers/{server_id}/scan")
def server_scan(server_id: str):
    scan = _db.get_latest_scan(server_id)
    if not scan:
        raise HTTPException(404, "No scan found for this server")
    return scan


@api.get("/api/servers/{server_id}/scans")
def server_scans(server_id: str):
    return _db.list_scans(server_id)


@api.get("/api/servers/{server_id}/snapshots")
def server_snapshots(server_id: str):
    return _db.list_snapshots(server_id)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@api.get("/api/tools")
def tools(
    server_id: Optional[str] = Query(None),
    effect_class: Optional[str] = Query(None),
    policy: Optional[str] = Query(None),
    q: Optional[str] = Query(None, max_length=200),
    page: int = Query(1, ge=1),
    limit: int = Query(50, le=200),
):
    return _db.list_tools(
        server_id=server_id, effect_class=effect_class, policy=policy, page=page, limit=limit, q=q or None
    )


@api.get("/api/tools/activity")
def tools_activity(days: int = Query(7, ge=1, le=30), server_id: Optional[str] = Query(None)):
    return _db.get_tool_activity(days=days, server_id=server_id)


@api.get("/api/tools/{server_id}/{tool_name}")
def tool_detail(server_id: str, tool_name: str):
    t = _db.get_tool_detail(server_id, tool_name)
    if not t:
        raise HTTPException(404, f"Tool '{tool_name}' not found on '{server_id}'")
    return t


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@api.get("/api/findings")
def findings(
    risk_level: Optional[str] = Query(None),
    server_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(100, le=500),
):
    return _db.get_all_findings(risk_level=risk_level, server_id=server_id, page=page, limit=limit)


# ---------------------------------------------------------------------------
# Runs / History
# ---------------------------------------------------------------------------


@api.get("/api/runs")
def runs(
    server_id: Optional[str] = Query(None),
    tool_name: Optional[str] = Query(None),
    success: Optional[bool] = Query(None),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    after_id: Optional[int] = Query(None),
    limit: int = Query(100, le=500),
):
    return _db.get_runs(
        server_id=server_id,
        tool_name=tool_name,
        success=success,
        start=start,
        end=end,
        after_id=after_id,
        limit=limit,
    )


@api.get("/api/runs/stats")
def runs_stats(hours: int = Query(24, ge=1, le=168)):
    return _db.get_runs_stats(hours=hours)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


@api.get("/api/graph")
def graph(server_id: Optional[str] = Query(None)):
    return _db.get_graph(server_id=server_id)


@api.post("/api/graph/rebuild")
def graph_rebuild(server_id: Optional[str] = None):
    try:
        from .graph import builder as _builder

        _builder.rebuild_from_db(server_id=server_id)
        return {"rebuilt": True}
    except Exception as e:
        _log.error("graph rebuild error: %s", e)
        return {"rebuilt": False, "error": "rebuild failed"}


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@api.get("/api/policies")
def policies():
    return _db.get_policies()


class PolicyBody(BaseModel):
    server_id: str
    tool_name: str
    policy: str


@api.post("/api/policies")
def set_policy(body: PolicyBody):
    if body.policy not in ("allow", "block"):
        raise HTTPException(400, "policy must be 'allow' or 'block'")
    _db.set_policy(body.server_id, body.tool_name, body.policy)
    return {"ok": True}


@api.delete("/api/policies/{server_id}/{tool_name}")
def delete_policy(server_id: str, tool_name: str):
    _db.set_policy(server_id, tool_name, None)
    return {"ok": True}


@api.post("/api/policies/bulk-block-high")
def bulk_block_high():
    findings_data = _db.get_all_findings(limit=10000)
    blocked = []
    for f in findings_data["items"]:
        if f.get("risk_level") in ("HIGH", "CRITICAL"):
            server_id = f.get("server_id")
            tool_name = f.get("name")
            if server_id and tool_name:
                _db.set_policy(server_id, tool_name, "block")
                blocked.append({"server_id": server_id, "tool_name": tool_name})
    return {"blocked": blocked, "count": len(blocked)}


# ---------------------------------------------------------------------------
# Discovered servers
# ---------------------------------------------------------------------------


@api.get("/api/discovered")
def discovered():
    return _db.get_discovered()


# ---------------------------------------------------------------------------
# Security scans (queued, one server at a time)
# ---------------------------------------------------------------------------


class ScanBody(BaseModel):
    confirm_authorized: bool = False
    server_ids: Optional[List[str]] = None


_scan_state: Dict[str, Any] = {"current": None, "queue": [], "results": {}}
_scan_worker: Optional[asyncio.Task] = None


def _loads(raw: Any) -> Dict[str, Any]:
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        return {"error": "Unreadable response"}
    return data if isinstance(data, dict) else {"result": data}


def _scan_status() -> Dict[str, Any]:
    return {
        "current": _scan_state["current"],
        "queue": list(_scan_state["queue"]),
        "results": dict(_scan_state["results"]),
    }


async def _drain_scan_queue() -> None:
    from .server import security_scan_server

    while _scan_state["queue"]:
        server_id = _scan_state["queue"].pop(0)
        _scan_state["current"] = server_id
        try:
            data = _loads(await security_scan_server(server_id=server_id, confirm_authorized=True, background=False))
            if data.get("error"):
                result = {"status": "failed", "error": str(data["error"])}
            else:
                result = {"status": "completed", "overall_risk_level": data.get("overall_risk_level")}
        except Exception as exc:
            _log.error("dashboard scan failed for %s: %s", server_id, exc, exc_info=True)
            result = {"status": "failed", "error": "Scan failed. Check the server logs."}
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        _scan_state["results"][server_id] = result
        _scan_state["current"] = None
        if len(_scan_state["results"]) > 1000:
            oldest = sorted(_scan_state["results"].items(), key=lambda kv: kv[1].get("finished_at", ""))
            for key, _ in oldest[:200]:
                _scan_state["results"].pop(key, None)


def _enqueue_scans(server_ids: List[str]) -> Dict[str, Any]:
    global _scan_worker
    queued, skipped = [], []
    for server_id in server_ids:
        if server_id == _scan_state["current"] or server_id in _scan_state["queue"]:
            skipped.append(server_id)
            continue
        _scan_state["queue"].append(server_id)
        queued.append(server_id)
    if queued and (_scan_worker is None or _scan_worker.done()):
        _scan_worker = asyncio.get_running_loop().create_task(_drain_scan_queue())
    return {"queued": queued, "already_queued": skipped, **_scan_status()}


def _require_authorization(body: ScanBody) -> None:
    if not body.confirm_authorized:
        raise HTTPException(400, "Confirm that you own these servers and are authorized to test them.")


@api.post("/api/servers/{server_id}/scan")
async def start_scan(server_id: str, body: ScanBody):
    _require_authorization(body)
    if not _db.get_server(server_id):
        raise HTTPException(404, f"Server '{server_id}' not found")
    return _enqueue_scans([server_id])


@api.post("/api/scans")
async def start_scans(body: ScanBody):
    _require_authorization(body)
    known = [s["server_id"] for s in _db.list_servers()]
    wanted = body.server_ids if body.server_ids is not None else known
    known_set = set(known)
    return _enqueue_scans([s for s in wanted if s in known_set])


@api.get("/api/scans/status")
def scans_status():
    return _scan_status()


@api.delete("/api/scans/queue")
def clear_scan_queue():
    cleared = len(_scan_state["queue"])
    _scan_state["queue"].clear()
    return {"cleared": cleared, **_scan_status()}


# ---------------------------------------------------------------------------
# Registration and discovery
# ---------------------------------------------------------------------------


class RegisterBody(BaseModel):
    server_id: str = Field(min_length=1, max_length=128)
    transport: Optional[str] = None
    command: Optional[str] = None
    args: Optional[List[str]] = None
    url: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    github_url: Optional[str] = None
    auto_inspect: bool = True


class OnboardBody(BaseModel):
    discovery_ids: List[str] = Field(min_length=1)


def _raise_on_error(data: Dict[str, Any]) -> Dict[str, Any]:
    if data.get("error"):
        raise HTTPException(400, str(data["error"]))
    return data


@api.post("/api/servers")
async def register(body: RegisterBody):
    from .server import register_server

    if body.transport and body.transport not in ("stdio", "sse", "streamable_http"):
        raise HTTPException(400, "transport must be stdio, sse or streamable_http")
    if not body.command and not body.url:
        raise HTTPException(400, "Provide a command for stdio servers or a URL for remote servers.")
    return _raise_on_error(_loads(await register_server(**body.model_dump())))


@api.post("/api/discover")
async def discover():
    from .server import discover_servers

    return _raise_on_error(_loads(await discover_servers()))


@api.post("/api/discovered/onboard")
async def onboard_discovered(body: OnboardBody):
    from .server import onboard_discovered_servers

    return _raise_on_error(
        _loads(await onboard_discovered_servers(discovery_ids=body.discovery_ids, auto_inspect=True))
    )


# ---------------------------------------------------------------------------
# Static SPA serving
# ---------------------------------------------------------------------------

if STATIC_DIR.exists() and (STATIC_DIR / "index.html").exists():
    assets_dir = STATIC_DIR / "assets"
    if assets_dir.exists():
        api.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @api.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        return FileResponse(str(STATIC_DIR / "index.html"))
else:

    @api.get("/{full_path:path}", include_in_schema=False)
    def spa_not_built(full_path: str):
        return JSONResponse(
            status_code=200,
            content={
                "message": "Dashboard UI not built yet.",
                "instructions": [
                    "cd dashboard",
                    "npm install",
                    "npm run build",
                ],
                "api_docs": "The REST API is available at /api/*",
            },
        )


# ---------------------------------------------------------------------------
# Launcher
# ---------------------------------------------------------------------------


def launch(host: str = "127.0.0.1", port: int = 7070, open_browser: bool = True) -> None:
    import uvicorn

    url = f"http://{host}:{port}"
    _log.info("Starting mcpsafetywarden dashboard at %s", url)
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    uvicorn.run(api, host=host, port=port, log_level="warning")
