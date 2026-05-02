"""Web dashboard for mcpsafetywarden - FastAPI backend + static SPA."""

import logging
import threading
import webbrowser
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import dashboard_db as _db

_log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"

api = FastAPI(title="mcpsafetywarden", version="1.0", docs_url=None, redoc_url=None)
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


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
    page: int = Query(1, ge=1),
    limit: int = Query(50, le=200),
):
    return _db.list_tools(server_id=server_id, effect_class=effect_class, policy=policy, page=page, limit=limit)


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
        return {"rebuilt": False, "error": str(e)}


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
