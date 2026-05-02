"""Read-only query layer for the dashboard. Never writes to the DB."""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from .core.database import get_connection, DB_PATH

_log = logging.getLogger(__name__)


def _j(s: Any, default: Any = None) -> Any:
    if default is None:
        default = {}
    try:
        return json.loads(s) if s else default
    except (json.JSONDecodeError, TypeError):
        return default


def get_health() -> Dict[str, Any]:
    try:
        path = str(DB_PATH)
        size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
        conn = get_connection()
        try:
            server_count = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
        finally:
            conn.close()
        return {"ok": True, "db_path": path, "db_size_bytes": size, "server_count": server_count}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_overview() -> Dict[str, Any]:
    conn = get_connection()
    try:
        server_count = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
        tool_count = conn.execute("SELECT COUNT(*) FROM tools").fetchone()[0]
        blocked_tools = conn.execute("SELECT COUNT(*) FROM tool_policies WHERE policy='block'").fetchone()[0]

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        runs_24h = conn.execute("SELECT COUNT(*) FROM tool_runs WHERE timestamp > ?", (cutoff,)).fetchone()[0]

        rows = conn.execute(
            """
            SELECT ss.overall_risk_level, COUNT(*) as cnt
            FROM security_scans ss
            INNER JOIN (
                SELECT server_id, MAX(scanned_at) as max_at FROM security_scans GROUP BY server_id
            ) latest ON ss.server_id = latest.server_id AND ss.scanned_at = latest.max_at
            GROUP BY ss.overall_risk_level
            """,
        ).fetchall()
        risk_dist = {r["overall_risk_level"]: r["cnt"] for r in rows}

        effect_rows = conn.execute(
            "SELECT effect_class, COUNT(*) as cnt FROM behavior_profiles GROUP BY effect_class"
        ).fetchall()
        effect_dist = {r["effect_class"]: r["cnt"] for r in effect_rows}

        critical = risk_dist.get("CRITICAL", 0)
        high = risk_dist.get("HIGH", 0)

        recent_fails = conn.execute(
            """
            SELECT tr.run_id, tr.tool_id, tr.timestamp, tr.latency_ms, tr.notes, tr.output_preview
            FROM tool_runs tr
            WHERE tr.success=0 OR (tr.notes IS NOT NULL AND tr.notes != '')
            ORDER BY tr.timestamp DESC LIMIT 10
            """
        ).fetchall()
        recent_activity = []
        for r in recent_fails:
            parts = r["tool_id"].split("::", 1)
            recent_activity.append(
                {
                    "run_id": r["run_id"],
                    "server_id": parts[0] if len(parts) == 2 else r["tool_id"],
                    "tool_name": parts[1] if len(parts) == 2 else "",
                    "timestamp": r["timestamp"],
                    "latency_ms": r["latency_ms"],
                    "notes": r["notes"],
                    "preview": r["output_preview"],
                }
            )

        recent_scans = conn.execute(
            "SELECT server_id, overall_risk_level, provider, scanned_at FROM security_scans ORDER BY scanned_at DESC LIMIT 5"
        ).fetchall()

        return {
            "server_count": server_count,
            "tool_count": tool_count,
            "blocked_tools": blocked_tools,
            "runs_24h": runs_24h,
            "critical_findings": critical,
            "high_findings": high,
            "risk_distribution": risk_dist,
            "effect_distribution": effect_dist,
            "recent_activity": recent_activity,
            "recent_scans": [dict(r) for r in recent_scans],
        }
    finally:
        conn.close()


def list_servers(transport: Optional[str] = None, risk_level: Optional[str] = None) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM servers ORDER BY registered_at DESC").fetchall()
        result = []
        for r in rows:
            sid = r["server_id"]
            tool_count = conn.execute("SELECT COUNT(*) FROM tools WHERE server_id=?", (sid,)).fetchone()[0]
            scan = conn.execute(
                "SELECT overall_risk_level, scanned_at, provider FROM security_scans WHERE server_id=? ORDER BY scanned_at DESC LIMIT 1",
                (sid,),
            ).fetchone()
            last_run = conn.execute(
                """
                SELECT MAX(tr.timestamp) as last_run FROM tool_runs tr
                INNER JOIN tools t ON tr.tool_id = t.tool_id
                WHERE t.server_id=?
                """,
                (sid,),
            ).fetchone()
            server = {
                "server_id": sid,
                "transport": r["transport"],
                "command": r["command"],
                "url": r["url"],
                "registered_at": r["registered_at"],
                "tool_count": tool_count,
                "latest_scan_risk": scan["overall_risk_level"] if scan else None,
                "latest_scan_at": scan["scanned_at"] if scan else None,
                "latest_scan_provider": scan["provider"] if scan else None,
                "last_run_at": last_run["last_run"] if last_run else None,
            }
            if transport and server["transport"] != transport:
                continue
            if risk_level and server["latest_scan_risk"] != risk_level:
                continue
            result.append(server)
        return result
    finally:
        conn.close()


def get_server(server_id: str) -> Optional[Dict]:
    conn = get_connection()
    try:
        r = conn.execute("SELECT * FROM servers WHERE server_id=?", (server_id,)).fetchone()
        if not r:
            return None
        snap = conn.execute("SELECT * FROM source_hashes WHERE server_id=?", (server_id,)).fetchone()
        return {
            "server_id": r["server_id"],
            "transport": r["transport"],
            "command": r["command"],
            "url": r["url"],
            "registered_at": r["registered_at"],
            "args": _j(r["args_json"], []),
            "source_hash": dict(snap) if snap else None,
        }
    finally:
        conn.close()


def list_tools(
    server_id: Optional[str] = None,
    effect_class: Optional[str] = None,
    policy: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
) -> Dict[str, Any]:
    conn = get_connection()
    try:
        where_clauses = []
        params: List[Any] = []
        if server_id:
            where_clauses.append("t.server_id = ?")
            params.append(server_id)
        if effect_class:
            where_clauses.append("bp.effect_class = ?")
            params.append(effect_class)
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        total_row = conn.execute(
            f"SELECT COUNT(*) FROM tools t LEFT JOIN behavior_profiles bp ON t.tool_id=bp.tool_id {where_sql}",
            params,
        ).fetchone()
        total = total_row[0]
        offset = (page - 1) * limit

        rows = conn.execute(
            f"""
            SELECT t.*, bp.effect_class, bp.retry_safety, bp.destructiveness,
                   bp.latency_p50_ms, bp.latency_p95_ms, bp.failure_rate,
                   bp.output_size_p95_bytes, bp.run_count, bp.confidence_json,
                   tp.policy
            FROM tools t
            LEFT JOIN behavior_profiles bp ON t.tool_id = bp.tool_id
            LEFT JOIN tool_policies tp ON t.server_id=tp.server_id AND t.tool_name=tp.tool_name
            {where_sql}
            ORDER BY t.server_id, t.tool_name
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()

        items = []
        for r in rows:
            if policy and r["policy"] != policy:
                continue
            items.append(
                {
                    "tool_id": r["tool_id"],
                    "server_id": r["server_id"],
                    "tool_name": r["tool_name"],
                    "description": r["description"],
                    "discovered_at": r["discovered_at"],
                    "effect_class": r["effect_class"] or "unknown",
                    "retry_safety": r["retry_safety"] or "unknown",
                    "destructiveness": r["destructiveness"] or "unknown",
                    "latency_p50_ms": r["latency_p50_ms"],
                    "latency_p95_ms": r["latency_p95_ms"],
                    "failure_rate": r["failure_rate"],
                    "output_size_p95_bytes": r["output_size_p95_bytes"],
                    "run_count": r["run_count"] or 0,
                    "confidence": _j(r["confidence_json"], {}),
                    "policy": r["policy"],
                }
            )

        return {"items": items, "total": total, "page": page, "limit": limit}
    finally:
        conn.close()


def get_tool_detail(server_id: str, tool_name: str) -> Optional[Dict]:
    conn = get_connection()
    try:
        r = conn.execute("SELECT * FROM tools WHERE server_id=? AND tool_name=?", (server_id, tool_name)).fetchone()
        if not r:
            return None
        bp = conn.execute("SELECT * FROM behavior_profiles WHERE tool_id=?", (r["tool_id"],)).fetchone()
        policy = conn.execute(
            "SELECT policy FROM tool_policies WHERE server_id=? AND tool_name=?", (server_id, tool_name)
        ).fetchone()
        runs = conn.execute(
            "SELECT run_id, timestamp, success, latency_ms, output_size, notes, output_preview FROM tool_runs WHERE tool_id=? ORDER BY timestamp DESC LIMIT 5",
            (r["tool_id"],),
        ).fetchall()
        return {
            "tool_id": r["tool_id"],
            "server_id": server_id,
            "tool_name": tool_name,
            "description": r["description"],
            "schema": _j(r["schema_json"], {}),
            "discovered_at": r["discovered_at"],
            "profile": dict(bp) if bp else None,
            "policy": policy["policy"] if policy else None,
            "recent_runs": [dict(run) for run in runs],
        }
    finally:
        conn.close()


def get_latest_scan(server_id: str) -> Optional[Dict]:
    conn = get_connection()
    try:
        r = conn.execute(
            "SELECT * FROM security_scans WHERE server_id=? ORDER BY scanned_at DESC LIMIT 1",
            (server_id,),
        ).fetchone()
        if not r:
            return None
        return {
            "scan_id": r["scan_id"],
            "server_id": r["server_id"],
            "provider": r["provider"],
            "model_id": r["model_id"],
            "overall_risk_level": r["overall_risk_level"],
            "summary_text": r["summary_text"],
            "tool_findings": _j(r["tool_findings_json"], []),
            "server_risks": _j(r["server_risks_json"], []),
            "scanned_at": r["scanned_at"],
        }
    finally:
        conn.close()


def list_scans(server_id: str) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT scan_id, server_id, provider, model_id, overall_risk_level, scanned_at FROM security_scans WHERE server_id=? ORDER BY scanned_at DESC",
            (server_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_snapshots(server_id: str) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM tool_snapshots WHERE server_id=? ORDER BY snapshot_at DESC",
            (server_id,),
        ).fetchall()
        result = []
        for i, r in enumerate(rows):
            drift = False
            if i < len(rows) - 1:
                drift = r["tools_hash"] != rows[i + 1]["tools_hash"]
            result.append(
                {
                    "snapshot_id": r["snapshot_id"],
                    "snapshot_at": r["snapshot_at"],
                    "tool_names": _j(r["tool_names_json"], []),
                    "tools_hash": r["tools_hash"],
                    "drift_from_previous": drift,
                }
            )
        return result
    finally:
        conn.close()


def get_all_findings(
    risk_level: Optional[str] = None,
    server_id: Optional[str] = None,
    page: int = 1,
    limit: int = 100,
) -> Dict[str, Any]:
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT ss.scan_id, ss.server_id, ss.provider, ss.model_id,
                   ss.tool_findings_json, ss.server_risks_json, ss.scanned_at
            FROM security_scans ss
            INNER JOIN (
                SELECT server_id, MAX(scanned_at) as max_at FROM security_scans GROUP BY server_id
            ) latest ON ss.server_id=latest.server_id AND ss.scanned_at=latest.max_at
            ORDER BY ss.scanned_at DESC
            """,
        ).fetchall()

        tool_findings: List[Dict] = []
        server_risks: List[Dict] = []
        for row in rows:
            if server_id and row["server_id"] != server_id:
                continue
            for f in _j(row["tool_findings_json"], []):
                entry = {
                    **f,
                    "server_id": row["server_id"],
                    "scanned_at": row["scanned_at"],
                    "provider": row["provider"],
                }
                if risk_level and entry.get("risk_level") != risk_level:
                    continue
                tool_findings.append(entry)
            for r in _j(row["server_risks_json"], []):
                server_risks.append({**r, "server_id": row["server_id"], "scanned_at": row["scanned_at"]})

        total = len(tool_findings)
        start = (page - 1) * limit
        return {
            "items": tool_findings[start : start + limit],
            "server_risks": server_risks,
            "total": total,
            "page": page,
            "limit": limit,
        }
    finally:
        conn.close()


def get_runs(
    server_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    success: Optional[bool] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    after_id: Optional[int] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    conn = get_connection()
    try:
        clauses = []
        params: List[Any] = []
        if server_id:
            clauses.append("t.server_id = ?")
            params.append(server_id)
        if tool_name:
            clauses.append("t.tool_name = ?")
            params.append(tool_name)
        if success is not None:
            clauses.append("tr.success = ?")
            params.append(1 if success else 0)
        if start:
            clauses.append("tr.timestamp >= ?")
            params.append(start)
        if end:
            clauses.append("tr.timestamp <= ?")
            params.append(end)
        if after_id:
            clauses.append("tr.run_id > ?")
            params.append(after_id)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM tool_runs tr INNER JOIN tools t ON tr.tool_id=t.tool_id {where}",
            params,
        ).fetchone()[0]

        rows = conn.execute(
            f"""
            SELECT tr.run_id, tr.tool_id, tr.timestamp, tr.success, tr.is_tool_error,
                   tr.latency_ms, tr.output_size, tr.notes, tr.output_preview,
                   t.server_id, t.tool_name
            FROM tool_runs tr
            INNER JOIN tools t ON tr.tool_id = t.tool_id
            {where}
            ORDER BY tr.timestamp DESC
            LIMIT ?
            """,
            params + [limit],
        ).fetchall()

        return {
            "items": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
        }
    finally:
        conn.close()


def get_runs_stats(hours: int = 24) -> Dict[str, Any]:
    conn = get_connection()
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        rows = conn.execute(
            "SELECT timestamp, success, latency_ms FROM tool_runs WHERE timestamp > ? ORDER BY timestamp ASC",
            (cutoff,),
        ).fetchall()

        buckets: Dict[str, Dict] = {}
        for r in rows:
            try:
                dt = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
                bucket = dt.strftime("%Y-%m-%dT%H:00:00")
            except Exception:
                continue
            if bucket not in buckets:
                buckets[bucket] = {"runs": 0, "failures": 0, "latencies": []}
            buckets[bucket]["runs"] += 1
            if not r["success"]:
                buckets[bucket]["failures"] += 1
            if r["latency_ms"] is not None:
                buckets[bucket]["latencies"].append(r["latency_ms"])

        series = []
        for hour, data in sorted(buckets.items()):
            latencies = sorted(data["latencies"])
            p95 = latencies[int(len(latencies) * 0.95)] if latencies else None
            series.append(
                {
                    "hour": hour,
                    "runs": data["runs"],
                    "failures": data["failures"],
                    "failure_rate": data["failures"] / data["runs"] if data["runs"] else 0,
                    "latency_p95": p95,
                }
            )

        return {"series": series, "hours": hours}
    finally:
        conn.close()


def get_policies() -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT tp.*, t.description FROM tool_policies tp LEFT JOIN tools t ON tp.server_id=t.server_id AND tp.tool_name=t.tool_name ORDER BY tp.server_id, tp.tool_name"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def set_policy(server_id: str, tool_name: str, policy: Optional[str]) -> None:
    from .core.database import set_tool_policy as _set

    _set(server_id, tool_name, policy)


def get_graph(server_id: Optional[str] = None) -> Dict[str, Any]:
    conn = get_connection()
    try:
        if server_id:
            obj_rows = conn.execute(
                "SELECT * FROM inventory_objects WHERE obj_id LIKE ? OR name LIKE ? OR source LIKE ?",
                (f"%{server_id}%", f"%{server_id}%", f"%{server_id}%"),
            ).fetchall()
            obj_ids = {r["obj_id"] for r in obj_rows}
            rel_rows = (
                conn.execute(
                    "SELECT * FROM inventory_relations WHERE source_id IN ({}) OR target_id IN ({})".format(
                        ",".join("?" * len(obj_ids)), ",".join("?" * len(obj_ids))
                    ),
                    list(obj_ids) + list(obj_ids),
                ).fetchall()
                if obj_ids
                else []
            )
        else:
            obj_rows = conn.execute("SELECT * FROM inventory_objects").fetchall()
            rel_rows = conn.execute("SELECT * FROM inventory_relations").fetchall()

        objects = [
            {
                "id": r["obj_id"],
                "type": r["obj_type"],
                "name": r["name"],
                "source": r["source"],
                "metadata": _j(r["metadata"], {}),
            }
            for r in obj_rows
        ]
        relations = [
            {
                "source": r["source_id"],
                "target": r["target_id"],
                "relation": r["relation"],
                "metadata": _j(r["metadata"], {}),
            }
            for r in rel_rows
        ]
        return {"objects": objects, "relations": relations}
    finally:
        conn.close()


def get_discovered() -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM discovered_servers WHERE registered_server_id IS NULL ORDER BY last_seen_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
