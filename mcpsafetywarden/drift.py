"""Schema and tool-list drift detection for registered MCP servers."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import database as db
from .client_manager import _list_tools_raw

_log = logging.getLogger(__name__)

_SEVERITY_ORDER: Dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
_SEVERITY_NAMES: Dict[int, str] = {v: k for k, v in _SEVERITY_ORDER.items()}


def _max_severity(findings: List[Dict[str, Any]]) -> str:
    best = max((_SEVERITY_ORDER.get(f.get("severity", "NONE"), 0) for f in findings), default=0)
    return _SEVERITY_NAMES.get(best, "NONE")


def _diff_input_schema(
    old_schema: Dict[str, Any],
    new_schema: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Structured field-level diff of two JSON Schema inputSchema objects."""
    changes: List[Dict[str, Any]] = []
    old_props = old_schema.get("properties") or {}
    new_props = new_schema.get("properties") or {}
    old_req = set(old_schema.get("required") or [])
    new_req = set(new_schema.get("required") or [])

    for prop in sorted(set(old_props) - set(new_props)):
        changes.append({"field": f"properties.{prop}", "change": "removed", "severity": "HIGH"})

    for prop in sorted(set(new_props) - set(old_props)):
        changes.append({
            "field": f"properties.{prop}",
            "change": "added",
            "severity": "MEDIUM" if prop in new_req else "LOW",
        })

    for prop in sorted(set(old_props) & set(new_props)):
        old_type = (old_props[prop] or {}).get("type")
        new_type = (new_props[prop] or {}).get("type")
        if old_type != new_type:
            changes.append({
                "field": f"properties.{prop}.type",
                "change": f"{old_type} -> {new_type}",
                "severity": "HIGH",
            })

    for prop in sorted(old_req - new_req):
        changes.append({
            "field": "required",
            "param": prop,
            "change": "no_longer_required",
            "severity": "MEDIUM",
        })
    for prop in sorted(new_req - old_req):
        if prop in new_props:
            changes.append({
                "field": "required",
                "param": prop,
                "change": "now_required",
                "severity": "MEDIUM",
            })

    return changes


def compare_db_snapshots(
    server_id: str,
    old: Dict[str, Dict[str, Any]],
    new: Dict[str, Dict[str, Any]],
    checked_at: str,
) -> Dict[str, Any]:
    """
    Pure comparison of two tool-state dicts (db.list_tools() row format, keyed by tool_name).
    No I/O. Returns a drift report dict.
    """
    findings: List[Dict[str, Any]] = []

    for name in sorted(set(old) - set(new)):
        findings.append({
            "tool_name": name,
            "change_type": "tool_removed",
            "severity": "CRITICAL",
            "detail": "Tool present in baseline but no longer served",
        })

    for name in sorted(set(new) - set(old)):
        findings.append({
            "tool_name": name,
            "change_type": "tool_added",
            "severity": "LOW",
            "detail": "New tool not present in baseline",
            "description": (new[name].get("description") or "")[:200],
        })

    for name in sorted(set(old) & set(new)):
        o = old[name]
        n = new[name]

        old_desc = o.get("description") or ""
        new_desc = n.get("description") or ""
        if old_desc != new_desc:
            findings.append({
                "tool_name": name,
                "change_type": "description_changed",
                "severity": "MEDIUM",
                "old_description": old_desc[:300],
                "new_description": new_desc[:300],
                "detail": "Description changed - possible prompt-injection swap",
            })

        old_hash = o.get("schema_hash") or ""
        new_hash = n.get("schema_hash") or ""
        if old_hash and new_hash and old_hash != "OVERSIZED" and old_hash != new_hash:
            old_schema = o.get("schema") or {}
            new_schema = n.get("schema") or {}
            schema_diffs = _diff_input_schema(old_schema, new_schema)
            sev = _max_severity(schema_diffs) if schema_diffs else "MEDIUM"
            findings.append({
                "tool_name": name,
                "change_type": "schema_changed",
                "severity": sev,
                "schema_changes": schema_diffs,
                "detail": (
                    f"{len(schema_diffs)} field-level change(s) detected"
                    if schema_diffs
                    else "Schema hash changed"
                ),
            })

    overall = _max_severity(findings) if findings else "NONE"
    return {
        "server_id": server_id,
        "checked_at": checked_at,
        "drift_detected": bool(findings),
        "overall_severity": overall,
        "findings": findings,
        "tools_added": [f["tool_name"] for f in findings if f["change_type"] == "tool_added"],
        "tools_removed": [f["tool_name"] for f in findings if f["change_type"] == "tool_removed"],
        "tools_modified": [
            f["tool_name"] for f in findings
            if f["change_type"] in ("description_changed", "schema_changed")
        ],
    }


async def check_server_drift(
    server_id: str,
    update_baseline: bool = True,
) -> Dict[str, Any]:
    """
    Live drift check: re-enumerate tools from the running server and compare against
    the stored baseline from the last inspect_server call.

    If update_baseline=True and drift is detected, updates the stored baseline to the
    current live state so repeated calls track incremental changes.
    """
    server = db.get_server(server_id)
    if not server:
        raise ValueError(f"Server {server_id!r} is not registered")

    stored_list = db.list_tools(server_id)
    if not stored_list:
        raise ValueError(
            f"No tools stored for {server_id!r} - run inspect_server first to establish a baseline"
        )

    old = {t["tool_name"]: t for t in stored_list}
    live_raw = await asyncio.wait_for(_list_tools_raw(server), timeout=30)
    checked_at = datetime.now(timezone.utc).isoformat()

    new = {
        t["name"]: {
            "tool_name": t["name"],
            "description": t.get("description") or "",
            "schema": t.get("schema") or {},
            "schema_hash": db.make_hash(t.get("schema") or {}),
        }
        for t in live_raw
    }

    result = compare_db_snapshots(server_id, old, new, checked_at)

    source_record = db.get_source_hash(server_id)
    if source_record:
        result["source_drift_info"] = {
            "github_url": source_record.get("github_url"),
            "last_checked_at": source_record.get("last_checked_at"),
            "first_seen_at": source_record.get("first_seen_at"),
            "note": "Run scan --github-url to re-check source code for changes",
        }

    snapshot = db.get_latest_tool_snapshot(server_id)
    result["baseline_snapshot_at"] = snapshot["snapshot_at"] if snapshot else None

    if update_baseline and result["drift_detected"]:
        loop = asyncio.get_running_loop()
        for t in live_raw:
            await loop.run_in_executor(
                None,
                db.upsert_tool,
                server_id,
                t["name"],
                t.get("description") or "",
                t.get("schema") or {},
                t.get("annotations") or {},
            )
        name_to_hash = {t["name"]: db.make_hash(t.get("schema") or {}) for t in live_raw}
        await loop.run_in_executor(None, db.upsert_tool_snapshot, server_id, name_to_hash)
        result["baseline_updated"] = True
    else:
        result["baseline_updated"] = False

    return result
