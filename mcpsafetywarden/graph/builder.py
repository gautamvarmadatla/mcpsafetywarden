import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from .. import database as _db
from ..inventory.models import InventoryObject, InventoryRelation
from . import store
from ._constants import READ_EFFECTS as _READ_EFFECTS, EXFILTRATION_EFFECTS as _EXFILTRATION_EFFECTS

_log = logging.getLogger(__name__)


def on_server_registered(
    server_id: str,
    transport: str,
    command: Optional[str],
    url: Optional[str],
) -> None:
    try:
        store.upsert_object(InventoryObject(
            id=server_id,
            type="mcp_server",
            name=server_id,
            source="registration",
            metadata={"transport": transport, "command": command, "url": url},
        ))
    except Exception as exc:
        _log.debug("graph on_server_registered failed for %s: %s", server_id, exc)


def on_credentials_detected(
    server_id: str,
    env_cred_keys: List[str],
    header_cred_keys: List[str],
) -> None:
    try:
        current_ids = set()
        for key in env_cred_keys:
            current_ids.add(f"cred_surface::{server_id}::env::{key}")
        for key in header_cred_keys:
            current_ids.add(f"cred_surface::{server_id}::header::{key}")

        conn = _db.get_connection()
        try:
            cred_prefix = f"cred_surface::{server_id}::"
            existing = conn.execute(
                "SELECT obj_id FROM inventory_objects WHERE obj_type = 'credential_surface'"
            ).fetchall()
            stale_ids = [
                r["obj_id"] for r in existing
                if r["obj_id"].startswith(cred_prefix) and r["obj_id"] not in current_ids
            ]
            if stale_ids:
                ph = ",".join("?" * len(stale_ids))
                conn.execute(
                    f"DELETE FROM inventory_relations WHERE source_id IN ({ph}) OR target_id IN ({ph})",
                    stale_ids * 2,
                )
                conn.execute(f"DELETE FROM inventory_objects WHERE obj_id IN ({ph})", stale_ids)
                conn.commit()
        finally:
            conn.close()

        for key in env_cred_keys:
            cred_id = f"cred_surface::{server_id}::env::{key}"
            store.upsert_object(InventoryObject(
                id=cred_id,
                type="credential_surface",
                name=f"env:{key}",
                source="registration",
                metadata={"server_id": server_id, "kind": "env_var", "key": key},
            ))
            store.upsert_relation(InventoryRelation(
                source_id=server_id,
                target_id=cred_id,
                relation="uses_credential",
            ))
        for key in header_cred_keys:
            cred_id = f"cred_surface::{server_id}::header::{key}"
            store.upsert_object(InventoryObject(
                id=cred_id,
                type="credential_surface",
                name=f"header:{key}",
                source="registration",
                metadata={"server_id": server_id, "kind": "header", "key": key},
            ))
            store.upsert_relation(InventoryRelation(
                source_id=server_id,
                target_id=cred_id,
                relation="uses_credential",
            ))
    except Exception as exc:
        _log.debug("graph on_credentials_detected failed for %s: %s", server_id, exc)


def on_tools_inspected(server_id: str, tools: List[Dict[str, Any]]) -> None:
    try:
        for t in tools:
            tool_name = t.get("tool_name") or t.get("name", "")
            if not tool_name:
                continue
            tool_id = f"{server_id}::{tool_name}"
            store.upsert_object(InventoryObject(
                id=tool_id,
                type="tool",
                name=tool_name,
                source="inspection",
                metadata={
                    "server_id": server_id,
                    "effect_class": t.get("effect_class", "unknown"),
                    "destructiveness": t.get("destructiveness", "unknown"),
                    "open_world": bool(t.get("open_world", False)),
                    "description": (t.get("description") or "")[:200],
                },
            ))
            store.upsert_relation(InventoryRelation(
                source_id=server_id,
                target_id=tool_id,
                relation="exposes",
            ))
        _add_composition_edges(server_id, tools)
    except Exception as exc:
        _log.debug("graph on_tools_inspected failed for %s: %s", server_id, exc)


def on_scan_stored(server_id: str, findings: Dict[str, Any]) -> None:
    try:
        for finding in findings.get("tool_findings", []):
            tool_name = finding.get("name", "")
            if not tool_name:
                continue
            tool_id = f"{server_id}::{tool_name}"
            finding_id = f"finding::{server_id}::{tool_name}"
            store.upsert_object(InventoryObject(
                id=finding_id,
                type="finding",
                name=(finding.get("finding") or tool_name)[:120],
                source="security_scan",
                metadata={
                    "risk_level": finding.get("risk_level"),
                    "risk_tags": finding.get("risk_tags", []),
                    "exploitation_scenario": (finding.get("exploitation_scenario") or "")[:300],
                    "remediation": (finding.get("remediation") or "")[:300],
                },
            ))
            store.upsert_relation(InventoryRelation(
                source_id=tool_id,
                target_id=finding_id,
                relation="affected_by",
                metadata={"risk_level": finding.get("risk_level")},
            ))
    except Exception as exc:
        _log.debug("graph on_scan_stored failed for %s: %s", server_id, exc)


def on_server_discovered(
    discovery_id: str,
    client: str,
    client_name: str,
    server_name: str,
    registered_server_id: Optional[str] = None,
) -> None:
    try:
        store.upsert_object(InventoryObject(
            id=client,
            type="agent_client",
            name=client_name,
            source="discovery",
        ))
        store.upsert_object(InventoryObject(
            id=discovery_id,
            type="mcp_config",
            name=server_name,
            source="discovery",
            metadata={"client": client, "registered_server_id": registered_server_id},
        ))
        store.upsert_relation(InventoryRelation(
            source_id=client,
            target_id=discovery_id,
            relation="declares",
        ))
        if registered_server_id:
            store.upsert_relation(InventoryRelation(
                source_id=discovery_id,
                target_id=registered_server_id,
                relation="declares",
            ))
    except Exception as exc:
        _log.debug("graph on_server_discovered failed for %s: %s", discovery_id, exc)


def _add_composition_edges(server_id: str, tools: List[Dict[str, Any]]) -> None:
    all_tool_ids = [
        f"{server_id}::{(t.get('tool_name') or t.get('name', ''))}"
        for t in tools if (t.get("tool_name") or t.get("name", ""))
    ]
    if all_tool_ids:
        conn = _db.get_connection()
        try:
            ph = ",".join("?" * len(all_tool_ids))
            conn.execute(
                f"DELETE FROM inventory_relations WHERE relation = 'can_exfiltrate'"
                f" AND (source_id IN ({ph}) OR target_id IN ({ph}))",
                all_tool_ids * 2,
            )
            conn.commit()
        finally:
            conn.close()

    read_tools = [t for t in tools if t.get("effect_class") in _READ_EFFECTS]
    external_tools = [t for t in tools if t.get("effect_class") in _EXFILTRATION_EFFECTS]
    if not read_tools or not external_tools:
        return
    for r in read_tools:
        r_name = r.get("tool_name") or r.get("name", "")
        if not r_name:
            continue
        for e in external_tools:
            e_name = e.get("tool_name") or e.get("name", "")
            if not e_name:
                continue
            try:
                store.upsert_relation(InventoryRelation(
                    source_id=f"{server_id}::{r_name}",
                    target_id=f"{server_id}::{e_name}",
                    relation="can_exfiltrate",
                    metadata={"composition": "read+external_action"},
                ))
            except Exception as exc:
                _log.debug("graph composition edge failed: %s", exc)


def _parse_json_field(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _load_server_cred_keys(server_id: str) -> Tuple[List[str], List[str]]:
    conn = _db.get_connection()
    try:
        row = conn.execute(
            "SELECT env_json, headers_json FROM servers WHERE server_id = ?", (server_id,)
        ).fetchone()
        if not row:
            return [], []
        env_data = _parse_json_field(_db.decrypt_field(row["env_json"] or "{}"))
        headers_data = _parse_json_field(_db.decrypt_field(row["headers_json"] or "{}"))
        env_keys = [k for k, v in env_data.items() if isinstance(v, str) and v.startswith("cref_")]
        header_keys = [k for k, v in headers_data.items() if isinstance(v, str) and v.startswith("cref_")]
        return env_keys, header_keys
    finally:
        conn.close()


def cleanup_server_graph(server_id: str) -> None:
    try:
        conn = _db.get_connection()
        try:
            tool_rows = conn.execute(
                "SELECT tool_id FROM tools WHERE server_id = ?", (server_id,)
            ).fetchall()
            tool_ids = [r["tool_id"] for r in tool_rows]
            finding_ids = [
                f"finding::{server_id}::{tid.split('::', 1)[1]}"
                for tid in tool_ids if "::" in tid
            ]

            cred_prefix = f"cred_surface::{server_id}::"
            cred_rows = conn.execute(
                "SELECT obj_id FROM inventory_objects WHERE obj_type = 'credential_surface'",
            ).fetchall()
            cred_ids = [r["obj_id"] for r in cred_rows if r["obj_id"].startswith(cred_prefix)]

            disc_rows = conn.execute(
                "SELECT discovery_id, client FROM discovered_servers WHERE registered_server_id = ?",
                (server_id,),
            ).fetchall()
            config_ids = [r["discovery_id"] for r in disc_rows]
            client_ids = []
            for client_id in {r["client"] for r in disc_rows}:
                total = conn.execute(
                    "SELECT COUNT(*) FROM discovered_servers WHERE client = ?", (client_id,)
                ).fetchone()[0]
                this_server_refs = sum(1 for r in disc_rows if r["client"] == client_id)
                if total <= this_server_refs:
                    client_ids.append(client_id)

            ids_to_delete = list({server_id} | set(tool_ids) | set(finding_ids) | set(cred_ids) | set(config_ids) | set(client_ids))
            ph = ",".join("?" * len(ids_to_delete))
            conn.execute(
                f"DELETE FROM inventory_relations WHERE source_id IN ({ph}) OR target_id IN ({ph})",
                ids_to_delete * 2,
            )
            conn.execute(f"DELETE FROM inventory_objects WHERE obj_id IN ({ph})", ids_to_delete)
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        _log.debug("graph cleanup_server_graph failed for %s: %s", server_id, exc)


def rebuild_from_db() -> Dict[str, int]:
    counts: Dict[str, int] = {"servers": 0, "tools": 0, "findings": 0, "discovered": 0}
    for server in _db.list_servers():
        sid = server["server_id"]
        on_server_registered(sid, server["transport"], server.get("command"), server.get("url"))
        counts["servers"] += 1

        env_cred_keys, header_cred_keys = _load_server_cred_keys(sid)
        if env_cred_keys or header_cred_keys:
            on_credentials_detected(sid, env_cred_keys, header_cred_keys)

        tools_raw = _db.list_tools(sid)
        if tools_raw:
            profiles = _db.get_profiles_batch([t["tool_id"] for t in tools_raw])
            enriched = []
            for t in tools_raw:
                p = profiles.get(t["tool_id"]) or {}
                enriched.append({**t, **p})
            on_tools_inspected(sid, enriched)
            counts["tools"] += len(enriched)

        scan = _db.get_latest_security_scan(sid)
        if scan:
            on_scan_stored(sid, scan)
            counts["findings"] += len(scan.get("tool_findings", []))

    for disc in _db.list_discovered_servers():
        on_server_discovered(
            disc["discovery_id"],
            disc["client"],
            disc["client_name"],
            disc["server_name"],
            disc.get("registered_server_id"),
        )
        counts["discovered"] += 1

    return counts
