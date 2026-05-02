import json
import logging
from typing import Any, Dict, List, Optional

from .. import database as _db
from ..inventory.models import InventoryObject, InventoryRelation

_log = logging.getLogger(__name__)


def _jl(s: Any, default: Any) -> Any:
    try:
        return json.loads(s) if s else default
    except (json.JSONDecodeError, TypeError):
        return default


def upsert_object(obj: InventoryObject) -> None:
    conn = _db.get_connection()
    try:
        conn.execute(
            """
            INSERT INTO inventory_objects (obj_id, obj_type, name, source, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(obj_id) DO UPDATE SET
                obj_type=excluded.obj_type,
                name=excluded.name,
                source=excluded.source,
                metadata=excluded.metadata
            """,
            (obj.id, obj.type, obj.name, obj.source, json.dumps(obj.metadata)),
        )
        conn.commit()
    finally:
        conn.close()


def upsert_relation(rel: InventoryRelation) -> None:
    conn = _db.get_connection()
    try:
        conn.execute(
            """
            INSERT INTO inventory_relations (source_id, target_id, relation, metadata)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source_id, target_id, relation) DO UPDATE SET
                metadata=excluded.metadata
            """,
            (rel.source_id, rel.target_id, rel.relation, json.dumps(rel.metadata)),
        )
        conn.commit()
    finally:
        conn.close()


def patch_object_metadata(obj_id: str, updates: Dict[str, Any]) -> None:
    conn = _db.get_connection()
    try:
        row = conn.execute(
            "SELECT metadata FROM inventory_objects WHERE obj_id = ?", (obj_id,)
        ).fetchone()
        if row is None:
            return
        meta = _jl(row["metadata"], {})
        meta.update(updates)
        conn.execute(
            "UPDATE inventory_objects SET metadata = ? WHERE obj_id = ?",
            (json.dumps(meta), obj_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_object(obj_id: str) -> Optional[Dict[str, Any]]:
    conn = _db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM inventory_objects WHERE obj_id = ?", (obj_id,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["metadata"] = _jl(d.pop("metadata", "{}"), {})
        return d
    finally:
        conn.close()


def get_objects_by_type(obj_type: str) -> List[Dict[str, Any]]:
    conn = _db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM inventory_objects WHERE obj_type = ?", (obj_type,)
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["metadata"] = _jl(d.pop("metadata", "{}"), {})
            result.append(d)
        return result
    finally:
        conn.close()


def get_relations_from(source_id: str) -> List[Dict[str, Any]]:
    conn = _db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM inventory_relations WHERE source_id = ?", (source_id,)
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["metadata"] = _jl(d.pop("metadata", "{}"), {})
            result.append(d)
        return result
    finally:
        conn.close()


def get_relations_to(target_id: str) -> List[Dict[str, Any]]:
    conn = _db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM inventory_relations WHERE target_id = ?", (target_id,)
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["metadata"] = _jl(d.pop("metadata", "{}"), {})
            result.append(d)
        return result
    finally:
        conn.close()


def get_full_graph(server_id: Optional[str] = None) -> Dict[str, Any]:
    conn = _db.get_connection()
    try:
        if server_id:
            tool_ids_raw = conn.execute(
                "SELECT tool_id FROM tools WHERE server_id = ?", (server_id,)
            ).fetchall()
            tool_ids = [r["tool_id"] for r in tool_ids_raw]
            finding_prefix = f"finding::{server_id}::"
            tamper_prefix = f"finding::tamper::{server_id}::"
            finding_rows_raw = conn.execute(
                "SELECT obj_id FROM inventory_objects WHERE obj_id LIKE ? OR obj_id LIKE ?",
                (finding_prefix + "%", tamper_prefix + "%"),
            ).fetchall()
            finding_ids = [r["obj_id"] for r in finding_rows_raw]
            disc_rows = conn.execute(
                "SELECT discovery_id, client FROM discovered_servers WHERE registered_server_id = ?",
                (server_id,),
            ).fetchall()
            cred_prefix = f"cred_surface::{server_id}::"
            cred_rows = conn.execute(
                "SELECT obj_id FROM inventory_objects WHERE obj_id LIKE ?",
                (cred_prefix + "%",),
            ).fetchall()
            relevant_ids = list(
                {server_id, f"provenance::{server_id}"}
                | set(tool_ids)
                | set(finding_ids)
                | {dr["discovery_id"] for dr in disc_rows}
                | {dr["client"] for dr in disc_rows}
                | {r["obj_id"] for r in cred_rows}
            )
            ph = ",".join("?" * len(relevant_ids))
            obj_rows = conn.execute(
                f"SELECT * FROM inventory_objects WHERE obj_id IN ({ph})",
                relevant_ids,
            ).fetchall()
            rel_rows = conn.execute(
                f"SELECT * FROM inventory_relations WHERE source_id IN ({ph}) OR target_id IN ({ph})",
                relevant_ids * 2,
            ).fetchall()
            technique_ids = list({r["target_id"] for r in rel_rows if r["relation"] == "maps_to"})
            if technique_ids:
                tph = ",".join("?" * len(technique_ids))
                tech_rows = conn.execute(
                    f"SELECT * FROM inventory_objects WHERE obj_id IN ({tph})",
                    technique_ids,
                ).fetchall()
                obj_rows = list(obj_rows) + list(tech_rows)
        else:
            obj_rows = conn.execute("SELECT * FROM inventory_objects").fetchall()
            rel_rows = conn.execute("SELECT * FROM inventory_relations").fetchall()

        objects = []
        for row in obj_rows:
            d = dict(row)
            d["metadata"] = _jl(d.pop("metadata", "{}"), {})
            objects.append(d)

        relations = []
        for row in rel_rows:
            d = dict(row)
            d["metadata"] = _jl(d.pop("metadata", "{}"), {})
            relations.append(d)

        return {"objects": objects, "relations": relations}
    finally:
        conn.close()


def get_servers_by_client(client_id: str) -> List[str]:
    """Return server_ids reachable from an agent_client via the declares chain."""
    server_ids: List[str] = []
    for rel in get_relations_from(client_id):
        if rel["relation"] != "declares":
            continue
        config_obj = get_object(rel["target_id"])
        if not config_obj or config_obj["obj_type"] != "mcp_config":
            continue
        for rel2 in get_relations_from(config_obj["obj_id"]):
            if rel2["relation"] != "declares":
                continue
            srv_obj = get_object(rel2["target_id"])
            if srv_obj and srv_obj["obj_type"] == "mcp_server":
                sid = rel2["target_id"]
                if sid not in server_ids:
                    server_ids.append(sid)
    return server_ids


def get_tools_for_servers(server_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Return tool metadata dicts grouped by server_id."""
    result: Dict[str, List[Dict[str, Any]]] = {}
    for sid in server_ids:
        tools = []
        for rel in get_relations_from(sid):
            if rel["relation"] != "exposes":
                continue
            tobj = get_object(rel["target_id"])
            if tobj and tobj["obj_type"] == "tool":
                tools.append({**tobj.get("metadata", {}), "name": tobj["name"], "obj_id": tobj["obj_id"]})
        result[sid] = tools
    return result
