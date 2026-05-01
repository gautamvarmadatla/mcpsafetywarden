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
            finding_ids = [
                f"finding::{server_id}::{tid.split('::', 1)[1]}"
                for tid in tool_ids if "::" in tid
            ]
            disc_rows = conn.execute(
                "SELECT discovery_id, client FROM discovered_servers WHERE registered_server_id = ?",
                (server_id,),
            ).fetchall()
            cred_prefix = f"cred_surface::{server_id}::"
            all_cred_rows = conn.execute(
                "SELECT obj_id FROM inventory_objects WHERE obj_type = 'credential_surface'",
            ).fetchall()
            relevant_ids = list(
                {server_id}
                | set(tool_ids)
                | set(finding_ids)
                | {dr["discovery_id"] for dr in disc_rows}
                | {dr["client"] for dr in disc_rows}
                | {r["obj_id"] for r in all_cred_rows if r["obj_id"].startswith(cred_prefix)}
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
