import logging
from typing import Any, Dict, List, Optional

from ..core import database as db
from ..graph import builder as _graph_builder

_log = logging.getLogger(__name__)


def _gh_on_registered(server_id: str, transport: str, command: Optional[str], url: Optional[str]) -> None:
    try:
        _graph_builder.on_server_registered(server_id, transport, command, url)
    except Exception as _ge:
        _log.debug("graph hook on_server_registered failed: %s", _ge)


def _gh_on_tools_inspected(
    server_id: str,
    tools: List[Dict[str, Any]],
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> None:
    try:
        tool_ids = [t.get("tool_id") or f"{server_id}::{t.get('tool_name') or t.get('name', '')}" for t in tools]
        profiles = db.get_profiles_batch([tid for tid in tool_ids if tid])
        enriched = [
            {
                **t,
                **(
                    profiles.get(
                        t.get("tool_id") or f"{server_id}::{t.get('tool_name') or t.get('name', '')}",
                        {},
                    )
                    or {}
                ),
            }
            for t in tools
        ]
        _graph_builder.on_tools_inspected(
            server_id,
            enriched,
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_api_key=llm_api_key,
        )
    except Exception as _ge:
        _log.debug("graph hook on_tools_inspected failed: %s", _ge)


def _gh_on_credentials_detected(server_id: str, cref_map: Dict[str, Any]) -> None:
    env_keys = list((cref_map.get("env") or {}).keys())
    header_keys = list((cref_map.get("headers") or {}).keys())
    if not env_keys and not header_keys:
        return
    try:
        _graph_builder.on_credentials_detected(server_id, env_keys, header_keys)
    except Exception as _ge:
        _log.debug("graph hook on_credentials_detected failed: %s", _ge)


def _gh_cleanup_server(server_id: str) -> None:
    try:
        _graph_builder.cleanup_server_graph(server_id)
    except Exception as _ge:
        _log.debug("graph hook cleanup_server failed for %s: %s", server_id, _ge)


def _gh_on_scan_stored(server_id: str, findings: Dict[str, Any]) -> None:
    try:
        _graph_builder.on_scan_stored(server_id, findings)
    except Exception as _ge:
        _log.debug("graph hook on_scan_stored failed: %s", _ge)


def _gh_on_composition_analysis(
    server_id: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> None:
    try:
        _graph_builder.on_composition_analysis(server_id, llm_provider, llm_model, llm_api_key)
    except Exception as _ge:
        _log.debug("graph hook on_composition_analysis failed: %s", _ge)


def _gh_on_provenance_detected(server_id: str, prov_info: Dict[str, Any]) -> None:
    try:
        _graph_builder.on_provenance_detected(server_id, prov_info)
    except Exception as _ge:
        _log.debug("graph hook on_provenance_detected failed: %s", _ge)


def _gh_on_server_discovered(
    discovery_id: str,
    client: str,
    client_name: str,
    server_name: str,
    registered_server_id: Optional[str] = None,
) -> None:
    try:
        _graph_builder.on_server_discovered(discovery_id, client, client_name, server_name, registered_server_id)
    except Exception as _ge:
        _log.debug("graph hook on_server_discovered failed: %s", _ge)


def _gh_on_cross_server_analysis(server_id: str) -> None:
    try:
        conn = db.get_connection()
        try:
            rows = conn.execute(
                "SELECT DISTINCT client FROM discovered_servers WHERE registered_server_id = ?",
                (server_id,),
            ).fetchall()
            client_ids = [r["client"] for r in rows]
        finally:
            conn.close()
        for cid in client_ids:
            _graph_builder.on_cross_server_analysis(cid)
    except Exception as exc:
        _log.debug("_gh_on_cross_server_analysis failed for %s: %s", server_id, exc)
