import json
import logging
from typing import Optional

from ..graph import store as _graph_store, builder as _graph_builder, explain as _graph_explain
from ._app import mcp

_log = logging.getLogger(__name__)


@mcp.tool()
def get_risk_graph(server_id: Optional[str] = None, rebuild: bool = False) -> str:
    """
    Return the inventory graph of MCP servers, tools, security findings, and their relationships.

    The graph exposes connections that preflight_tool_call and safe_tool_call use for
    blast-radius context. On first call the graph may be empty - pass rebuild=True to
    populate it from all data Safety Warden has already stored.

    server_id: scope the graph to one server; omit for the full workspace graph.
    rebuild:   True = rebuild from existing Safety Warden tables before returning.

    Returns objects (nodes) and relations (edges). Node types: mcp_server, tool, finding,
    agent_client, mcp_config, credential_surface, mitre_technique. Relation types: exposes,
    affected_by, can_exfiltrate, declares, uses_credential, maps_to.

    NEXT: explain_tool_risk(server_id, tool_name) to walk risk paths for a specific tool.
    NEXT: export_graph(format="mermaid") for a diagram.
    """
    try:
        if rebuild:
            counts = _graph_builder.rebuild_from_db()
            graph = _graph_store.get_full_graph(server_id)
            return json.dumps({"rebuilt": counts, "graph": graph}, indent=2)

        graph = _graph_store.get_full_graph(server_id)
        if not graph["objects"]:
            if server_id and _graph_store.get_full_graph()["objects"]:
                return json.dumps(
                    {
                        "note": f"No graph nodes found for server '{server_id}'. Run inspect_server to populate.",
                        "graph": graph,
                    },
                    indent=2,
                )
            counts = _graph_builder.rebuild_from_db()
            graph = _graph_store.get_full_graph(server_id)
            return json.dumps(
                {
                    "note": "Graph was empty - rebuilt from existing Safety Warden data",
                    "rebuilt": counts,
                    "graph": graph,
                },
                indent=2,
            )

        return json.dumps(graph, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def explain_tool_risk(server_id: str, tool_name: str) -> str:
    """
    Walk the risk graph for a specific tool and return blast radius, risk paths, and recommended action.

    Returns:
      blast_radius: critical | high | medium | low | none
      direct_findings: security scan findings that affect this tool
      composition_risks: dangerous tool combinations (e.g. read + external_post = exfiltration)
      risk_paths: human-readable paths from findings to the tool
      agent_clients: which AI clients have this server configured
      recommended_action: allow | warn | require_approval | block

    BEFORE: get_risk_graph (to ensure graph is populated).
    AFTER: set_tool_policy('block') if recommended_action is 'block'.
    """
    try:
        result = _graph_explain.explain_tool_risk(server_id, tool_name)
        if "error" in result:
            _graph_builder.rebuild_from_db()
            result = _graph_explain.explain_tool_risk(server_id, tool_name)
            if "error" in result:
                result["hint"] = (
                    f"Tool '{tool_name}' may not have been inspected yet. "
                    "Run inspect_server to populate tool data, then retry."
                )
            else:
                result["note"] = "Graph rebuilt from existing data before analysis"
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def export_graph(format: str = "png", server_id: Optional[str] = None, output_path: Optional[str] = None) -> str:
    """
    Export the risk graph in the requested format.

    format: "png" (default) - PNG image rendered via mmdc (requires: npm install -g @mermaid-js/mermaid-cli).
            "mermaid" - Mermaid LR diagram source for pasting into mermaid.live.
            "json" - structured objects and relations list.

    server_id: scope export to one server; omit for full workspace graph.
    output_path: file path for PNG output; defaults to <server_id>_graph.png in the current directory.

    Graph is rebuilt automatically before export.
    """
    try:
        _graph_builder.rebuild_from_db()
        if format == "png":
            path = _graph_explain.export_as_png(server_id, output_path)
            return json.dumps({"format": "png", "path": path}, indent=2)
        if format == "mermaid":
            diagram = _graph_explain.export_as_mermaid(server_id)
            return json.dumps({"format": "mermaid", "diagram": diagram}, indent=2)
        if format != "json":
            return json.dumps(
                {"error": f"Unsupported format {format!r}. Supported: 'png', 'mermaid', 'json'"}, indent=2
            )
        graph = _graph_store.get_full_graph(server_id)
        return json.dumps({"format": "json", **graph}, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def explain_client_risk(client_id: str) -> str:
    """
    Analyze cross-server risks for all MCP servers registered under one agent client.

    Detects risks that are invisible when looking at servers individually:
      cross_server_exfiltration: read tool on server-A + external tool on server-B - data can
        leave the system even if each server individually looks safe.
      tool_shadowing: same tool name on multiple servers - attacker controlling one can intercept
        calls intended for another.
      shared_cve_blast_radius: a single supply-chain CVE affects tools across multiple servers.

    client_id: agent client identifier (e.g. "claude-desktop", "cursor", "vscode").
      Run discover_servers first to populate the client-server linkage, or register_server
      will auto-link stdio servers that match a known config file entry.

    BEFORE: discover_servers or onboard_discovered_servers (to establish client-server links).
    BEFORE: inspect_server for each server (tools must be known for exfil path analysis).
    AFTER: set_tool_policy('block') on any external tools that appear in exfil paths.
    AFTER: security_scan_server on servers with HIGH composite_risk.
    """
    try:
        result = _graph_explain.explain_client_risk(client_id)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def analyze_cve_blast_radius(
    client_id: Optional[str] = None,
    vuln_id: Optional[str] = None,
) -> str:
    """
    Report CVEs that affect multiple servers, showing the blast radius across the client's workspace.

    A single supply-chain vulnerability (e.g. a CVE in the 'requests' library) may be present
    in several MCP servers simultaneously. This tool surfaces those shared exposures so you can
    prioritize patching by blast radius rather than server-by-server.

    client_id: scope to servers under one client; omit to query across all clients.
    vuln_id: filter to a specific CVE / GHSA / vulnerability ID.

    BEFORE: inspect_server for each server (provenance must be built to detect CVEs).
    AFTER: security_scan_server on the affected servers for deeper analysis.
    """
    try:
        cve_nodes = _graph_store.get_objects_by_type("cve_blast_radius")
        if client_id:
            prefix = f"cve_blast::{client_id}::"
            cve_nodes = [n for n in cve_nodes if n["obj_id"].startswith(prefix)]
        if vuln_id:
            cve_nodes = [
                n for n in cve_nodes if n["name"] == vuln_id or n.get("metadata", {}).get("vuln_id") == vuln_id
            ]

        results = []
        for n in cve_nodes:
            meta = n.get("metadata", {})
            results.append(
                {
                    "vuln_id": meta.get("vuln_id", n["name"]),
                    "severity": meta.get("severity", "UNKNOWN"),
                    "affected_servers": meta.get("affected_servers", []),
                    "client_id": meta.get("client_id", ""),
                    "blast_radius": len(meta.get("affected_servers", [])),
                }
            )
        results.sort(
            key=lambda x: ({"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x["severity"], 0), x["blast_radius"]),
            reverse=True,
        )

        if not results:
            hint = (
                "No shared CVEs found. Ensure inspect_server has been run for each server "
                "and provenance detection completed."
            )
            if client_id:
                hint += f" Also confirm '{client_id}' has at least 2 linked servers via discover_servers."
            return json.dumps({"cve_blast_radius": [], "count": 0, "hint": hint}, indent=2)

        return json.dumps({"cve_blast_radius": results, "count": len(results)}, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)
