from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .. import database as _db
from . import store
from ._constants import EXTERNAL_EFFECTS as _EXTERNAL_EFFECTS, READ_EFFECTS as _READ_EFFECTS, RISK_TAG_TO_MITRE as _RISK_TAG_TO_MITRE
from . import provenance as _provenance

_log = logging.getLogger(__name__)

_SEVERITY_SCORES: Dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.0,
    "none": 0.0,
    "unknown": 1.5,
}

_CRED_AMPLIFIER = 0.5
_EXTERNAL_TOOL_AMPLIFIER = 0.3
_COMPOSITION_PAIR_BONUS = 1.5
_MULTI_AGENT_AMPLIFIER = 0.4
_NO_SCAN_CONFIDENCE = 0.7


_OWASP_SHARED_RESOURCE = "ASI07"
_OWASP_UNSCANNED = "ASI03"


@dataclass
class InteractionRisk:
    pattern: str
    agents: List[str]
    risk_score: float
    description: str
    owasp_agentic_tag: str = ""
    mitre_tags: List[str] = field(default_factory=list)
    mitigated: bool = False


def explain_tool_risk(server_id: str, tool_name: str) -> Dict[str, Any]:
    tool_id = f"{server_id}::{tool_name}"
    tool_obj = store.get_object(tool_id)
    if tool_obj is None:
        return {
            "error": f"Tool '{tool_name}' not found in graph. Call get_risk_graph with rebuild=true first."
        }

    tool_meta = tool_obj.get("metadata", {})
    effect_class = tool_meta.get("effect_class", "unknown")
    tool_policy = _db.get_tool_policy(server_id, tool_name)
    scan_exists = _db.get_latest_security_scan(server_id) is not None

    tool_relations = store.get_relations_from(tool_id)

    findings: List[Dict[str, Any]] = []
    for rel in tool_relations:
        if rel["relation"] != "affected_by":
            continue
        fobj = store.get_object(rel["target_id"])
        if not fobj:
            continue
        fmeta = fobj.get("metadata", {})
        risk_tags = fmeta.get("risk_tags", [])
        entry: Dict[str, Any] = {
            "finding": fobj["name"],
            "risk_level": fmeta.get("risk_level"),
            "risk_tags": risk_tags,
            "mitre_techniques": _map_mitre(risk_tags),
            "remediation": fmeta.get("remediation", ""),
            "exploitation_scenario": fmeta.get("exploitation_scenario", ""),
        }
        if fmeta.get("confirmed_by"):
            entry["confirmed_by"] = fmeta["confirmed_by"]
        if fmeta.get("confidence") is not None:
            entry["confidence"] = fmeta["confidence"]
        findings.append(entry)

    has_cred_surface = any(
        r["relation"] == "uses_credential"
        for r in store.get_relations_from(server_id)
    )

    sibling_tools = _load_sibling_tools(server_id)
    external_tool_count = sum(1 for t in sibling_tools if t.get("effect_class") in _EXTERNAL_EFFECTS)

    composition_risks: List[Dict[str, Any]] = []
    if effect_class in _READ_EFFECTS:
        for rel in tool_relations:
            if rel["relation"] != "can_exfiltrate":
                continue
            ext_obj = store.get_object(rel["target_id"])
            if not ext_obj:
                continue
            ext_name = ext_obj["name"]
            ext_policy = _db.get_tool_policy(server_id, ext_name)
            is_mitigated = ext_policy == "block"
            composition_risks.append({
                "read_tool": tool_name,
                "external_tool": ext_name,
                "description": (
                    f"'{tool_name}' (read) + '{ext_name}' (external_action) = "
                    f"potential data exfiltration path"
                ),
                "mitigated": is_mitigated,
                "mitigation_note": f"'{ext_name}' is blocked by policy" if is_mitigated else None,
                "mitre_technique": "T1041",
            })
    elif effect_class in _EXTERNAL_EFFECTS:
        for rel in store.get_relations_to(tool_id):
            if rel["relation"] != "can_exfiltrate":
                continue
            src_obj = store.get_object(rel["source_id"])
            if not src_obj:
                continue
            src_name = src_obj["name"]
            src_policy = _db.get_tool_policy(server_id, src_name)
            is_mitigated = src_policy == "block" or tool_policy == "block"
            if src_policy == "block":
                mitigation_note: Optional[str] = f"'{src_name}' is blocked by policy"
            elif tool_policy == "block":
                mitigation_note = f"'{tool_name}' is blocked by policy"
            else:
                mitigation_note = None
            composition_risks.append({
                "read_tool": src_name,
                "external_tool": tool_name,
                "description": (
                    f"'{src_name}' (read) + '{tool_name}' (external_action) = "
                    f"potential data exfiltration path"
                ),
                "mitigated": is_mitigated,
                "mitigation_note": mitigation_note,
                "mitre_technique": "T1041",
            })

    live_risks = [c for c in composition_risks if not c["mitigated"]]
    mitigated_risks = [c for c in composition_risks if c["mitigated"]]

    agent_clients = _find_agent_clients(server_id)
    max_sev_score = max(
        (_SEVERITY_SCORES.get((f.get("risk_level") or "none").lower(), 0.0) for f in findings),
        default=0.0,
    )
    multi_agent_bonus = max(len(agent_clients) - 1, 0) * _MULTI_AGENT_AMPLIFIER
    composite_raw = (
        max_sev_score
        + (_CRED_AMPLIFIER if has_cred_surface else 0.0)
        + external_tool_count * _EXTERNAL_TOOL_AMPLIFIER
        + len(live_risks) * _COMPOSITION_PAIR_BONUS
        + multi_agent_bonus
    )
    composite_risk_score = round(min(composite_raw, 10.0), 1)
    confidence = round(_NO_SCAN_CONFIDENCE if not scan_exists else 1.0, 2)

    has_critical = any((f.get("risk_level") or "").upper() == "CRITICAL" for f in findings)
    has_high = any((f.get("risk_level") or "").upper() in ("HIGH", "CRITICAL") for f in findings)

    if has_critical or (effect_class in _EXTERNAL_EFFECTS and live_risks and has_cred_surface):
        blast_radius = "critical"
    elif has_high or (effect_class in _EXTERNAL_EFFECTS and (live_risks or has_cred_surface)):
        blast_radius = "high"
    elif live_risks or (findings and effect_class not in _READ_EFFECTS):
        blast_radius = "medium"
    elif findings or (not scan_exists and has_cred_surface):
        blast_radius = "low"
    else:
        blast_radius = "none"

    risk_paths: List[str] = []
    for f in findings:
        sev = f.get("risk_level") or "UNKNOWN"
        mitre = ", ".join(f.get("mitre_techniques", []))
        tags_str = ", ".join(f.get("risk_tags", []))
        path = f"[{sev}] SecurityFinding -> {tool_name}"
        if tags_str:
            path += f" [{tags_str}]"
        if mitre:
            path += f" (MITRE: {mitre})"
        risk_paths.append(path)
    for cr in live_risks:
        risk_paths.append(f"[EXFIL] {cr['description']} (MITRE: T1041)")
    if not scan_exists and has_cred_surface:
        risk_paths.append(
            "[UNSCANNED] Server has credential surfaces but no security scan has been run"
        )

    prov_obj = store.get_object(f"provenance::{server_id}")
    provenance_info: Optional[Dict[str, Any]] = prov_obj.get("metadata") if prov_obj else None

    interaction_risks = _detect_interaction_risks(server_id, agent_clients, scan_exists, sibling_tools, has_cred_surface, provenance_info)

    schema_tampered = any(
        "tool_poisoning" in f.get("risk_tags", [])
        and f.get("finding", "").startswith("schema_tampered")
        for f in findings
    )

    return {
        "server_id": server_id,
        "tool": tool_name,
        "blast_radius": blast_radius,
        "composite_risk_score": composite_risk_score,
        "confidence": confidence,
        "scan_exists": scan_exists,
        "effect_class": effect_class,
        "schema_fingerprint": (tool_meta.get("schema_fingerprint") or "")[:16] or None,
        "schema_tampered": schema_tampered,
        "cve_impacted": tool_meta.get("cve_impacted", False),
        "impacting_cves": tool_meta.get("impacting_cves", []),
        "provenance": provenance_info,
        "direct_findings": findings,
        "composition_risks": composition_risks,
        "live_composition_risks_count": len(live_risks),
        "mitigated_composition_risks_count": len(mitigated_risks),
        "risk_paths": risk_paths,
        "agent_clients": agent_clients,
        "has_credential_surface": has_cred_surface,
        "external_tool_count_on_server": external_tool_count,
        "interaction_risks": [
            {
                "pattern": ir.pattern,
                "agents": ir.agents,
                "risk_score": ir.risk_score,
                "description": ir.description,
                "owasp_agentic_tag": ir.owasp_agentic_tag,
                "mitre_tags": ir.mitre_tags,
                "mitigated": ir.mitigated,
            }
            for ir in interaction_risks
        ],
        "recommended_action": _recommended_action(blast_radius, composite_risk_score, tool_policy),
    }


def _map_mitre(risk_tags: List[str]) -> List[str]:
    seen: List[str] = []
    for tag in risk_tags:
        t = _RISK_TAG_TO_MITRE.get(tag)
        if t and t not in seen:
            seen.append(t)
    return seen


def _load_sibling_tools(server_id: str) -> List[Dict[str, Any]]:
    siblings = []
    for rel in store.get_relations_from(server_id):
        if rel["relation"] != "exposes":
            continue
        tobj = store.get_object(rel["target_id"])
        if tobj and tobj["obj_type"] == "tool":
            siblings.append({**tobj.get("metadata", {}), "name": tobj["name"]})
    return siblings


def _find_agent_clients(server_id: str) -> List[str]:
    clients: List[str] = []
    for rel in store.get_relations_to(server_id):
        if rel["relation"] != "declares":
            continue
        config_obj = store.get_object(rel["source_id"])
        if not config_obj or config_obj["obj_type"] != "mcp_config":
            continue
        for cr in store.get_relations_to(config_obj["obj_id"]):
            if cr["relation"] != "declares":
                continue
            client_obj = store.get_object(cr["source_id"])
            if client_obj and client_obj["obj_type"] == "agent_client":
                if client_obj["name"] not in clients:
                    clients.append(client_obj["name"])
    return clients


def _detect_interaction_risks(
    server_id: str,
    agent_clients: List[str],
    scan_exists: bool,
    sibling_tools: List[Dict[str, Any]],
    has_cred_surface: bool = False,
    prov_info: Optional[Dict[str, Any]] = None,
) -> List[InteractionRisk]:
    risks: List[InteractionRisk] = []

    external_tools = [t["name"] for t in sibling_tools if t.get("effect_class") in _EXTERNAL_EFFECTS]
    read_tools = [t["name"] for t in sibling_tools if t.get("effect_class") in _READ_EFFECTS]

    if len(agent_clients) >= 2:
        risks.append(InteractionRisk(
            pattern="shared_server",
            agents=agent_clients,
            risk_score=round(5.0 + min(len(agent_clients) * _MULTI_AGENT_AMPLIFIER, 2.0), 1),
            description=(
                f"Server '{server_id}' is configured across {len(agent_clients)} agent clients "
                f"({', '.join(agent_clients)}). A compromise affects all of them simultaneously."
            ),
            owasp_agentic_tag=_OWASP_SHARED_RESOURCE,
            mitre_tags=["T1078"],
        ))

    if external_tools and len(agent_clients) >= 2:
        risks.append(InteractionRisk(
            pattern="tool_overlap_execute",
            agents=agent_clients,
            risk_score=round(6.5 + min(len(agent_clients) * _MULTI_AGENT_AMPLIFIER, 2.0), 1),
            description=(
                f"External/destructive tools {external_tools[:3]} on '{server_id}' are "
                f"accessible from {len(agent_clients)} agent clients. Any client can trigger "
                f"side effects that affect the others' shared environment."
            ),
            owasp_agentic_tag=_OWASP_SHARED_RESOURCE,
            mitre_tags=["T1059", "T1041"],
        ))

    if has_cred_surface and not scan_exists:
        risks.append(InteractionRisk(
            pattern="unscanned_credentials",
            agents=agent_clients,
            risk_score=6.0,
            description=(
                f"Server '{server_id}' exposes credential surfaces but has never been "
                f"security-scanned. Credential leak risk is unquantified - no scan does not mean clean."
            ),
            owasp_agentic_tag=_OWASP_UNSCANNED,
            mitre_tags=["T1078"],
        ))

    if read_tools and external_tools:
        unblocked_external = [t for t in external_tools if _db.get_tool_policy(server_id, t) != "block"]
        if unblocked_external:
            client_note = (
                f" Accessible from {len(agent_clients)} agent client(s)." if agent_clients else ""
            )
            risks.append(InteractionRisk(
                pattern="scope_mismatch",
                agents=agent_clients,
                risk_score=5.5,
                description=(
                    f"Server '{server_id}' has {len(read_tools)} read tool(s) and "
                    f"{len(unblocked_external)} unblocked external/destructive tool(s) with no "
                    f"separating policy.{client_note} Set block on {unblocked_external[:3]} to "
                    f"eliminate exfiltration composition paths."
                ),
                owasp_agentic_tag=_OWASP_SHARED_RESOURCE,
                mitre_tags=["T1041"],
            ))
        else:
            risks.append(InteractionRisk(
                pattern="scope_mismatch",
                agents=agent_clients,
                risk_score=1.0,
                description="Server has read and external tools but all external tools are blocked by policy.",
                mitigated=True,
            ))

    if prov_info:
        if store.get_object(f"finding::cert_changed::{server_id}"):
            risks.append(InteractionRisk(
                pattern="cert_changed",
                agents=agent_clients,
                risk_score=8.0,
                description=(
                    f"TLS certificate for '{server_id}' changed since last inspection. "
                    f"Possible MITM, subdomain takeover, or unauthorized operator change."
                ),
                mitre_tags=["T1557", "T1195"],
            ))

        if store.get_object(f"finding::dns_changed::{server_id}"):
            risks.append(InteractionRisk(
                pattern="dns_changed",
                agents=agent_clients,
                risk_score=7.5,
                description=(
                    f"DNS resolution for '{server_id}' changed since last inspection. "
                    f"Possible DNS hijacking or BGP reroute to attacker-controlled infrastructure."
                ),
                mitre_tags=["T1584", "T1195"],
            ))

        private_ips = prov_info.get("private_ips") or []
        if private_ips:
            risks.append(InteractionRisk(
                pattern="private_ip_access",
                agents=agent_clients,
                risk_score=6.5,
                description=(
                    f"Server '{server_id}' resolves to private/internal IPs {private_ips[:3]}. "
                    f"DNS rebinding could redirect agent traffic to internal services."
                ),
                mitre_tags=["T1090", "T1557"],
            ))

        attest = prov_info.get("attestation") or {}
        ecosystem = prov_info.get("ecosystem", "unresolvable")
        if (
            ecosystem not in ("unresolvable", "")
            and attest.get("attestation_status") == "absent"
        ):
            risks.append(InteractionRisk(
                pattern="no_attestation",
                agents=agent_clients,
                risk_score=4.0,
                description=(
                    f"Package '{prov_info.get('package_name')}' ({ecosystem}) has no "
                    f"cryptographic provenance attestation on the registry. "
                    f"Supply chain tampering cannot be ruled out."
                ),
                mitre_tags=["T1195"],
            ))

        squats = prov_info.get("typosquatting_suspects") or []
        if squats:
            risks.append(InteractionRisk(
                pattern="typosquatting_risk",
                agents=agent_clients,
                risk_score=7.0,
                description=(
                    f"Package name '{prov_info.get('package_name')}' is suspiciously similar "
                    f"to known package(s): {squats[:3]}. Possible typosquatting attack."
                ),
                mitre_tags=["T1195", "T1036"],
            ))

        dep_squats = prov_info.get("dependency_typosquatting") or []
        if dep_squats:
            examples = [d["dependency"] for d in dep_squats[:3]]
            risks.append(InteractionRisk(
                pattern="dependency_typosquatting",
                agents=agent_clients,
                risk_score=8.5,
                description=(
                    f"Server '{server_id}' has {len(dep_squats)} dependency name(s) "
                    f"suspiciously similar to well-known packages: {examples}. "
                    f"A typosquatted dependency executes attacker code on install or import."
                ),
                mitre_tags=["T1195", "T1036"],
            ))

        dep_cves = prov_info.get("dependency_cves") or []
        if dep_cves:
            critical = [c for c in dep_cves if c.get("severity") == "CRITICAL"]
            high = [c for c in dep_cves if c.get("severity") == "HIGH"]
            top_score = 9.5 if critical else 8.0
            examples = [f"{c['package']} {c['vuln_id']}" for c in (critical or high)[:3]]
            risks.append(InteractionRisk(
                pattern="known_cves",
                agents=agent_clients,
                risk_score=top_score,
                description=(
                    f"Server '{server_id}' dependencies have {len(critical)} CRITICAL and "
                    f"{len(high)} HIGH CVEs: {examples}. Update affected packages."
                ),
                mitre_tags=["T1190", "T1195"],
            ))

    risks.sort(key=lambda r: r.risk_score, reverse=True)
    return risks


def _recommended_action(
    blast_radius: str, composite_risk_score: float, tool_policy: Optional[str]
) -> str:
    if tool_policy == "block":
        return "block"
    if tool_policy == "allow":
        return "allow"
    if blast_radius == "critical" or composite_risk_score >= 8.0:
        return "block"
    if blast_radius == "high" or composite_risk_score >= 5.0:
        return "require_approval"
    if blast_radius == "medium" or composite_risk_score >= 2.0:
        return "warn"
    return "allow"


def explain_client_risk(client_id: str) -> Dict[str, Any]:
    """Return cross-server risk analysis for all servers registered under a client."""
    server_ids = list(set(_db.get_servers_for_client(client_id)) | set(store.get_servers_by_client(client_id)))
    if not server_ids:
        client_obj = store.get_object(client_id)
        if not client_obj:
            return {"error": f"Client '{client_id}' not found. Run discover_servers or onboard_discovered_servers first."}
        server_ids = []

    if len(server_ids) < 2:
        return {
            "client_id": client_id,
            "server_count": len(server_ids),
            "servers": server_ids,
            "note": (
                "Cross-server analysis requires at least 2 servers under this client. "
                "Single-server risks are in explain_tool_risk."
            ),
        }

    cross_exfil = _find_cross_server_exfiltration(server_ids)
    tool_shadows = _find_tool_shadowing(client_id)
    cve_blast = _aggregate_cves(client_id)

    per_server: Dict[str, Any] = {}
    for sid in server_ids:
        tools = _load_sibling_tools(sid)
        per_server[sid] = {
            "tool_count": len(tools),
            "read_tools": [t["name"] for t in tools if t.get("effect_class") in _READ_EFFECTS],
            "external_tools": [t["name"] for t in tools if t.get("effect_class") in _EXTERNAL_EFFECTS],
        }

    composite_risk = "none"
    if cross_exfil:
        composite_risk = "high"
    if cve_blast:
        composite_risk = "critical" if any(c.get("severity") == "CRITICAL" for c in cve_blast) else "high"
    if tool_shadows:
        if composite_risk == "none":
            composite_risk = "medium"

    return {
        "client_id": client_id,
        "server_count": len(server_ids),
        "servers": per_server,
        "cross_server_exfiltration_paths": cross_exfil,
        "tool_shadowing": tool_shadows,
        "cve_blast_radius": cve_blast,
        "composite_risk": composite_risk,
        "summary": _cross_server_summary(cross_exfil, tool_shadows, cve_blast, server_ids),
    }


def _find_cross_server_exfiltration(server_ids: List[str]) -> List[Dict[str, Any]]:
    """Find cross_server_exfil relations and return as path dicts."""
    paths: List[Dict[str, Any]] = []
    seen: set = set()
    server_id_set = set(server_ids)
    tools_by_server = store.get_tools_for_servers(server_ids)
    for sid, tools in tools_by_server.items():
        for tool in tools:
            tool_id = tool.get("obj_id", "")
            if not tool_id:
                continue
            for rel in store.get_relations_from(tool_id):
                if rel["relation"] != "cross_server_exfil":
                    continue
                key = (rel["source_id"], rel["target_id"])
                if key in seen:
                    continue
                seen.add(key)
                meta = rel.get("metadata", {})
                if meta.get("read_server") not in server_id_set:
                    continue
                paths.append({
                    "read_tool": rel["source_id"],
                    "exfil_tool": rel["target_id"],
                    "read_server": meta.get("read_server", sid),
                    "exfil_server": meta.get("exfil_server", ""),
                    "client_id": meta.get("client_id", ""),
                })
    return paths


def _find_tool_shadowing(client_id: str) -> List[Dict[str, Any]]:
    """Return tool shadowing findings for this client."""
    prefix = f"finding::tool_shadow::{client_id}::"
    results: List[Dict[str, Any]] = []
    for f in store.get_objects_by_type("finding"):
        if not f["obj_id"].startswith(prefix):
            continue
        meta = f.get("metadata", {})
        entry: Dict[str, Any] = {
            "shadow_types": meta.get("shadow_types", ["exact"]),
            "risk_level": meta.get("risk_level", "MEDIUM"),
            "confidence": meta.get("confidence", 0.8),
            "description": meta.get("description", ""),
            "evidence": meta.get("evidence", {}),
        }
        if meta.get("tool_name"):
            entry["tool_name"] = meta["tool_name"]
            entry["shadowed_on_servers"] = meta.get("shadowed_by", [])
        else:
            entry["tool_a"] = meta.get("tool_a", "")
            entry["tool_b"] = meta.get("tool_b", "")
            entry["server_a"] = meta.get("server_a", "")
            entry["server_b"] = meta.get("server_b", "")
        results.append(entry)
    return results


def _aggregate_cves(client_id: str) -> List[Dict[str, Any]]:
    """Return CVE blast-radius nodes affecting multiple servers under this client."""
    prefix = f"cve_blast::{client_id}::"
    results: List[Dict[str, Any]] = []
    for n in store.get_objects_by_type("cve_blast_radius"):
        if not n["obj_id"].startswith(prefix):
            continue
        meta = n.get("metadata", {})
        results.append({
            "vuln_id": meta.get("vuln_id", n["name"]),
            "severity": meta.get("severity", "UNKNOWN"),
            "affected_servers": meta.get("affected_servers", []),
        })
    results.sort(
        key=lambda x: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x.get("severity", ""), 0),
        reverse=True,
    )
    return results


def _cross_server_summary(
    cross_exfil: List[Dict[str, Any]],
    shadows: List[Dict[str, Any]],
    cves: List[Dict[str, Any]],
    server_ids: List[str],
) -> str:
    parts = [f"{len(server_ids)} servers under same client."]
    if cross_exfil:
        parts.append(f"{len(cross_exfil)} cross-server exfiltration path(s) detected.")
    if shadows:
        parts.append(f"{len(shadows)} tool shadowing conflict(s).")
    if cves:
        critical = sum(1 for c in cves if c.get("severity") == "CRITICAL")
        high = sum(1 for c in cves if c.get("severity") == "HIGH")
        parts.append(f"Shared CVEs: {critical} CRITICAL, {high} HIGH affecting multiple servers.")
    if not cross_exfil and not shadows and not cves:
        parts.append("No cross-server risks detected.")
    return " ".join(parts)


def export_as_mermaid(server_id: Optional[str] = None) -> str:
    graph = store.get_full_graph(server_id)

    _SERVER_RISK_STYLES: Dict[str, str] = {
        "HIGH":     "fill:#D0021B,color:#fff",
        "CRITICAL": "fill:#7B0000,color:#fff",
        "MEDIUM":   "fill:#F5A623,color:#fff",
        "LOW":      "fill:#4A90E2,color:#fff",
        "NONE":     "fill:#4A90E2,color:#fff",
    }

    type_styles: Dict[str, str] = {
        "tool": "fill:#7ED321,color:#fff",
        "finding": "fill:#D0021B,color:#fff",
        "agent_client": "fill:#9B59B6,color:#fff",
        "mcp_config": "fill:#F5A623,color:#fff",
        "credential_surface": "fill:#E74C3C,color:#fff",
        "package_provenance": "fill:#27AE60,color:#fff",
        "mitre_technique": "fill:#8E44AD,color:#fff",
        "cve_blast_radius": "fill:#6C3483,color:#fff,stroke:#A569BD,stroke-width:2px",
    }

    rel_labels: Dict[str, str] = {
        "exposes": "exposes",
        "affected_by": "has finding",
        "can_exfiltrate": "exfil risk",
        "cross_server_exfil": "cross-server exfil",
        "declares": "declares",
        "uses_credential": "uses cred",
        "has_provenance": "provenance",
        "depends_on": "depends on",
        "maps_to": "maps to",
        "affected_by_cve": "CVE",
    }

    def _clean(s: str) -> str:
        return s[:30].replace("\n", " ").replace("\r", "").replace('"', "'").replace("[", "(").replace("]", ")").replace("{", "(").replace("}", ")").replace("#", "-").replace("|", "-")

    lines = ["graph LR"]
    node_ids: Dict[str, str] = {}
    for i, obj in enumerate(graph["objects"]):
        nid = f"N{i}"
        node_ids[obj["obj_id"]] = nid
        meta = obj.get("metadata", {})
        label = _clean(obj["name"])
        if obj["obj_type"] == "mcp_server":
            risk = (meta.get("overall_risk_level") or "").upper()
            count = meta.get("finding_count")
            if risk and risk != "NONE":
                label = f"{label} | {risk}"
            if count:
                label = f"{label} | {count} findings"
        elif obj["obj_type"] == "tool" and meta.get("cve_impacted"):
            label = f"{label} impacted"
        elif obj["obj_type"] == "finding":
            confirmed_by = meta.get("confirmed_by")
            confidence = meta.get("confidence")
            if confirmed_by:
                label = f"{label} | {confirmed_by}"
            if confidence is not None:
                label = f"{label} | {confidence:.0%}"
        lines.append(f'    {nid}["{label}"]')

    for obj in graph["objects"]:
        nid = node_ids.get(obj["obj_id"])
        if not nid:
            continue
        if obj["obj_type"] == "mcp_server":
            risk = (obj.get("metadata", {}).get("overall_risk_level") or "NONE").upper()
            style = _SERVER_RISK_STYLES.get(risk, _SERVER_RISK_STYLES["NONE"])
        else:
            style = type_styles.get(obj["obj_type"])
        if style:
            lines.append(f"    style {nid} {style}")

    for rel in graph["relations"]:
        src = node_ids.get(rel["source_id"])
        tgt = node_ids.get(rel["target_id"])
        if src and tgt:
            label = rel_labels.get(rel["relation"], rel["relation"])
            lines.append(f"    {src} -->|{label}| {tgt}")

    return "\n".join(lines)
