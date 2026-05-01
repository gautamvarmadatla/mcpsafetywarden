from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .. import database as _db
from . import store
from ._constants import EXTERNAL_EFFECTS as _EXTERNAL_EFFECTS, READ_EFFECTS as _READ_EFFECTS

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

_RISK_TAG_TO_MITRE: Dict[str, str] = {
    "credential_exposure": "T1078",
    "arbitrary_exec": "T1059",
    "data_exfiltration": "T1041",
    "lateral_movement": "T1570",
    "prompt_injection": "T1190",
    "privilege_escalation": "T1068",
    "tool_poisoning": "T1195",
    "tool_shadowing": "T1036",
    "filesystem_access": "T1005",
}

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
        findings.append({
            "finding": fobj["name"],
            "risk_level": fmeta.get("risk_level"),
            "risk_tags": risk_tags,
            "mitre_techniques": _map_mitre(risk_tags),
            "remediation": fmeta.get("remediation", ""),
            "exploitation_scenario": fmeta.get("exploitation_scenario", ""),
        })

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

    interaction_risks = _detect_interaction_risks(server_id, agent_clients, scan_exists, sibling_tools, has_cred_surface)

    return {
        "server_id": server_id,
        "tool": tool_name,
        "blast_radius": blast_radius,
        "composite_risk_score": composite_risk_score,
        "confidence": confidence,
        "scan_exists": scan_exists,
        "effect_class": effect_class,
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


def export_as_mermaid(server_id: Optional[str] = None) -> str:
    graph = store.get_full_graph(server_id)

    type_styles: Dict[str, str] = {
        "mcp_server": "fill:#4A90E2,color:#fff",
        "tool": "fill:#7ED321,color:#fff",
        "finding": "fill:#D0021B,color:#fff",
        "agent_client": "fill:#9B59B6,color:#fff",
        "mcp_config": "fill:#F5A623,color:#fff",
        "credential_surface": "fill:#E74C3C,color:#fff",
    }

    rel_labels: Dict[str, str] = {
        "exposes": "exposes",
        "affected_by": "has finding",
        "can_exfiltrate": "exfil risk",
        "declares": "declares",
        "uses_credential": "uses cred",
        "depends_on": "depends on",
    }

    lines = ["graph LR"]
    node_ids: Dict[str, str] = {}
    for i, obj in enumerate(graph["objects"]):
        nid = f"N{i}"
        node_ids[obj["obj_id"]] = nid
        label = obj["name"][:30].replace("\n", " ").replace("\r", "").replace('"', "'").replace("[", "(").replace("]", ")").replace("#", "-").replace("|", "-")
        lines.append(f'    {nid}["{label}"]')

    for obj in graph["objects"]:
        style = type_styles.get(obj["obj_type"])
        if style:
            nid = node_ids.get(obj["obj_id"])
            if nid:
                lines.append(f"    style {nid} {style}")

    for rel in graph["relations"]:
        src = node_ids.get(rel["source_id"])
        tgt = node_ids.get(rel["target_id"])
        if src and tgt:
            label = rel_labels.get(rel["relation"], rel["relation"])
            lines.append(f"    {src} -->|{label}| {tgt}")

    return "\n".join(lines)
