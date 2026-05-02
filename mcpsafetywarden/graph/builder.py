import datetime
import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import database as _db
from ..inventory.models import InventoryObject, InventoryRelation
from . import store
from . import provenance as _provenance
from ._constants import READ_EFFECTS as _READ_EFFECTS, EXFILTRATION_EFFECTS as _EXFILTRATION_EFFECTS, RISK_TAG_TO_MITRE as _RISK_TAG_TO_MITRE, MITRE_NAMES as _MITRE_NAMES

_log = logging.getLogger(__name__)

_MIN_NAME_LEN_TYPOSQUAT = 5
_TYPOSQUAT_RATIO_THRESHOLD = 0.85
_TYPOSQUAT_MAX_EDIT_DIST = 2
_DESC_DRIFT_JACCARD_THRESHOLD = 0.25
_DESC_SAME_JACCARD_THRESHOLD = 0.60
_MIN_DESC_TOKENS = 3

_STOPWORDS: frozenset = frozenset({
    "a", "an", "the", "and", "or", "for", "in", "to", "of", "with",
    "from", "by", "is", "it", "its", "that", "this", "be", "are", "as",
})

_ANTONYM_TOKEN_PAIRS: frozenset = frozenset({
    frozenset({"read", "write"}), frozenset({"get", "set"}),
    frozenset({"fetch", "post"}), frozenset({"load", "save"}),
    frozenset({"import", "export"}), frozenset({"pull", "push"}),
    frozenset({"put", "get"}), frozenset({"receive", "send"}),
    frozenset({"download", "upload"}),
    frozenset({"create", "delete"}), frozenset({"create", "destroy"}),
    frozenset({"create", "remove"}), frozenset({"add", "remove"}),
    frozenset({"add", "delete"}), frozenset({"insert", "delete"}),
    frozenset({"build", "destroy"}), frozenset({"spawn", "kill"}),
    frozenset({"allocate", "free"}), frozenset({"register", "deregister"}),
    frozenset({"register", "unregister"}), frozenset({"subscribe", "unsubscribe"}),
    frozenset({"publish", "unpublish"}),
    frozenset({"start", "stop"}), frozenset({"enable", "disable"}),
    frozenset({"activate", "deactivate"}), frozenset({"open", "close"}),
    frozenset({"begin", "end"}), frozenset({"init", "cleanup"}),
    frozenset({"init", "teardown"}), frozenset({"setup", "teardown"}),
    frozenset({"pause", "resume"}), frozenset({"suspend", "resume"}),
    frozenset({"freeze", "unfreeze"}),
    frozenset({"login", "logout"}), frozenset({"signin", "signout"}),
    frozenset({"lock", "unlock"}), frozenset({"block", "unblock"}),
    frozenset({"grant", "revoke"}), frozenset({"allow", "deny"}),
    frozenset({"approve", "reject"}), frozenset({"accept", "decline"}),
    frozenset({"authorize", "unauthorize"}), frozenset({"whitelist", "blacklist"}),
    frozenset({"install", "uninstall"}), frozenset({"mount", "unmount"}),
    frozenset({"attach", "detach"}), frozenset({"connect", "disconnect"}),
    frozenset({"bind", "unbind"}), frozenset({"link", "unlink"}),
    frozenset({"join", "leave"}), frozenset({"enroll", "unenroll"}),
    frozenset({"encode", "decode"}), frozenset({"encrypt", "decrypt"}),
    frozenset({"compress", "decompress"}), frozenset({"pack", "unpack"}),
    frozenset({"serialize", "deserialize"}), frozenset({"marshal", "unmarshal"}),
    frozenset({"zip", "unzip"}),
    frozenset({"backup", "restore"}), frozenset({"archive", "unarchive"}),
    frozenset({"archive", "restore"}), frozenset({"checkpoint", "rollback"}),
    frozenset({"commit", "rollback"}), frozenset({"apply", "revert"}),
    frozenset({"deploy", "rollback"}), frozenset({"promote", "demote"}),
    frozenset({"push", "pop"}), frozenset({"enqueue", "dequeue"}),
    frozenset({"acquire", "release"}),
})

_VERSION_SUFFIX_RE = re.compile(r"[_\-]?v\d+$|[_\-]?(old|new|legacy|deprecated|latest|beta|alpha|preview)$", re.I)
_FORMAT_SUFFIX_RE = re.compile(r"[_\-](json|csv|xml|yaml|toml|txt|html|md|raw|binary|base64)$", re.I)
_BATCH_SUFFIX_RE = re.compile(r"[_\-](async|sync|batch|bulk|single|stream|preview|dry_?run|run)$", re.I)


def _strip_variant_suffixes(name: str) -> str:
    """Strip known non-semantic suffixes so variants aren't flagged as shadows."""
    n = _VERSION_SUFFIX_RE.sub("", name)
    n = _FORMAT_SUFFIX_RE.sub("", n)
    n = _BATCH_SUFFIX_RE.sub("", n)
    return n


def _is_known_variant_pair(name_a: str, name_b: str) -> bool:
    """True if one name is a known variant of the other (version, format, batch suffix, pluralization)."""
    base_a = _strip_variant_suffixes(_normalize_name(name_a))
    base_b = _strip_variant_suffixes(_normalize_name(name_b))
    if base_a == base_b:
        return True

    la, lb = name_a.lower(), name_b.lower()
    shorter, longer = (la, lb) if len(la) <= len(lb) else (lb, la)
    if longer.startswith(shorter + "_") or longer.startswith(shorter + "-"):
        return True
    if longer == shorter + "s" or longer == shorter + "es":
        return True

    tokens_a = _strip_numeric_tokens(_tokenize_name(name_a))
    tokens_b = _strip_numeric_tokens(_tokenize_name(name_b))
    if tokens_a and tokens_b and tokens_a == tokens_b:
        return True

    return False


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    dp = list(range(lb + 1))
    for i in range(1, la + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, lb + 1):
            temp = dp[j]
            dp[j] = prev if a[i - 1] == b[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[lb]


def _name_similarity(a: str, b: str) -> Tuple[float, int]:
    norm_a = _normalize_name(a)
    norm_b = _normalize_name(b)
    dist = _levenshtein_distance(norm_a, norm_b)
    ratio = 1.0 - dist / max(len(norm_a), len(norm_b), 1)
    return ratio, dist


def _tokenize_name(name: str) -> List[str]:
    """Split snake_case, kebab-case, camelCase, and digit boundaries into lowercase tokens."""
    name = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", name)
    name = re.sub(r"([a-zA-Z])(\d)", r"\1_\2", name)
    name = re.sub(r"(\d)([a-zA-Z])", r"\1_\2", name)
    return [t for t in re.split(r"[_\-\s]+", name.lower()) if t]


def _normalize_name(name: str) -> str:
    """Flatten to lowercase with all separators and camelCase boundaries removed."""
    name = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", name)
    return re.sub(r"[_\-\s]", "", name.lower())


_NUMERIC_TOKEN_RE = re.compile(r"^v?\d+$")


def _strip_numeric_tokens(tokens: List[str]) -> List[str]:
    return [t for t in tokens if not _NUMERIC_TOKEN_RE.match(t)]


def _is_antonym_name_pair(name_a: str, name_b: str) -> bool:
    tokens_a = set(_tokenize_name(name_a))
    tokens_b = set(_tokenize_name(name_b))
    for ta in tokens_a:
        for tb in tokens_b:
            if frozenset({ta, tb}) in _ANTONYM_TOKEN_PAIRS:
                return True
    return False


def _desc_tokens(desc: str) -> frozenset:
    words = re.findall(r"\b[a-zA-Z]\w+\b", desc.lower())
    return frozenset(w for w in words if w not in _STOPWORDS and len(w) > 2)


def _desc_jaccard(desc_a: str, desc_b: str) -> Optional[float]:
    ta = _desc_tokens(desc_a or "")
    tb = _desc_tokens(desc_b or "")
    if len(ta) < _MIN_DESC_TOKENS or len(tb) < _MIN_DESC_TOKENS:
        return None
    union = ta | tb
    return len(ta & tb) / len(union) if union else None


def _schema_fingerprint(schema: Any) -> str:
    def _strip(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _strip(v) for k, v in obj.items() if k != "description"}
        if isinstance(obj, list):
            return [_strip(i) for i in obj]
        return obj
    return hashlib.md5(json.dumps(_strip(schema or {}), sort_keys=True).encode()).hexdigest()


def _detect_exact_name_shadows(
    client_id: str,
    server_ids: List[str],
    all_tools: Dict[str, List[Dict[str, Any]]],
) -> None:
    """Flag same-named tools across servers that differ in schema or description."""
    name_to_instances: Dict[str, List[Tuple[str, Dict]]] = {}
    for sid in server_ids:
        for t in all_tools.get(sid, []):
            t_name = t.get("tool_name") or t.get("name", "")
            if t_name:
                name_to_instances.setdefault(t_name, []).append((sid, t))

    for tool_name, instances in name_to_instances.items():
        if len(instances) < 2:
            continue

        fingerprints = {_schema_fingerprint(t.get("schema", {})) for _, t in instances}
        raw_descs = [(sid, (t.get("description") or "").strip()) for sid, t in instances]
        desc_set = {d.lower() for _, d in raw_descs}

        if len(fingerprints) == 1 and len(desc_set) == 1:
            continue

        shadow_types: List[str] = []
        evidence: Dict[str, Any] = {}

        if len(fingerprints) > 1:
            shadow_types.append("schema_drift")
            evidence["schema_fingerprints"] = list(fingerprints)

        if len(desc_set) > 1:
            min_j: Optional[float] = None
            for i in range(len(raw_descs)):
                for j in range(i + 1, len(raw_descs)):
                    score = _desc_jaccard(raw_descs[i][1], raw_descs[j][1])
                    if score is not None:
                        min_j = min(min_j, score) if min_j is not None else score
            if min_j is not None and min_j < _DESC_DRIFT_JACCARD_THRESHOLD:
                shadow_types.append("desc_drift")
                evidence["min_desc_jaccard"] = round(min_j, 3)

        if not shadow_types:
            continue

        both = len(shadow_types) == 2
        risk_level = "HIGH" if both else "MEDIUM"
        confidence = 0.95 if both else 0.85
        sids = [sid for sid, _ in instances]

        finding_id = f"finding::tool_shadow::{client_id}::{tool_name}"
        store.upsert_object(InventoryObject(
            id=finding_id,
            type="finding",
            name=f"tool_shadowing:{tool_name}",
            source="cross_server_analysis",
            metadata={
                "risk_level": risk_level,
                "risk_tags": ["tool_shadowing"],
                "shadow_types": shadow_types,
                "confidence": confidence,
                "shadowed_by": sids,
                "tool_name": tool_name,
                "evidence": evidence,
                "description": (
                    f"Tool '{tool_name}' on {len(sids)} servers diverges in "
                    f"{' and '.join(shadow_types)}. Servers: {sids}. "
                    "An attacker controlling one server can shadow the legitimate tool."
                ),
            },
        ))
        for sid, _ in instances:
            try:
                store.upsert_relation(InventoryRelation(
                    source_id=f"{sid}::{tool_name}",
                    target_id=finding_id,
                    relation="affected_by",
                ))
            except Exception as exc:
                _log.debug("exact shadow relation failed: %s", exc)


def _detect_typosquat_shadows(
    client_id: str,
    server_ids: List[str],
    all_tools: Dict[str, List[Dict[str, Any]]],
) -> None:
    """Flag tools with suspiciously similar names across different servers."""
    tool_list: List[Tuple[str, str, Dict]] = [
        (sid, t.get("tool_name") or t.get("name", ""), t)
        for sid in server_ids
        for t in all_tools.get(sid, [])
        if t.get("tool_name") or t.get("name", "")
    ]

    seen: Set[Tuple] = set()
    for i, (sid_a, name_a, tool_a) in enumerate(tool_list):
        for sid_b, name_b, tool_b in tool_list[i + 1:]:
            if sid_a == sid_b or name_a == name_b:
                continue
            if len(name_a) < _MIN_NAME_LEN_TYPOSQUAT or len(name_b) < _MIN_NAME_LEN_TYPOSQUAT:
                continue

            ratio, dist = _name_similarity(name_a, name_b)
            if ratio < _TYPOSQUAT_RATIO_THRESHOLD or dist > _TYPOSQUAT_MAX_EDIT_DIST:
                continue
            if _is_antonym_name_pair(name_a, name_b):
                continue
            if _is_known_variant_pair(name_a, name_b):
                continue

            j_score = _desc_jaccard(tool_a.get("description", ""), tool_b.get("description", ""))
            if j_score is not None and j_score > _DESC_SAME_JACCARD_THRESHOLD:
                continue

            if _schema_fingerprint(tool_a.get("schema", {})) == _schema_fingerprint(tool_b.get("schema", {})):
                continue

            pair_key = (min(name_a, name_b), max(name_a, name_b), min(sid_a, sid_b), max(sid_a, sid_b))
            if pair_key in seen:
                continue
            seen.add(pair_key)

            finding_id = (
                f"finding::tool_shadow::{client_id}::{min(name_a, name_b)}::{max(name_a, name_b)}"
            )
            store.upsert_object(InventoryObject(
                id=finding_id,
                type="finding",
                name=f"tool_shadowing_typosquat:{name_a}:{name_b}",
                source="cross_server_analysis",
                metadata={
                    "risk_level": "MEDIUM",
                    "risk_tags": ["tool_shadowing", "typosquatting"],
                    "shadow_types": ["typosquat"],
                    "confidence": round(ratio, 3),
                    "tool_a": name_a,
                    "tool_b": name_b,
                    "server_a": sid_a,
                    "server_b": sid_b,
                    "evidence": {"name_similarity": round(ratio, 3), "edit_distance": dist},
                    "description": (
                        f"'{name_a}' on '{sid_a}' is suspiciously similar to '{name_b}' on '{sid_b}' "
                        f"(similarity {ratio:.0%}, edit distance {dist}) with diverging schema/description. "
                        "Possible typosquatting."
                    ),
                },
            ))
            for sid, name in [(sid_a, name_a), (sid_b, name_b)]:
                try:
                    store.upsert_relation(InventoryRelation(
                        source_id=f"{sid}::{name}",
                        target_id=finding_id,
                        relation="affected_by",
                    ))
                except Exception as exc:
                    _log.debug("typosquat relation failed: %s", exc)


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
                "SELECT obj_id FROM inventory_objects WHERE obj_type = 'credential_surface' AND obj_id LIKE ?",
                (cred_prefix + "%",),
            ).fetchall()
            stale_ids = [
                r["obj_id"] for r in existing
                if r["obj_id"] not in current_ids
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


def on_provenance_detected(server_id: str, prov_info: Dict[str, Any]) -> None:
    try:
        prov_id = f"provenance::{server_id}"
        pkg_name = prov_info.get("package_name") or "unresolvable"
        version = prov_info.get("version")
        display_name = f"{pkg_name}@{version}" if version else pkg_name

        existing_obj = store.get_object(prov_id)
        if existing_obj:
            old_meta = existing_obj.get("metadata", {})

            old_cert = old_meta.get("tls_cert_fingerprint")
            new_cert = prov_info.get("tls_cert_fingerprint")
            if old_cert and old_cert != new_cert:
                cert_fid = f"finding::cert_changed::{server_id}"
                store.upsert_object(InventoryObject(
                    id=cert_fid,
                    type="finding",
                    name="tls_cert_changed",
                    source="provenance_detection",
                    metadata={
                        "risk_level": "HIGH",
                        "risk_tags": ["tool_poisoning", "supply_chain"],
                        "old_fingerprint": old_cert[:16],
                        "new_fingerprint": (new_cert or "")[:16] or "none",
                        "remediation": (
                            "TLS certificate changed since last inspection. "
                            "Verify the server is still operated by a trusted party."
                        ),
                        "exploitation_scenario": (
                            "Certificate change may indicate MITM, subdomain takeover, "
                            "or unauthorized operator change."
                        ),
                    },
                ))
                store.upsert_relation(InventoryRelation(
                    source_id=server_id,
                    target_id=cert_fid,
                    relation="affected_by",
                    metadata={"risk_level": "HIGH", "auto_detected": True},
                ))
                _log.warning("tls_cert_changed for %s: %s -> %s", server_id, old_cert[:12], (new_cert or "none")[:12])

            old_ips = set(old_meta.get("resolved_ips") or [])
            new_ips = set(prov_info.get("resolved_ips") or [])
            if old_ips and old_ips != new_ips:
                dns_fid = f"finding::dns_changed::{server_id}"
                store.upsert_object(InventoryObject(
                    id=dns_fid,
                    type="finding",
                    name="dns_resolution_changed",
                    source="provenance_detection",
                    metadata={
                        "risk_level": "HIGH",
                        "risk_tags": ["supply_chain"],
                        "old_ips": sorted(old_ips),
                        "new_ips": sorted(new_ips),
                        "added_ips": sorted(new_ips - old_ips),
                        "removed_ips": sorted(old_ips - new_ips),
                        "remediation": (
                            "DNS resolution changed. Verify this is an expected "
                            "infrastructure change."
                        ),
                        "exploitation_scenario": (
                            "DNS hijacking or BGP reroute could redirect traffic "
                            "to an attacker-controlled server."
                        ),
                    },
                ))
                store.upsert_relation(InventoryRelation(
                    source_id=server_id,
                    target_id=dns_fid,
                    relation="affected_by",
                    metadata={"risk_level": "HIGH", "auto_detected": True},
                ))
                _log.warning("dns_changed for %s: %s -> %s", server_id, sorted(old_ips), sorted(new_ips))

        dep_cves = prov_info.get("dependency_cves") or []
        if dep_cves:
            critical = [c for c in dep_cves if c.get("severity") == "CRITICAL"]
            high = [c for c in dep_cves if c.get("severity") == "HIGH"]
            top_severity = "CRITICAL" if critical else "HIGH"
            examples = [f"{c['package']} ({c['vuln_id']})" for c in (critical or high)[:3]]
            cve_fid = f"finding::dep_cve::{server_id}"
            store.upsert_object(InventoryObject(
                id=cve_fid,
                type="finding",
                name="dependency_cves",
                source="provenance_detection",
                metadata={
                    "risk_level": top_severity,
                    "risk_tags": ["supply_chain"],
                    "cves": dep_cves,
                    "critical_count": len(critical),
                    "high_count": len(high),
                    "remediation": (
                        f"Update affected dependencies: {examples}. "
                        "Run dependency audit and pin to patched versions."
                    ),
                    "exploitation_scenario": (
                        "Known CVEs in dependencies can be exploited through the MCP server "
                        "to compromise the agent or the host system."
                    ),
                },
            ))
            store.upsert_relation(InventoryRelation(
                source_id=server_id,
                target_id=cve_fid,
                relation="affected_by",
                metadata={"risk_level": top_severity, "auto_detected": True},
            ))
            _log.warning("dependency_cves for %s: %d findings", server_id, len(dep_cves))

            impacting_ids = list({c["vuln_id"] for c in dep_cves if c.get("vuln_id")})
            conn = _db.get_connection()
            try:
                tool_rows = conn.execute(
                    "SELECT tool_id FROM tools WHERE server_id = ?", (server_id,)
                ).fetchall()
            finally:
                conn.close()
            for row in tool_rows:
                store.patch_object_metadata(row["tool_id"], {
                    "cve_impacted": True,
                    "impacting_cves": impacting_ids,
                })
        else:
            conn = _db.get_connection()
            try:
                tool_rows = conn.execute(
                    "SELECT tool_id FROM tools WHERE server_id = ?", (server_id,)
                ).fetchall()
            finally:
                conn.close()
            for row in tool_rows:
                store.patch_object_metadata(row["tool_id"], {
                    "cve_impacted": False,
                    "impacting_cves": [],
                })

        dep_squats = prov_info.get("dependency_typosquatting") or []
        if dep_squats:
            dep_fid = f"finding::dep_typosquat::{server_id}"
            store.upsert_object(InventoryObject(
                id=dep_fid,
                type="finding",
                name="dependency_typosquatting",
                source="provenance_detection",
                metadata={
                    "risk_level": "HIGH",
                    "risk_tags": ["supply_chain", "tool_poisoning"],
                    "suspects": dep_squats,
                    "remediation": (
                        "One or more dependencies have names very similar to well-known packages. "
                        "Verify each dependency is the intended package before use."
                    ),
                    "exploitation_scenario": (
                        "A typosquatted dependency executes attacker code on install or import, "
                        "compromising the MCP server and all agents that use it."
                    ),
                },
            ))
            store.upsert_relation(InventoryRelation(
                source_id=server_id,
                target_id=dep_fid,
                relation="affected_by",
                metadata={"risk_level": "HIGH", "auto_detected": True},
            ))
            _log.warning("dependency_typosquatting for %s: %s", server_id, dep_squats[:3])

        private_ips = prov_info.get("private_ips") or []
        if private_ips:
            priv_fid = f"finding::private_ip::{server_id}"
            store.upsert_object(InventoryObject(
                id=priv_fid,
                type="finding",
                name="private_ip_access",
                source="provenance_detection",
                metadata={
                    "risk_level": "MEDIUM",
                    "risk_tags": ["supply_chain"],
                    "private_ips": private_ips,
                    "remediation": (
                        "Server resolves to private/internal IPs. "
                        "Ensure this is expected before use in agent workflows."
                    ),
                    "exploitation_scenario": (
                        "DNS rebinding: a public hostname resolving to internal IPs "
                        "allows SSRF against internal services."
                    ),
                },
            ))
            store.upsert_relation(InventoryRelation(
                source_id=server_id,
                target_id=priv_fid,
                relation="affected_by",
                metadata={"risk_level": "MEDIUM", "auto_detected": True},
            ))

        store.upsert_object(InventoryObject(
            id=prov_id,
            type="package_provenance",
            name=display_name,
            source="provenance_detection",
            metadata={k: v for k, v in prov_info.items() if k != "server_id"},
        ))
        store.upsert_relation(InventoryRelation(
            source_id=server_id,
            target_id=prov_id,
            relation="has_provenance",
        ))
    except Exception as exc:
        _log.debug("graph on_provenance_detected failed for %s: %s", server_id, exc)


def _prune_stale_tool_nodes(server_id: str, current_tool_ids: set) -> None:
    conn = _db.get_connection()
    try:
        rel_rows = conn.execute(
            "SELECT target_id FROM inventory_relations WHERE source_id = ? AND relation = 'exposes'",
            (server_id,),
        ).fetchall()
        stale = [r["target_id"] for r in rel_rows if r["target_id"] not in current_tool_ids]
        if stale:
            ph = ",".join("?" * len(stale))
            conn.execute(
                f"DELETE FROM inventory_relations WHERE source_id IN ({ph}) OR target_id IN ({ph})",
                stale * 2,
            )
            conn.execute(f"DELETE FROM inventory_objects WHERE obj_id IN ({ph})", stale)
            conn.commit()
    finally:
        conn.close()


def on_tools_inspected(
    server_id: str,
    tools: List[Dict[str, Any]],
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> None:
    try:
        for t in tools:
            tool_name = t.get("tool_name") or t.get("name", "")
            if not tool_name:
                continue
            tool_id = f"{server_id}::{tool_name}"

            raw_schema = t.get("schema") or t.get("inputSchema") or {}
            if isinstance(raw_schema, str):
                try:
                    raw_schema = json.loads(raw_schema)
                except (json.JSONDecodeError, TypeError):
                    raw_schema = {}

            description = t.get("description") or ""
            fingerprint = _provenance.compute_tool_fingerprint(tool_name, description, raw_schema)

            existing = store.get_object(tool_id)
            if existing:
                old_fp = existing.get("metadata", {}).get("schema_fingerprint")
                if old_fp and old_fp != fingerprint:
                    tamper_id = f"finding::tamper::{server_id}::{tool_name}"
                    store.upsert_object(InventoryObject(
                        id=tamper_id,
                        type="finding",
                        name=f"schema_tampered: {tool_name}",
                        source="tamper_detection",
                        metadata={
                            "risk_level": "HIGH",
                            "risk_tags": ["tool_poisoning"],
                            "old_fingerprint": old_fp,
                            "new_fingerprint": fingerprint,
                            "remediation": (
                                f"Tool '{tool_name}' schema changed since last inspection. "
                                "Re-run security_scan_server to audit the new definition."
                            ),
                            "exploitation_scenario": (
                                "A compromised or silently-updated package changed this tool's "
                                "name, description, or parameters. An attacker can use this to "
                                "manipulate agent behavior without detection."
                            ),
                        },
                    ))
                    store.upsert_relation(InventoryRelation(
                        source_id=tool_id,
                        target_id=tamper_id,
                        relation="affected_by",
                        metadata={"risk_level": "HIGH", "auto_detected": True},
                    ))
                    _log.warning(
                        "schema_tampered: %s::%s fingerprint %s -> %s",
                        server_id, tool_name, old_fp[:12], fingerprint[:12],
                    )

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
                    "description": description[:200],
                    "schema_fingerprint": fingerprint,
                    "cve_impacted": (existing or {}).get("metadata", {}).get("cve_impacted", False),
                    "impacting_cves": (existing or {}).get("metadata", {}).get("impacting_cves", []),
                },
            ))
            store.upsert_relation(InventoryRelation(
                source_id=server_id,
                target_id=tool_id,
                relation="exposes",
            ))
        _add_composition_edges(server_id, tools, llm_provider, llm_model, llm_api_key)

        current_tool_ids = {
            f"{server_id}::{t.get('tool_name') or t.get('name', '')}"
            for t in tools if t.get("tool_name") or t.get("name")
        }
        _prune_stale_tool_nodes(server_id, current_tool_ids)
    except Exception as exc:
        _log.debug("graph on_tools_inspected failed for %s: %s", server_id, exc)


def on_scan_stored(server_id: str, findings: Dict[str, Any]) -> None:
    try:
        tool_findings = findings.get("tool_findings", [])
        overall_risk = findings.get("overall_risk_level", "NONE")
        scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        store.patch_object_metadata(server_id, {
            "overall_risk_level": overall_risk,
            "finding_count": len(tool_findings),
            "last_scanned_at": scanned_at,
        })

        for finding in tool_findings:
            tool_name = finding.get("name", "")
            if not tool_name:
                continue
            tool_id = f"{server_id}::{tool_name}"
            finding_id = f"finding::{server_id}::{tool_name}"
            risk_tags = finding.get("risk_tags", [])
            mitre_tags = finding.get("mitre_techniques", [])

            raw_basis = finding.get("evidence_basis", "")
            if raw_basis == "observed":
                confirmed_by = "probe"
            elif raw_basis == "static_analysis":
                confirmed_by = "source"
            else:
                confirmed_by = "inferred"

            store.upsert_object(InventoryObject(
                id=finding_id,
                type="finding",
                name=(finding.get("finding") or tool_name)[:120],
                source="security_scan",
                metadata={
                    "risk_level": finding.get("risk_level"),
                    "risk_tags": risk_tags,
                    "exploitation_scenario": (finding.get("exploitation_scenario") or "")[:300],
                    "remediation": (finding.get("remediation") or "")[:300],
                    "confirmed_by": confirmed_by,
                    "confidence": finding.get("confidence"),
                },
            ))
            store.upsert_relation(InventoryRelation(
                source_id=tool_id,
                target_id=finding_id,
                relation="affected_by",
                metadata={"risk_level": finding.get("risk_level")},
            ))

            techniques: List[str] = list(mitre_tags)
            for tag in risk_tags:
                tid = _RISK_TAG_TO_MITRE.get(tag)
                if tid and tid not in techniques:
                    techniques.append(tid)

            for tid in techniques:
                technique_id = f"technique::{tid}"
                store.upsert_object(InventoryObject(
                    id=technique_id,
                    type="mitre_technique",
                    name=_MITRE_NAMES.get(tid, tid),
                    source="security_scan",
                    metadata={"technique_id": tid},
                ))
                store.upsert_relation(InventoryRelation(
                    source_id=finding_id,
                    target_id=technique_id,
                    relation="maps_to",
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


_COMPOSITION_EVAL_PROMPT = """\
You are a security analyst evaluating data exfiltration risks between MCP tools on the same server.

For each (read_tool, external_tool) pair below, decide if the read tool's output could plausibly
contain sensitive data that the external tool could send outside the system.

Be strict: only flag pairs where there is a realistic semantic connection, not just theoretical possibility.

Pairs to evaluate:
{pairs_json}

Return ONLY a JSON array, one entry per pair:
[
  {{
    "read_tool": "<name>",
    "external_tool": "<name>",
    "is_exfil_path": true|false,
    "confidence": 0.0-1.0,
    "reason": "<one sentence>"
  }}
]"""


def _llm_evaluate_composition_pairs(
    pairs: List[Tuple[Dict, Dict]],
    provider: str,
    model_id: Optional[str],
    api_key: Optional[str],
) -> List[Dict[str, Any]]:
    from ..scanner import call_llm
    from ..security_utils import strip_json_fence as _strip_json_fence
    slim = [
        {
            "read_tool": r.get("tool_name") or r.get("name", ""),
            "read_description": (r.get("description") or "")[:150],
            "external_tool": e.get("tool_name") or e.get("name", ""),
            "external_description": (e.get("description") or "")[:150],
        }
        for r, e in pairs
    ]
    prompt = _COMPOSITION_EVAL_PROMPT.format(pairs_json=json.dumps(slim, indent=2))
    try:
        raw = call_llm(provider, model_id, api_key, prompt)
        parsed = json.loads(_strip_json_fence(raw.strip()))
        return parsed if isinstance(parsed, list) else []
    except Exception as exc:
        _log.debug("composition LLM eval failed: %s", exc)
        return []


def _add_composition_edges(
    server_id: str,
    tools: List[Dict[str, Any]],
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> None:
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

    all_pairs = [(r, e) for r in read_tools for e in external_tools]

    if llm_provider:
        evaluated = _llm_evaluate_composition_pairs(all_pairs, llm_provider, llm_model, llm_api_key)
        confirmed = {
            (ev["read_tool"], ev["external_tool"])
            for ev in evaluated
            if ev.get("is_exfil_path")
        }
        confidence_map = {
            (ev["read_tool"], ev["external_tool"]): ev.get("confidence", 1.0)
            for ev in evaluated
        }
    else:
        confirmed = None
        confidence_map = {}

    for r, e in all_pairs:
        r_name = r.get("tool_name") or r.get("name", "")
        e_name = e.get("tool_name") or e.get("name", "")
        if not r_name or not e_name:
            continue
        if confirmed is not None and (r_name, e_name) not in confirmed:
            continue
        try:
            store.upsert_relation(InventoryRelation(
                source_id=f"{server_id}::{r_name}",
                target_id=f"{server_id}::{e_name}",
                relation="can_exfiltrate",
                metadata={
                    "composition": "read+external_action",
                    "llm_evaluated": llm_provider is not None,
                    "confidence": confidence_map.get((r_name, e_name), 1.0),
                },
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
            finding_prefix = f"finding::{server_id}::"
            tamper_prefix = f"finding::tamper::{server_id}::"
            finding_rows = conn.execute(
                "SELECT obj_id FROM inventory_objects WHERE obj_id LIKE ? OR obj_id LIKE ?",
                (finding_prefix + "%", tamper_prefix + "%"),
            ).fetchall()
            finding_ids = [r["obj_id"] for r in finding_rows]

            cred_prefix = f"cred_surface::{server_id}::"
            cred_rows = conn.execute(
                "SELECT obj_id FROM inventory_objects WHERE obj_id LIKE ?",
                (cred_prefix + "%",),
            ).fetchall()
            cred_ids = [r["obj_id"] for r in cred_rows]

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

            prov_id = f"provenance::{server_id}"
            prov_finding_ids = [
                f"finding::cert_changed::{server_id}",
                f"finding::dns_changed::{server_id}",
                f"finding::private_ip::{server_id}",
                f"finding::dep_typosquat::{server_id}",
                f"finding::dep_cve::{server_id}",
            ]
            ids_to_delete = list(
                {server_id, prov_id}
                | set(tool_ids)
                | set(finding_ids)
                | set(prov_finding_ids)
                | set(cred_ids)
                | set(config_ids)
                | set(client_ids)
            )
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

        existing_prov = store.get_object(f"provenance::{sid}")
        if existing_prov:
            prov = existing_prov.get("metadata", {})
        else:
            prov = _provenance.build_provenance_info(
                sid, server.get("command"), server.get("args") or [],
                url=server.get("url"), transport=server.get("transport"),
                github_url=server.get("github_url"),
            )
        on_provenance_detected(sid, prov)

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


def on_cross_server_analysis(client_id: str) -> None:
    """Build cross-server risk edges and findings for all servers under a client."""
    try:
        server_ids = list(set(_db.get_servers_for_client(client_id)) | set(store.get_servers_by_client(client_id)))
        if len(server_ids) < 2:
            return

        conn = _db.get_connection()
        try:
            all_exfil = conn.execute(
                "SELECT source_id, metadata FROM inventory_relations WHERE relation = 'cross_server_exfil'",
            ).fetchall()
            stale_source_ids = list({
                row["source_id"] for row in all_exfil
                if json.loads(row["metadata"] or "{}").get("client_id") == client_id
            })
            if stale_source_ids:
                ph = ",".join("?" * len(stale_source_ids))
                conn.execute(
                    f"DELETE FROM inventory_relations WHERE relation = 'cross_server_exfil' AND source_id IN ({ph})",
                    stale_source_ids,
                )
                conn.commit()
        finally:
            conn.close()

        all_tools = _db.list_tools_multi(server_ids)

        for sid_a in server_ids:
            tools_a = all_tools.get(sid_a, [])
            read_tools_a = [t for t in tools_a if t.get("effect_class") in _READ_EFFECTS]
            if not read_tools_a:
                continue
            for sid_b in server_ids:
                if sid_b == sid_a:
                    continue
                tools_b = all_tools.get(sid_b, [])
                ext_tools_b = [t for t in tools_b if t.get("effect_class") in _EXFILTRATION_EFFECTS]
                for r in read_tools_a:
                    for e in ext_tools_b:
                        r_name = r.get("tool_name") or r.get("name", "")
                        e_name = e.get("tool_name") or e.get("name", "")
                        if not r_name or not e_name:
                            continue
                        try:
                            store.upsert_relation(InventoryRelation(
                                source_id=f"{sid_a}::{r_name}",
                                target_id=f"{sid_b}::{e_name}",
                                relation="cross_server_exfil",
                                metadata={
                                    "client_id": client_id,
                                    "read_server": sid_a,
                                    "exfil_server": sid_b,
                                },
                            ))
                        except Exception as exc:
                            _log.debug("cross_server_exfil edge failed: %s", exc)

        _detect_exact_name_shadows(client_id, server_ids, all_tools)
        _detect_typosquat_shadows(client_id, server_ids, all_tools)
        _build_cross_server_cve_nodes(client_id, server_ids)

    except Exception as exc:
        _log.debug("on_cross_server_analysis failed for %s: %s", client_id, exc)


def _build_cross_server_cve_nodes(client_id: str, server_ids: List[str]) -> None:
    """Create shared CVE blast-radius nodes when the same CVE affects multiple servers."""
    try:
        cve_to_servers: Dict[str, List[Tuple[str, str]]] = {}
        for sid in server_ids:
            prov = store.get_object(f"provenance::{sid}")
            if not prov:
                continue
            dep_cves = prov.get("metadata", {}).get("dependency_cves") or []
            for cve in dep_cves:
                vid = cve.get("vuln_id") or cve.get("cve_id") or ""
                if vid:
                    cve_to_servers.setdefault(vid, []).append((sid, cve.get("severity", "UNKNOWN")))

        for vuln_id, affected in cve_to_servers.items():
            unique_servers = list({s for s, _ in affected})
            if len(unique_servers) < 2:
                continue
            severities = [sev for _, sev in affected]
            top_severity = "CRITICAL" if "CRITICAL" in severities else "HIGH" if "HIGH" in severities else "MEDIUM"
            cve_node_id = f"cve_blast::{client_id}::{vuln_id}"
            store.upsert_object(InventoryObject(
                id=cve_node_id,
                type="cve_blast_radius",
                name=vuln_id,
                source="cross_server_analysis",
                metadata={
                    "vuln_id": vuln_id,
                    "severity": top_severity,
                    "affected_servers": unique_servers,
                    "client_id": client_id,
                },
            ))
            for sid in unique_servers:
                try:
                    store.upsert_relation(InventoryRelation(
                        source_id=sid,
                        target_id=cve_node_id,
                        relation="affected_by_cve",
                    ))
                except Exception as exc:
                    _log.debug("affected_by_cve relation failed: %s", exc)
    except Exception as exc:
        _log.debug("_build_cross_server_cve_nodes failed for %s: %s", client_id, exc)
