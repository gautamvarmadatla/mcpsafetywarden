"""
Tool behaviour classifier.

Two paths:
    1. Rule-based (default) - fast, zero API calls, covers ~95% of well-named tools.
  2. LLM agent (optional)  - pass llm_provider to classify_tool(); uses a comprehensive
     prompt that covers every edge case and falls back to rule-based on failure.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

from .security_utils import sanitise_for_prompt as _sanitise_for_prompt, strip_json_fence as _strip_json_fence


def _sanitise_annotations(annotations: Dict[str, Any]) -> Dict[str, Any]:
    """Strip injection-risk text from annotation values before embedding in an LLM prompt."""
    if not isinstance(annotations, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, v in annotations.items():
        if isinstance(v, str):
            out[k] = _sanitise_for_prompt(v, 200)
        elif isinstance(v, (bool, int, float)):
            out[k] = v
        # drop nested dicts/lists - MCP annotations should be simple scalars
    return out


def _sanitise_schema(schema: Dict[str, Any], _depth: int = 0) -> Dict[str, Any]:
    """Recursively sanitize schema `description` fields before embedding in an LLM prompt."""
    if _depth > 8 or not isinstance(schema, dict):
        return schema
    out: Dict[str, Any] = {}
    for k, v in schema.items():
        if k == "description" and isinstance(v, str):
            out[k] = _sanitise_for_prompt(v, 300)
        elif isinstance(v, dict):
            out[k] = _sanitise_schema(v, _depth + 1)
        elif isinstance(v, list):
            out[k] = [_sanitise_schema(i, _depth + 1) if isinstance(i, dict) else i for i in v]
        else:
            out[k] = v
    return out


EFFECT_PATTERNS: List[Tuple[str, List[str]]] = [
    ("read_only", [
        r"^(get|list|read|search|find|fetch|retrieve|describe|show|view|check|"
        r"query|inspect|look|scan|peek|watch|monitor|explain|analyze|analyse|"
        r"audit|count|stat|stats|summarize|summarise|report|preview|diff|compare|"
        r"validate|verify|ping|test|probe|resolve|lookup|whoami|status|health|"
        r"info|information|details|detail|profile|dump|export|download|pull|"
        r"load|read|parse|decode|detect|identify|classify|estimate|forecast|"
        r"predict|evaluate|assess|review|trace|log|history|tail|head|cat|"
        r"ls|dir|tree|walk|glob|match|filter|sort|rank|score|measure|calc|"
        r"calculate|compute|hash|checksum|lint|format|render|convert|translate|"
        r"encode|sign|verify|token|jwt|decode)",
        r"_(get|list|read|search|find|fetch|retrieve|describe|show|view|check|"
        r"query|inspect|scan|count|stat|status|health|info|details|preview|"
        r"diff|compare|validate|verify|resolve|lookup|export|download|report|"
        r"analyze|analyse|audit|estimate|evaluate|assess|trace|history)$",
        r"^(is_|has_|can_|should_|was_|did_|does_|will_)",
    ]),
    ("additive_write", [
        r"^(create|add|insert|append|push|upload|new|make|build|generate|write|"
        r"save|store|put|register|import|open|begin|start|init|initiate|launch|"
        r"spawn|fork|clone|copy|duplicate|snapshot|backup|seed|provision|allocate|"
        r"reserve|claim|acquire|lock|checkout|subscribe|enroll|join|enqueue|"
        r"post|draft|compose|record|log|track|tag|label|annotate|bookmark|"
        r"pin|star|follow|like|vote|comment|reply|submit|propose|request|"
        r"apply|install|deploy|release|publish|promote|activate|enable)",
        r"_(create|add|insert|append|push|upload|write|save|store|register|"
        r"import|init|launch|spawn|clone|copy|duplicate|snapshot|backup|seed|"
        r"provision|subscribe|enroll|join|enqueue|draft|record|log|track|"
        r"tag|label|annotate|install|deploy|release|publish|activate|enable)$",
    ]),
    ("mutating_write", [
        r"^(update|edit|set|modify|change|patch|rename|move|replace|alter|"
        r"transform|enable|disable|toggle|configure|assign|link|attach|merge|"
        r"reorder|sort|mark|flag|archive|hide|show|pin|unpin|mute|unmute|"
        r"suspend|resume|pause|unpause|lock|unlock|block|unblock|approve|"
        r"reject|accept|decline|promote|demote|grant|revoke|rotate|refresh|"
        r"invalidate|expire|extend|resize|scale|migrate|sync|reconcile|"
        r"reindex|rebuild|reprocess|retry|requeue|replay|redo|repair|fix|"
        r"heal|recover|restore|rollback|revert|undo|reset|clear|flush|"
        r"drain|prune|trim|compact|optimize|vacuum|rebalance|redistribute)",
        r"_(update|edit|set|modify|change|patch|rename|move|replace|alter|"
        r"configure|assign|toggle|lock|unlock|block|unblock|approve|reject|"
        r"grant|revoke|rotate|refresh|resize|scale|migrate|sync|restore|"
        r"rollback|revert|reset|clear|flush|prune|trim|optimize)$",
    ]),
    ("destructive", [
        r"^(delete|remove|drop|purge|erase|destroy|truncate|kill|terminate|"
        r"wipe|shred|nuke|obliterate|unlink|detach|uninstall|deregister|"
        r"deactivate|deprecate|retire|decommission|evict|expel|ban|revoke|"
        r"cancel|abort|stop|shutdown|poweroff|halt|suspend|freeze|"
        r"close|disconnect|end|finish|complete|expire|invalidate|"
        r"overwrite|clobber|squash|force|hard_reset|factory_reset)",
        r"_(delete|remove|drop|purge|erase|destroy|truncate|kill|terminate|"
        r"wipe|unlink|detach|uninstall|deregister|deactivate|retire|"
        r"evict|ban|cancel|abort|stop|shutdown|halt|close|disconnect|"
        r"expire|invalidate|overwrite|force_delete|hard_delete|bulk_delete)$",
    ]),
    ("external_action", [
        r"^(send|post|publish|notify|emit|broadcast|submit|trigger|invoke|"
        r"call|email|message|sms|mms|whatsapp|slack|teams|webhook|ping|"
        r"alert|request|dispatch|relay|forward|share|transfer|pay|charge|"
        r"book|schedule|enqueue|push_notification|pagerduty|opsgenie|"
        r"twilio|sendgrid|mailgun|ses|sns|pubsub|kafka|rabbitmq|"
        r"execute|run|eval|exec|shell|bash|python|node|script|"
        r"curl|http|fetch_url|open_browser|browse|navigate|click|"
        r"login|authenticate|oauth|saml|ldap|ssh|rdp|telnet|ftp|sftp)",
        r"_(send|post|publish|notify|emit|broadcast|submit|trigger|invoke|"
        r"email|message|sms|webhook|alert|dispatch|pay|charge|"
        r"execute|run|eval|exec|shell|script|call|request|forward|relay)$",
    ]),
]

_EFFECT_PATTERNS_COMPILED: List[Tuple[str, List[re.Pattern]]] = [
    (effect, [re.compile(p, re.IGNORECASE) for p in patterns])
    for effect, patterns in EFFECT_PATTERNS
]

_EXEC_PREFIX_RE = re.compile(r"^(sudo|root|elevated|admin|privileged)_", re.IGNORECASE)
_DESTRUCTIVE_PREFIX_RE = re.compile(r"^(kill|nuke|wipe|purge|drop|destroy|terminate|erase|delete|remove)_", re.IGNORECASE)

DESTRUCTIVENESS_MAP = {
    "read_only": "none",
    "additive_write": "low",
    "mutating_write": "medium",
    "external_action": "medium",
    "destructive": "high",
    "unknown": "unknown",
}

RETRY_SAFE_EFFECTS   = {"read_only"}
RETRY_UNSAFE_EFFECTS = {"external_action", "additive_write"}


_DESC_EFFECT_SIGNALS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"\b(read[s]?|retriev|fetch|list[s]?|search|query|queries|look.?up|find[s]?|get[s]?|show[s]?|view[s]?|describe[s]?|inspect[s]?|check[s]?|monitor[s]?|watch[es]?|scan[s]?|report[s]?|stat[s]?|count[s]?|summarize[s]?|display[s]?)\b", re.IGNORECASE), "read_only", 0.45),
    (re.compile(r"\b(creat|add[s]?|insert[s]?|append[s]?|upload[s]?|generat|build[s]?|spawn[s]?|provision[s]?|register[s]?|save[s]?|store[s]?|record[s]?|log[s]?|track[s]?)\b", re.IGNORECASE), "additive_write", 0.45),
    (re.compile(r"\b(updat|edit[s]?|modif|patch[es]?|replac|renam|mov[es]?|configur|toggl|assign[s]?|sync[s]?|migrat|restor|rollback|revert|reset[s]?|clear[s]?|flush[es]?|purge[s]?)\b", re.IGNORECASE), "mutating_write", 0.45),
    (re.compile(r"\b(delet|remov|drop[s]?|purg[es]?|eras[es]?|destroy[s]?|terminat|kill[s]?|wip[es]?|unlink[s]?|shutdown[s]?|expir[es]?|invalidat)\b", re.IGNORECASE), "destructive", 0.50),
    (re.compile(r"\b(send[s]?|email[s]?|notif|messag|sms|webhook[s]?|post[s]?|publish[es]?|broadcast[s]?|dispatch[es]?|trigger[s]?|execut|run[s]?|deploy[s]?|call[s]?|pay[s]?|charg[es]?|alert[s]?|ping[s]?)\b", re.IGNORECASE), "external_action", 0.50),
]

_DESC_OPEN_WORLD_SIGNALS = re.compile(
    r"\b(internet|external|third.?party|outbound|remote|cloud|api|webhook|"
    r"http[s]?|network|public|online|web|url|endpoint|service|integration|"
    r"send[s]? (to|data)|upload[s]? (to|data)|forward[s]? (to|data)|"
    r"notify|alert|email|sms|slack|teams|pagerduty|twilio)\b",
    re.IGNORECASE,
)

_DESC_CREDENTIAL_SIGNALS = re.compile(
    r"\b(password[s]?|secret[s]?|token[s]?|api.?key[s]?|credential[s]?|"
    r"auth|oauth|bearer|private.?key|pem|certificate|cert|ssh.?key|"
    r"access.?key|signing.?key|encryption.?key|passphrase|pin)\b",
    re.IGNORECASE,
)

_DESC_EXEC_SIGNALS = re.compile(
    r"\b(execut[es]?|run[s]?|eval[s]?|shell|bash|sh\b|zsh|powershell|cmd|"
    r"subprocess|spawn|command|script[s]?|binary|binaries|arbitrary|"
    r"code.?(execution|run)|run.?code|interpret)\b",
    re.IGNORECASE,
)

_DESC_FILESYSTEM_SIGNALS = re.compile(
    r"\b(file[s]?|director(y|ies)|path[s]?|folder[s]?|disk|filesystem|"
    r"read.?file|write.?file|delete.?file|list.?file|upload.?file|"
    r"download.?file|\.\.\/|\/etc\/|\/home\/|\.ssh|\.pem|\.env)\b",
    re.IGNORECASE,
)

_SCHEMA_SIGNALS: List[Tuple[re.Pattern, str, float, str]] = [
    (re.compile(r"^(recipient|to|email|phone|mobile|sms_to|channel|topic|webhook_url|slack_channel|teams_channel)$", re.IGNORECASE), "external_action", 0.82, "schema_has_recipient_field"),
    (re.compile(r"^(subject|body|content|message|text|payload|html|template|attachment)$",                           re.IGNORECASE), "external_action", 0.55, "schema_has_message_body_field"),
    (re.compile(r"^(command|cmd|shell|bash|script|code|eval|expression|statement|program|binary|executable|args|arguments|argv)$", re.IGNORECASE), "external_action", 0.88, "schema_has_execution_field"),
    (re.compile(r"^(password|passwd|secret|token|api_key|apikey|access_key|private_key|pem|cert|certificate|passphrase|credential|auth_token|bearer|signing_key|encryption_key|ssh_key)$", re.IGNORECASE), "read_only", 0.60, "schema_has_credential_field"),
    (re.compile(r"^(path|file_path|filepath|filename|file|directory|dir|dest|destination|target_path|output_path)$", re.IGNORECASE), "additive_write", 0.55, "schema_has_file_path"),
    (re.compile(r"^(overwrite|force|replace|truncate|clobber|mode|flags)$",                                           re.IGNORECASE), "mutating_write", 0.70, "schema_has_overwrite_flag"),
    (re.compile(r"^(table|collection|index|database|db|keyspace|namespace|schema)$",                                  re.IGNORECASE), "mutating_write", 0.58, "schema_has_db_target"),
    (re.compile(r"^(cascade|recursive|hard_delete|permanent|purge_all|wipe|drop_table|force_delete)$",                re.IGNORECASE), "destructive",    0.85, "schema_has_destructive_flag"),
    (re.compile(r"^(host|hostname|ip|ip_address|port|endpoint|url|base_url|server|remote|ssh_host|rdp_host)$",        re.IGNORECASE), "external_action", 0.72, "schema_has_network_target"),
    (re.compile(r"^(role|permission|policy|acl|scope|grant|privilege|access_level|user_role|group)$",                 re.IGNORECASE), "mutating_write", 0.68, "schema_has_permission_field"),
    (re.compile(r"^(query|filter|search|q|keyword|term|expression|pattern|regex|selector|xpath|jq)$",                re.IGNORECASE), "read_only", 0.65, "schema_has_query_field"),
    (re.compile(r"^(page|limit|offset|cursor|per_page|page_size|max_results|count|skip|from|size)$",                 re.IGNORECASE), "read_only", 0.60, "schema_has_pagination_field"),
    (re.compile(r"^(cron|schedule|interval|delay|at|run_at|trigger_at|timeout|ttl|retry_count|retry_policy)$",       re.IGNORECASE), "external_action", 0.62, "schema_has_scheduling_field"),
    (re.compile(r"^(amount|price|cost|charge|fee|currency|payment_method|card|stripe_token|billing)$",               re.IGNORECASE), "external_action", 0.80, "schema_has_financial_field"),
]

_OUTPUT_RISK_SIGNALS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"\b(binary|blob|bytes|raw|base64|file_content|attachment|image|video|audio|stream)\b", re.I), "high",   "output_may_be_binary_blob"),
    (re.compile(r"\b(password|secret|token|api.?key|credential|private.?key|pem|cert|ssh)\b",           re.I), "high",   "output_may_contain_credentials"),
    (re.compile(r"\b(env|environment|environ|process\.env|os\.environ|dotenv|\.env)\b",                  re.I), "high",   "output_may_expose_env_vars"),
    (re.compile(r"\b(list|array|items|results|rows|records|entries|nodes|edges|all_)\b",                  re.I), "medium", "output_is_list_or_collection"),
    (re.compile(r"\b(file|directory|path|filesystem|disk|storage)\b",                                     re.I), "medium", "output_contains_filesystem_data"),
    (re.compile(r"\b(log[s]?|trace|debug|stack.?trace|error.?detail|diagnostic)\b",                       re.I), "medium", "output_contains_log_data"),
]


def _classify_by_name(tool_name: str) -> Tuple[str, float, List[str]]:
    lower = tool_name.lower()
    if _EXEC_PREFIX_RE.match(lower):
        return "external_action", 0.70, ["name_has_privileged_exec_prefix"]
    if _DESTRUCTIVE_PREFIX_RE.match(lower):
        return "destructive", 0.70, ["name_has_destructive_prefix"]
    for effect_class, patterns in _EFFECT_PATTERNS_COMPILED:
        for rx in patterns:
            if rx.search(lower): return effect_class, 0.65, [f"name_matches_{effect_class}_pattern"]
    return "unknown", 0.30, ["no_name_pattern_matched"]


def _classify_by_description(description: str) -> Tuple[str, float, List[str]]:
    if not description:
        return "unknown", 0.0, []

    votes: Dict[str, float] = {}
    evidence: List[str] = []

    for pattern, effect, conf in _DESC_EFFECT_SIGNALS:
            if pattern.search(description):
                votes[effect] = votes.get(effect, 0.0) + conf
                evidence.append(f"description_signals_{effect}")

    if not votes: return "unknown", 0.0, ["no_description_signals"]

    best_effect = max(votes, key=votes.__getitem__)
    raw_conf    = min(0.72, votes[best_effect])
    return best_effect, raw_conf, list(dict.fromkeys(evidence))


def _classify_by_schema(schema: Dict[str, Any]) -> Tuple[str, float, List[str]]:
    props = schema.get("properties", {})
    if not props: return "unknown", 0.30, ["no_schema_properties"]

    param_names = {k.lower() for k in props}
    hints: List[Tuple[str, float, str]] = []

    for rx, effect, conf, label in _SCHEMA_SIGNALS:
        if any(rx.match(p) for p in param_names): hints.append((effect, conf, label))

    # Compound boost: message body + recipient = strong external_action signal
    body_fields = {"body", "content", "message", "text", "payload", "html", "template"}
    recv_fields = {"recipient", "to", "email", "channel", "topic", "webhook_url", "slack_channel"}
    if body_fields & param_names and recv_fields & param_names: hints.append(("external_action", 0.90, "schema_body_plus_recipient_compound"))

    # Execution compound: command/script + optional args = very high confidence
    exec_fields = {"command", "cmd", "shell", "script", "code", "eval", "executable"}
    if exec_fields & param_names: hints.append(("external_action", 0.92, "schema_execution_compound"))

    # Destructive compound: target path + overwrite/force
    if {"path", "file_path", "filepath", "filename"} & param_names:
        if {"overwrite", "force", "truncate", "replace", "clobber"} & param_names: hints.append(("destructive", 0.78, "schema_path_plus_overwrite_compound"))

    if not hints: return "unknown", 0.30, ["no_schema_pattern_matched"]

    votes: Dict[str, float] = {}
    evidence: List[str] = []
    for effect, conf, label in hints:
        votes[effect] = votes.get(effect, 0.0) + conf
        evidence.append(label)

    best = max(votes, key=votes.__getitem__)
    return best, min(0.92, votes[best]), evidence


def _infer_output_risk(schema: Dict[str, Any], description: str, effect_class: str) -> Tuple[str, List[str]]:
    combined = (str(schema) + " " + description).lower()
    evidence: List[str] = []

    for rx, level, label in _OUTPUT_RISK_SIGNALS:
        if rx.search(combined):
            if level == "high":
                evidence.append(label)
                return "high", evidence
            evidence.append(label)

    if evidence: return "medium", evidence

    if effect_class == "read_only": return "low", ["read_only_low_output_risk"]

    return "low", ["no_output_risk_signals"]


def _infer_open_world(description: str, schema: Dict[str, Any], effect_class: str) -> Tuple[bool, List[str]]:
    evidence: List[str] = []
    combined = description + " " + str(schema)

    if _DESC_OPEN_WORLD_SIGNALS.search(combined): evidence.append("open_world_external_signal_in_description_or_schema")

    schema_props = {k.lower() for k in schema.get("properties", {})}
    network_params = {"url", "host", "hostname", "ip", "ip_address", "port", "endpoint", "base_url", "webhook_url", "remote", "ssh_host"}
    if network_params & schema_props: evidence.append("schema_has_network_target_param")

    if effect_class == "external_action": evidence.append("effect_class_is_external_action")

    return bool(evidence), evidence


def _infer_extra_risks(description: str, schema: Dict[str, Any]) -> Dict[str, Any]:
    """Surface secondary risk signals: credential access, arbitrary exec, filesystem breadth."""
    combined = description + " " + str(schema)
    risks: Dict[str, Any] = {}

    if _DESC_CREDENTIAL_SIGNALS.search(combined): risks["credential_access_risk"] = True

    if _DESC_EXEC_SIGNALS.search(combined): risks["arbitrary_execution_risk"] = True

    if _DESC_FILESYSTEM_SIGNALS.search(combined): risks["filesystem_access_risk"] = True

    return risks


def _classify_by_annotations(annotations: Dict[str, Any]) -> Tuple[Optional[str], float, Optional[bool], Optional[bool], List[str]]:
    """Returns (effect, conf, open_world, retry_safe_hint, evidence)."""
    evidence: List[str] = []
    effect: Optional[str]   = None
    conf: float           = 0.0
    open_world: Optional[bool] = None
    retry_hint: Optional[bool] = None

    if annotations.get("readOnlyHint") is True:
        effect, conf = "read_only", 0.82
        evidence.append("annotation_readOnlyHint=true")
    elif annotations.get("destructiveHint") is True:
        effect, conf = "destructive", 0.82
        evidence.append("annotation_destructiveHint=true")
    elif annotations.get("readOnlyHint") is False:
        effect, conf = "mutating_write", 0.40
        evidence.append("annotation_readOnlyHint=false")

    if annotations.get("idempotentHint") is True:
        retry_hint = True
        evidence.append("annotation_idempotentHint=true")
    elif annotations.get("idempotentHint") is False:
        retry_hint = False
        evidence.append("annotation_idempotentHint=false")

    if annotations.get("openWorldHint") is not None:
        open_world = bool(annotations["openWorldHint"])
        evidence.append(f"annotation_openWorldHint={open_world}")

    return effect, conf, open_world, retry_hint, evidence


_LLM_CLASSIFY_PROMPT = """\
Classify the MCP tool described below for behavioral effect and security posture.
All claims must be traceable to specific signals in the provided name, description, schema, or annotations.

TOOL INFORMATION
================
Name: {tool_name}
Description: {description}
Input schema (JSON Schema): {schema_json}
MCP annotations: {annotations_json}

MISSING DATA POLICY
====================
- If description is absent or uninformative, base classification on name and schema only.
  Set evidence_basis to "name_only" or "schema" accordingly.
- If schema has no properties, treat the parameter surface as unconstrained.
- If all inputs are absent or uninformative, set effect_class to "unknown",
  all confidence values to 0.0, and do not guess.

OUTPUT FORMAT
=============
Return ONLY valid JSON. No markdown. No text outside the JSON object.

{{
  "effect_class": "<read_only|additive_write|mutating_write|destructive|external_action|unknown>",
  "retry_safety": "<safe|unsafe|caution>",
  "destructiveness": "<none|low|medium|high|unknown>",
  "open_world": <true|false>,
  "output_risk": "<low|medium|high>",
  "reversible": <true|false|null>,
  "credential_access_risk": <true|false>,
  "arbitrary_execution_risk": <true|false>,
  "filesystem_access_risk": <true|false>,
  "prompt_injection_surface": <true|false>,
  "lateral_movement_risk": <true|false>,
  "privilege_escalation_risk": <true|false>,
  "data_exfiltration_risk": <true|false>,
  "risk_level": "<HIGH|MEDIUM|LOW|NONE>",
  "risk_tags": ["<tag>"],
  "exploitation_scenario": "<null if risk_level is NONE; otherwise 1-2 sentences grounded in observed signals>",
  "remediation": "<null if risk_level is NONE; otherwise specific mitigation>",
  "evidence_basis": "<name_only|description|schema|combined>",
  "evidence": ["<specific signal: parameter name, name pattern, description phrase, or annotation value>"],
  "confidence": {{
    "effect_class": <0.0-1.0>,
    "risk_level": <0.0-1.0>,
    "retry_safety": <0.0-1.0>,
    "destructiveness": <0.0-1.0>
  }}
}}

CLASSIFICATION RULES
====================

effect_class - use the highest-impact class that applies:
  read_only       - queries or reads data only; no state changed anywhere
  additive_write  - creates new records or resources; existing state untouched
  mutating_write  - modifies existing data; data preserved but changed
  destructive     - permanently deletes, purges, wipes, terminates, or irrecoverably alters
  external_action - sends data or triggers action outside the local system
                    (HTTP call, email, SMS, webhook, subprocess, payment, SSH, browser)
  unknown         - evidence is genuinely insufficient; do not use as a default

  Prefer unknown ONLY when no positive evidence supports any specific class.
  If multiple classes apply, use the highest-impact one.

retry_safety:
  safe    - read_only; or mutating_write with idempotentHint=true annotation
  unsafe  - external_action; additive_write (calling twice creates duplicates)
  caution - mutating_write without idempotency annotation; destructive

destructiveness:
  none    - read_only
  low     - additive_write (new resource; originals intact)
  medium  - mutating_write, external_action (reversible side effects)
  high    - destructive (data loss, irreversible, cascading, kill/terminate)
  unknown - insufficient signal

output_risk:
  low    - simple scalars: id, boolean, count, status string
  medium - structured objects, lists, logs, file metadata, stack traces
  high   - raw file contents, blobs, credentials, tokens, keys, env vars,
           or any data that carries security risk if exfiltrated

RISK SEVERITY (security - separate from destructiveness):
  HIGH   - directly enables: credential exposure, arbitrary code execution, lateral movement,
           privilege escalation, or irreversible data destruction from metadata alone
  MEDIUM - notable attack surface requiring preconditions (broad filesystem access,
           free-text near sensitive ops, financial operations)
  LOW    - theoretical risk; minor attack surface
  NONE   - no meaningful security risk

DETERMINISTIC PATTERNS (always apply these regardless of description)
======================================================================
  "command"|"cmd"|"shell" param     -> external_action + arbitrary_execution_risk=true
  "exec"|"run"|"eval"|"script" name -> external_action + arbitrary_execution_risk=true
  name: delete_|purge_|wipe_|kill_  -> destructive + reversible=false
  name: bulk_*|all_*|batch_* + del  -> destructive + destructiveness=high
  "path" param, no format constraint -> filesystem_access_risk=true
  "role"|"permission"|"acl"|"policy" param -> privilege_escalation_risk=true
  "token"|"secret"|"key"|"credential" param -> credential_access_risk=true
  "token"|"secret"|"key" in output  -> output_risk=high + credential_access_risk=true
  name: send_|notify_|alert_|email_  -> external_action + data_exfiltration_risk=true
  name: export_|dump_|backup_        -> output_risk=high
  name: archive_|retire_|deactivate_ -> destructive (irreversible state change)
  name: sync_|reconcile_|replicate_  -> mutating_write; open_world if external target present
  free-text string param near exec op -> prompt_injection_surface=true
  payment/billing params             -> external_action + destructiveness=high

CONFIDENCE CALIBRATION
=======================
confidence reflects how strongly the metadata supports the classification - not severity.

  0.9–1.0 : classification follows directly from a deterministic pattern above
  0.7–0.9 : description explicitly states the capability
  0.5–0.7 : description implies it; moderate inference required
  0.3–0.5 : weak signals; significant inference
  0.0–0.3 : almost no evidence; unknown classifications land here

RULES
=====
- Do not set exploitation_scenario to non-null if risk_level is NONE.
- Include at least one entry in evidence[] for every non-NONE risk flag set to true.
- risk_tags must be empty if risk_level is NONE.
- Do not use "other" in risk_tags unless none of the defined tags apply.
- Do not claim a risk not grounded in a specific signal from the input.
"""


def _classify_with_llm(
    tool_name: str,
    description: str,
    schema: Dict[str, Any],
    annotations: Dict[str, Any],
    provider: str,
    model_id: Optional[str]  = None,
    api_key: Optional[str]  = None,
) -> Dict[str, Any]:
    from .scanner import call_llm

    prompt = _LLM_CLASSIFY_PROMPT.format(
        tool_name       = _sanitise_for_prompt(tool_name, 100),
        description     = _sanitise_for_prompt(description, 300) if description else "(none provided)",
        schema_json     = json.dumps(_sanitise_schema(schema), indent=2) if schema else "{}",
        annotations_json= json.dumps(_sanitise_annotations(annotations), indent=2) if annotations else "{}",
    )
    raw = call_llm(provider, model_id, api_key, prompt)

    raw = _strip_json_fence(raw.strip())

    try: parsed = json.loads(raw)
    except json.JSONDecodeError:
        _log.warning("LLM classify returned unparseable JSON for '%s': %.200s", tool_name, raw)
        return {}

    raw_conf = parsed.get("confidence", {})
    if not isinstance(raw_conf, dict):
        raw_conf = {"effect_class": float(raw_conf) if isinstance(raw_conf, (int, float)) else 0.80}
    raw_conf.setdefault("effect_class",    0.75)
    raw_conf.setdefault("risk_level",      0.75)
    raw_conf.setdefault("retry_safety",    0.75)
    raw_conf.setdefault("destructiveness", 0.75)
    # H5: Clamp to [0.0, 1.0] - LLMs occasionally return out-of-range confidence values.
    raw_conf = {
        k: max(0.0, min(1.0, float(v))) if isinstance(v, (int, float)) else 0.0
        for k, v in raw_conf.items()
    }

    result = {
        "effect_class": parsed.get("effect_class",   "unknown"),
        "retry_safety": parsed.get("retry_safety",   "caution"),
        "destructiveness":parsed.get("destructiveness", "unknown"),
        "open_world": bool(parsed.get("open_world", False)),
        "output_risk": parsed.get("output_risk",    "low"),
        "confidence": raw_conf,
        "evidence": parsed.get("evidence",       ["llm_classified"]),
        "run_count": 0,
    }

    for extra in ("credential_access_risk", "arbitrary_execution_risk", "filesystem_access_risk",
                  "prompt_injection_surface", "lateral_movement_risk", "privilege_escalation_risk",
                  "data_exfiltration_risk", "reversible"):
        if extra in parsed: result[extra] = parsed[extra]

    result["evidence"] = list(result["evidence"]) + [f"llm_provider={provider}"]

    # Attach security finding as a side-channel output so inspect_server_tools
    # can store it in security_scans without polluting the behavior profile.
    risk_level = parsed.get("risk_level", "LOW")
    result["_security_finding"] = {
        "name": tool_name,
        "risk_level": risk_level,
        "risk_tags": parsed.get("risk_tags", []),
        "finding": "; ".join(parsed.get("evidence", [])),
        "exploitation_scenario": parsed.get("exploitation_scenario"),
        "remediation": parsed.get("remediation"),
    }

    return result


_LLM_EXTRA_RISK_FIELDS = (
    "credential_access_risk", "arbitrary_execution_risk", "filesystem_access_risk",
    "prompt_injection_surface", "lateral_movement_risk", "privilege_escalation_risk",
    "data_exfiltration_risk", "reversible",
)


def classify_tool(
    tool_name: str,
    description: str,
    schema: Dict[str, Any],
    annotations: Dict[str, Any],
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Classify a tool's behaviour.

    No provider: rule-based only (fast, zero cost, zero network).
    Provider given: LLM + rule-based combined. LLM effect_class is added as a
    weighted vote alongside name/description/schema/annotation signals. LLM wins
    on nuanced fields (open_world, output_risk, extra risk flags). Rule-based
    always runs so there is always a result even if the LLM fails.
    """
    _saved_sec_finding = None
    llm_result: Optional[Dict[str, Any]] = None

    if llm_provider:
        try:
            raw_llm = _classify_with_llm(
                tool_name, description, schema, annotations,
                llm_provider, llm_model, llm_api_key,
            )
            if raw_llm:
                _saved_sec_finding = raw_llm.pop("_security_finding", None)
                if raw_llm.get("effect_class") not in (None, "unknown"): llm_result = raw_llm
        except Exception as exc:
            _log.debug("LLM classify failed for '%s': %s", tool_name, exc)

    evidence: List[str] = []

    name_effect,   name_conf,   name_ev   = _classify_by_name(tool_name)
    desc_effect,   desc_conf,   desc_ev   = _classify_by_description(description)
    schema_effect, schema_conf, schema_ev = _classify_by_schema(schema)
    ann_effect, ann_conf, ann_open_world, retry_hint, ann_ev = _classify_by_annotations(annotations)

    evidence.extend(name_ev)
    evidence.extend(desc_ev)
    evidence.extend(schema_ev)
    evidence.extend(ann_ev)

    votes: Dict[str, float] = {}
    for eff, conf in [
        (name_effect,   name_conf),
        (desc_effect,   desc_conf),
        (schema_effect, schema_conf),
        (ann_effect,    ann_conf),
    ]:
        if eff and eff != "unknown": votes[eff] = votes.get(eff, 0.0) + conf

    if llm_result:
        llm_eff  = llm_result["effect_class"]
        llm_conf = llm_result.get("confidence", {}).get("effect_class", 0.80)
        votes[llm_eff] = votes.get(llm_eff, 0.0) + llm_conf
        evidence.append(f"llm_vote:{llm_eff}:{llm_provider}")

    if not votes: final_effect, final_conf = "unknown", 0.25
    else:
        final_effect = max(votes, key=votes.__getitem__)
        winner       = votes[final_effect]
        total_signal = sum(votes.values())
        final_conf = min(0.95, winner * (winner / total_signal))

    # Annotations are authoritative on idempotency; effect class is the fallback.
    if retry_hint is True: retry_safety = "safe"
    elif retry_hint is False: retry_safety = "unsafe"
    elif final_effect in RETRY_SAFE_EFFECTS: retry_safety = "safe"
    elif final_effect in RETRY_UNSAFE_EFFECTS: retry_safety = "unsafe"
    else: retry_safety = "caution"

    if ann_open_world is not None:
        open_world = ann_open_world
    elif llm_result:
        open_world = llm_result.get("open_world", False)
        evidence.append(f"llm_open_world={open_world}")
    else:
        open_world, ow_ev = _infer_open_world(description, schema, final_effect)
        evidence.extend(ow_ev)

    if llm_result:
        output_risk = llm_result.get("output_risk", "low")
        evidence.append(f"llm_output_risk={output_risk}")
    else:
        output_risk, out_ev = _infer_output_risk(schema, description, final_effect)
        evidence.extend(out_ev)

    extra_risks = _infer_extra_risks(description, schema)
    if llm_result: extra_risks.update({k: v for k, v in llm_result.items() if k in _LLM_EXTRA_RISK_FIELDS})

    result: Dict[str, Any] = {
        "effect_class": final_effect,
        "retry_safety": retry_safety,
        "destructiveness": DESTRUCTIVENESS_MAP.get(final_effect, "unknown"),
        "open_world": open_world,
        "output_risk": output_risk,
        "confidence": {
            "effect_class": round(final_conf, 2),
            "retry_safety": round(final_conf * 0.90, 2),
            "destructiveness": round(final_conf * 0.85, 2),
        },
        "evidence": list(dict.fromkeys(evidence)),
        "run_count": 0,
    }
    result.update(extra_risks)
    if _saved_sec_finding: result["_security_finding"] = _saved_sec_finding
    return result
