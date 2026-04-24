"""
Argument safety scanning for safe_tool_call.

Provides regex-based threat detection across 20+ attack categories plus
optional LLM second-pass verification to clear false positives.
"""

import asyncio
import base64
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from .scanner import call_llm as _call_llm_scanner
from .security_utils import normalise_arg as _normalise_probe_str
from .security_utils import sanitise_for_prompt as _sanitise_for_prompt
from .security_utils import strip_json_fence as _strip_json_fence

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_PATH_TRAVERSAL_RE = re.compile(
    r"(\.\.[/\\]"                       # ../  ..\
    r"|\.\.%[25][fF0cC]"               # URL-encoded slashes after ..
    r"|\.\.[;,]"                        # ..;  ..,  (bypass tricks)
    r"|%c0%af|%c1%9c"                   # Overlong UTF-8 / (CVE-2002-0661)
    r"|\.\.[\x00-\x1f]"                # .. + control char
    r"|[/\\]{2,}[a-z.]*\.\."           # //..  \\..
    r"|\.+[/\\]\.+"                     # ../ variants with extra dots
    r")",
    re.IGNORECASE,
)

_SENSITIVE_ABS_PATHS_RE = re.compile(
    r"(/etc/(passwd|shadow|sudoers|hosts|crontab|group|gshadow|securetty|fstab)"
    r"|/proc/(self|[0-9]+)/(environ|cmdline|maps|mem|fd|exe|cwd)"
    r"|/sys/(kernel|class|bus|firmware)"
    r"|/dev/(mem|kmem|port|null|zero|random|urandom)"
    r"|/boot/(grub|efi|vmlinuz|initrd)"
    r"|/var/run/secrets/"              # k8s secrets mount
    r"|/run/secrets/"
    r")",
    re.IGNORECASE,
)

_CREDENTIAL_PATH_RE = re.compile(
    r"(\.ssh[/\\](id_(rsa|dsa|ecdsa|ed25519|xmss)|authorized_keys|known_hosts|config)"
    r"|\.pem(\b|$)"
    r"|\.key(\b|$)"
    r"|\.p12(\b|$)"
    r"|\.pfx(\b|$)"
    r"|\.jks(\b|$)"
    r"|\.keystore(\b|$)"
    r"|(^|[/\\])\.env($|[/\\.])"      # .env  .env.local  .env.production
    r"|\.envrc"
    r"|credentials\.json"
    r"|service.?account.*\.json"
    r"|application_default_credentials"
    r"|client_secret.*\.json"
    r"|[/\\]\.aws[/\\](credentials|config)"
    r"|[/\\]\.config[/\\]gcloud[/\\]"
    r"|[/\\]\.azure[/\\](credentials|accessTokens)"
    r"|[/\\]\.docker[/\\]config\.json"
    r"|[/\\]\.npmrc(\b|$)"
    r"|[/\\]\.pypirc(\b|$)"
    r"|[/\\]\.netrc(\b|$)"
    r"|[/\\]\.gitconfig(\b|$)"
    r"|[/\\]\.git[/\\]config"
    r"|[/\\]\.kube[/\\]config"
    r"|heroku\.json"
    r"|vault.?token"
    r"|vault.?unseal"
    r")",
    re.IGNORECASE,
)

_COMMAND_INJECTION_RE = re.compile(
    r"(\$\([^)]{1,200}\)"              # $(command)
    r"|`[^`]{1,200}`"                  # `command`
    r"|\$\{IFS\}"                      # ${IFS} - common bash bypass
    r"|\$\{[a-z_][a-z0-9_]*\}"       # ${VAR} expansion
    r"|;\s*(rm|cat|ls|wget|curl|nc|ncat|netcat|bash|sh|dash|zsh|ksh|"
    r"python[23]?|perl|ruby|php|node|lua|tclsh|awk|sed)\b"
    r"|[|&]\s*(rm|cat|ls|wget|curl|nc|ncat|netcat|bash|sh|dash|zsh|"
    r"python[23]?|perl|ruby|php|node)\b"
    r"|>[>\s]*/[a-z]"                  # redirect to absolute path
    r"|<\s*/[a-z]"                     # read from absolute path
    r"|__import__\s*\("
    r"|\bsubprocess\b"
    r"|\bos\.(system|popen|execv|execvp|spawnl|popen2)\b"
    r"|\beval\s*\(\s*['\"]"
    r"|\bexec\s*\(\s*['\"]"
    r"|\bcompile\s*\("
    r"|/bin/(sh|bash|dash|zsh|ksh|csh|tcsh)"
    r"|/usr/bin/(python|perl|ruby|php|node|lua|awk|sed|curl|wget)"
    r"|(powershell|pwsh)(\.exe)?\s*[-/]"
    r"|cmd(\.exe)?\s*/[ck]"
    r"|\bcrontab\s+-"
    r"|\bat\s+[0-9]"
    r")",
    re.IGNORECASE,
)

SSRF_RE = re.compile(
    r"(169\.254\.169\.254"             # AWS EC2 metadata
    r"|fd00:ec2::254"                  # AWS IPv6 metadata
    r"|metadata\.google\.internal"    # GCP metadata
    r"|169\.254\.170\.2"              # ECS task metadata
    r"|100\.100\.100\.200"            # Alibaba Cloud metadata
    r"|192\.0\.0\.192"                # Azure IMDS fallback
    r"|168\.63\.129\.16"              # Azure IMDS
    r"|127\.[0-9]+\.[0-9]+\.[0-9]+"  # 127.x.x.x loopback range
    r"|(?<![a-zA-Z0-9\-])localhost(?![a-zA-Z0-9\-\.])"
    r"|(?<![0-9\.])0\.0\.0\.0(?![0-9\.])"
    r"|::1(\b|])"
    r"|\[::1\]"
    r"|\[::ffff:[0-9a-f:]+\]"         # IPv4-mapped IPv6
    r"|fe80:"                          # IPv6 link-local (fe80::/10)
    r"|0177\."                         # Octal-encoded loopback (0177.0.0.1 = 127.0.0.1)
    r"|0x7f"                           # Hex-encoded loopback prefix (0x7f000001)
    r"|0x[0-9a-f]{8}\b"               # Full hex-encoded IPv4 address
    r"|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"  # RFC1918 10.x
    r"|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}"  # RFC1918 172.16-31
    r"|192\.168\.[0-9]{1,3}\.[0-9]{1,3}"         # RFC1918 192.168
    r"|file://"
    r"|gopher://"
    r"|dict://"
    r"|tftp://"
    r"|ldap://[^a-z]"
    r"|sftp://[^a-z]"
    r"|ftp://[^a-z]"
    r")",
    re.IGNORECASE,
)

_NULL_BYTE_RE = re.compile(
    r"(\x00"
    r"|%00"
    r"|\\x00"
    r"|\\u0000"
    r"|\\0(?!\d)"                      # \0 not followed by digit
    r"|%2500"                          # double-encoded null
    r")",
)

_TEMPLATE_INJECTION_RE = re.compile(
    r"(\{\{[^}]{1,500}\}\}"           # Jinja2 / Handlebars / Twig
    r"|\$\{[^}]{1,500}\}"            # Spring EL / Groovy / Kotlin
    r"|<%[=@-]?[^%]{1,500}%>"        # JSP / ERB / ASP
    r"|#\{[^}]{1,500}\}"             # Ruby string interpolation
    r"|\*\{[^}]{1,500}\}"            # Thymeleaf
    r"|@\{[^}]{1,500}\}"             # Thymeleaf URL
    r"|\[#[^\]]{1,500}\]"            # FreeMarker
    r"|<#[^>]{1,500}>"               # FreeMarker directive
    r")",
    re.IGNORECASE,
)

_CRLF_RE = re.compile(
    r"(%0d%0a"
    r"|%0a%0d"
    r"|\r\n"
    r"|\n\r"
    r"|%0a"
    r"|\\r\\n"
    r")",
    re.IGNORECASE,
)

_SQL_INJECTION_RE = re.compile(
    r"('\s*(or|and)\s*'?[0-9a-z]"       # ' OR '1'='1, ' AND 1=1
    r"|\bUNION\s+(ALL\s+)?SELECT\b"      # UNION SELECT
    r"|\bSELECT\b.{1,100}\bFROM\b"      # SELECT ... FROM
    r"|\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b"
    r"|\bINSERT\s+INTO\b"
    r"|\bDELETE\s+FROM\b"
    r"|\bUPDATE\b.{1,100}\bSET\b"
    r"|;\s*--"                            # ; -- (statement terminator + comment)
    r"|'\s*;\s*"                          # '; (statement terminator after quote)
    r"|\bEXEC\s*\("                       # EXEC()
    r"|\bEXECUTE\s+\w"                   # EXECUTE proc
    r"|\bxp_cmdshell\b"                  # MSSQL xp_cmdshell
    r"|\bSLEEP\s*\([0-9]"               # MySQL SLEEP()
    r"|\bWAITFOR\s+DELAY\b"             # MSSQL WAITFOR DELAY
    r"|\bpg_sleep\s*\("                 # PostgreSQL pg_sleep
    r"|\bBENCHMARK\s*\("               # MySQL BENCHMARK timing attack
    r"|\bINFORMATION_SCHEMA\b"
    r"|\bSYS(COLUMNS|TABLES|OBJECTS|PROCESSES)\b"
    r"|0x[0-9a-f]{4,}\s*--"             # hex-encoded payload + SQL comment
    r"|\bLOAD_FILE\s*\("               # MySQL LOAD_FILE
    r"|\bOUTFILE\b"                     # MySQL INTO OUTFILE
    r"|\bDATABASELINK\b"               # Oracle database link
    r"|\bEXTRACTVALUE\s*\("           # MySQL XPath injection via SQL
    r"|\bUPDATEXML\s*\("              # MySQL XPath injection via SQL
    r")",
    re.IGNORECASE,
)

_NOSQL_INJECTION_RE = re.compile(
    r'(\$\s*(where|gt|lt|gte|lte|ne|in|nin|regex|or|and|not|nor|exists|type|mod|all|size|elemMatch)\b'
    r'|\{\s*"\$'                         # {"$gt": ...
    r"|;\s*return\s+true\b"             # ; return true  (MongoDB $where injection)
    r"|this\.[a-zA-Z_]\w*\.length"      # this.field.length (MongoDB $where)
    r'|"\$ne"\s*:'                      # "$ne": value
    r'|"\$regex"\s*:'                   # "$regex": ".*"
    r")",
    re.IGNORECASE,
)

_LDAP_INJECTION_RE = re.compile(
    r"(\)\s*\("                          # )( - LDAP filter closure
    r"|\*\s*\)\s*\|"                    # *)|
    r"|\*\)\s*\("                       # *)(
    r"|\(\s*\|"                         # (|  - OR filter
    r"|\(\s*&"                          # (&  - AND filter with injection context
    r"|\(\s*!"                          # (!  - NOT filter injection
    r"|[)(|&!*\\]{3,}"                  # clusters of LDAP meta-characters
    r"|\\\([0-9a-f]{2}"                 # LDAP escape sequence abuse
    r")",
    re.IGNORECASE,
)

_XPATH_INJECTION_RE = re.compile(
    r"("
    r"'\s+or\s+'"                        # ' or '
    r"|'\s+and\s+'"                      # ' and '
    r"|\]\s*\|\s*//"                     # ] | //  - XPath union
    r"|//\*\["                           # //*[  - wildcard predicate
    r"|\bposition\s*\(\s*\)"            # position()
    r"|\bstring-length\s*\("            # string-length()  - blind XPath exfil
    r"|\bsubstring\s*\(.{1,50},\s*[0-9]+\s*,\s*1\s*\)"  # char-by-char extraction
    r"|\bdoc\s*\(\s*['\"]file://"       # doc('file://...')  - XXE via XPath
    r"|\bcount\s*\(\s*//"               # count(//*) - enumeration
    r")",
    re.IGNORECASE,
)

_XXE_RE = re.compile(
    r"("
    r"<!DOCTYPE\b"                       # DOCTYPE declaration
    r"|<!ENTITY\b"                       # ENTITY declaration
    r"|SYSTEM\s+['\"]file://"           # SYSTEM entity -> local file
    r"|SYSTEM\s+['\"]http://"           # SYSTEM entity -> remote DTD
    r"|SYSTEM\s+['\"]https://"
    r"|PUBLIC\s+['\"][^'\"]*['\"]"      # PUBLIC entity identifier
    r"|\[<!ENTITY"                       # inline DTD entity block
    r"|%[a-zA-Z][a-zA-Z0-9_-]*;"       # parameter entity reference %xxe;
    r")",
    re.IGNORECASE,
)

_HEADER_INJECTION_RE = re.compile(
    r"(?:%0d%0a|%0a%0d|%0a|%0d|\r\n|\n\r|\r|\n)"
    r"[a-zA-Z0-9_-]{1,60}\s*:",
    re.IGNORECASE,
)

_PROMPT_INJECTION_RE = re.compile(
    r"("
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?"
    r"|disregard\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|forget\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|you\s+(are|were)\s+now\s+(a|an|the)\b"
    r"|act\s+as\s+(a|an)\b.{0,60}(without\s+restriction|unrestricted|jailbreak)"
    r"|</?\s*(system|user|assistant|context|prompt|instruction|human)\s*>"
    r"|\[INST\]|\[/INST\]"
    r"|<\|im_start\|>|<\|im_end\|>"
    r"|<\|system\|>|<\|user\|>|<\|assistant\|>"
    r"|#{3,}\s*(system|user|assistant|context)\b"
    r"|\[\[SYSTEM\]\]|\[\[USER\]\]|\[\[ASSISTANT\]\]"
    r"|BEGIN\s+SYSTEM\s+PROMPT|END\s+SYSTEM\s+PROMPT"
    r"|OVERRIDE\s+(SAFETY\s+)?(MODE|INSTRUCTIONS)"
    r"|DAN\s+mode\s+enabled"
    r"|you\s+have\s+no\s+(restrictions|limitations|constraints)"
    r")",
    re.IGNORECASE,
)

_WINDOWS_SPECIFIC_RE = re.compile(
    r"("
    r"\\\\[a-zA-Z0-9_.\-]{1,100}\\"    # UNC path \\server\share
    r"|%5c%5c[a-zA-Z0-9_.\-]"          # URL-encoded UNC
    r"|\b(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.|$|\s)"  # Windows device names
    r"|::[$\$]DATA"                      # Alternate Data Stream ::$DATA
    r"|%3a%3a%24DATA"                   # URL-encoded ADS
    r")",
    re.IGNORECASE,
)

_DESERIALIZE_RE = re.compile(
    r"("
    r"rO0AB"                             # Java serialized object (base64 header)
    r"|aced0005"                         # Java serialized object (hex)
    r"|\\x80\\x04\\x95"                # Python pickle protocol 4 (escaped)
    r"|%80%04%95"                        # Python pickle (URL-encoded)
    r"|O:[0-9]+:\"[a-zA-Z]"            # PHP serialize O:4:"User"
    r"|a:[0-9]+:\{i:[0-9]"             # PHP serialize array
    r"|AAEAAAD"                          # .NET BinaryFormatter (base64)
    r"|YIId"                             # .NET BinaryFormatter (alternate base64)
    r")",
    re.IGNORECASE,
)

_B64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

_MAX_ARG_VALUE_LEN = 50_000
_MAX_PRODUCTION_SCAN_DEPTH = 20

# ---------------------------------------------------------------------------
# JSON parse helpers (shared with mcpsafety_scanner pipeline)
# ---------------------------------------------------------------------------

def _extract_json_fence(raw: str, open_ch: str, close_ch: str):
    start = raw.find(open_ch)
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape_next = False
    for i in range(start, len(raw)):
        ch = raw[i]
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return raw[start:i + 1]
    return None


def _safe_json_list(raw: str) -> List[Dict[str, Any]]:
    raw = raw.strip()
    raw = _strip_json_fence(raw).strip()
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        fragment = _extract_json_fence(raw[:204_800], "[", "]")
        if fragment:
            try:
                parsed = json.loads(fragment)
                return parsed if isinstance(parsed, list) else []
            except json.JSONDecodeError:
                pass
        return []


def _safe_json_dict(raw: str) -> Dict[str, Any]:
    raw = raw.strip()
    raw = _strip_json_fence(raw).strip()
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        fragment = _extract_json_fence(raw[:204_800], "{", "}")
        if fragment:
            try:
                parsed = json.loads(fragment)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                pass
        return {}


# ---------------------------------------------------------------------------
# Internal probe-time scanning (used by hacker stage)
# ---------------------------------------------------------------------------

def _scan_single_str(value: str, allow_destructive: bool) -> List[str]:
    issues: List[str] = []
    norm = _normalise_probe_str(value)

    if SSRF_RE.search(norm): issues.append("ssrf_target")
    if _NULL_BYTE_RE.search(value) or _NULL_BYTE_RE.search(norm): issues.append("null_byte")
    if len(value.encode("utf-8", errors="ignore")) > _MAX_ARG_VALUE_LEN: issues.append("oversized_value")
    if _CRLF_RE.search(norm): issues.append("crlf_injection")
    if _TEMPLATE_INJECTION_RE.search(norm): issues.append("template_injection")

    if not allow_destructive:
        if _PATH_TRAVERSAL_RE.search(norm): issues.append("path_traversal")
        if _SENSITIVE_ABS_PATHS_RE.search(norm): issues.append("sensitive_path_access")
        if _CREDENTIAL_PATH_RE.search(norm): issues.append("credential_path_access")
        if _COMMAND_INJECTION_RE.search(norm): issues.append("command_injection")

    return issues


def _scan_arg_values(obj: Any, allow_destructive: bool, depth: int = 0) -> List[str]:
    if depth > 8:
        return []
    issues: List[str] = []
    if isinstance(obj, str):
        issues.extend(_scan_single_str(obj, allow_destructive))
    elif isinstance(obj, dict):
        for v in obj.values():
            issues.extend(_scan_arg_values(v, allow_destructive, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            issues.extend(_scan_arg_values(item, allow_destructive, depth + 1))
    return list(dict.fromkeys(issues))


def _inspect_probe_args(
    tool_name: str,
    args: Dict[str, Any],
    allow_destructive: bool,
) -> Optional[str]:
    categories = _scan_arg_values(args, allow_destructive)
    if categories:
        return (
            f"Probe args rejected [{', '.join(categories)}] for tool '{tool_name}'. "
            "Args never reached target server."
        )
    return None


def _detect_base64_payloads(value: str) -> List[str]:
    issues: List[str] = []
    for m in _B64_CANDIDATE_RE.finditer(value):
        candidate = m.group()
        padding = (-len(candidate)) % 4
        try:
            decoded_bytes = base64.b64decode(candidate + "=" * padding, validate=False)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
        except Exception:
            continue
        if len(decoded) < 8:
            continue
        norm = _normalise_probe_str(decoded)
        found: List[str] = []
        if SSRF_RE.search(norm): found.append("ssrf_target")
        if _COMMAND_INJECTION_RE.search(norm): found.append("command_injection")
        if _PATH_TRAVERSAL_RE.search(norm): found.append("path_traversal")
        if _SQL_INJECTION_RE.search(norm): found.append("sql_injection")
        if _PROMPT_INJECTION_RE.search(decoded): found.append("prompt_injection")
        if _XXE_RE.search(norm): found.append("xxe")
        if found:
            issues.extend(f"b64_{cat}" for cat in found)
    return list(dict.fromkeys(issues))


def _scan_production_value(value: str) -> List[str]:
    issues: List[str] = []
    norm = _normalise_probe_str(value)

    if SSRF_RE.search(norm): issues.append("ssrf_target")
    if _NULL_BYTE_RE.search(value) or _NULL_BYTE_RE.search(norm): issues.append("null_byte")
    if len(value.encode("utf-8", errors="ignore")) > _MAX_ARG_VALUE_LEN: issues.append("oversized_value")
    if _CRLF_RE.search(norm): issues.append("crlf_injection")
    if _TEMPLATE_INJECTION_RE.search(norm): issues.append("template_injection")
    if _PATH_TRAVERSAL_RE.search(norm): issues.append("path_traversal")
    if _SENSITIVE_ABS_PATHS_RE.search(norm): issues.append("sensitive_path_access")
    if _CREDENTIAL_PATH_RE.search(norm): issues.append("credential_path_access")
    if _COMMAND_INJECTION_RE.search(norm): issues.append("command_injection")
    if _SQL_INJECTION_RE.search(norm): issues.append("sql_injection")
    if _NOSQL_INJECTION_RE.search(norm): issues.append("nosql_injection")
    if _LDAP_INJECTION_RE.search(value): issues.append("ldap_injection")
    if _XPATH_INJECTION_RE.search(norm): issues.append("xpath_injection")
    if _XXE_RE.search(norm): issues.append("xxe")
    if _HEADER_INJECTION_RE.search(value): issues.append("header_injection")
    if _PROMPT_INJECTION_RE.search(value): issues.append("prompt_injection")
    if _WINDOWS_SPECIFIC_RE.search(value): issues.append("windows_attack_path")
    if _DESERIALIZE_RE.search(value): issues.append("deserialization_payload")
    issues.extend(_detect_base64_payloads(value))

    return list(dict.fromkeys(issues))


def _scan_production_args(
    obj: Any,
    depth: int = 0,
    path: str = "",
) -> List[Tuple[str, str, List[str]]]:
    if depth > _MAX_PRODUCTION_SCAN_DEPTH:
        return [(path or "args", "", ["excessive_json_nesting"])]

    results: List[Tuple[str, str, List[str]]] = []

    if isinstance(obj, str):
        issues = _scan_production_value(obj)
        if issues:
            results.append((path or "args", obj[:300], issues))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{path}.{k}" if path else k
            results.extend(_scan_production_args(v, depth + 1, child))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            child = f"{path}[{i}]"
            results.extend(_scan_production_args(item, depth + 1, child))

    return results


# ---------------------------------------------------------------------------
# LLM verification prompt
# ---------------------------------------------------------------------------

_ARG_THREAT_VERIFY_PROMPT = """\
You are a senior application-security engineer performing a second-pass review of a flagged tool argument.
A regex scanner already identified one or more suspicious patterns. Your job is to decide, with full context,
whether this is a genuine attack payload that must be blocked or a legitimate value that triggered a false positive.

═══════════════════════════════════════════════════════════
TOOL CONTEXT
═══════════════════════════════════════════════════════════
Tool name        : {tool_name}
Tool description : {tool_description}
Argument path    : {arg_path}
Flagged value    : {value}
Detected categories: {categories}

═══════════════════════════════════════════════════════════
CATEGORY DEFINITIONS & FALSE-POSITIVE GUIDE
═══════════════════════════════════════════════════════════
Use these definitions to interpret the detected categories.

ssrf_target
  REAL: A URL/IP passed to a tool that makes outbound HTTP calls where the value is a cloud-metadata
        endpoint (169.254.169.254), a loopback (127.x, ::1, localhost), RFC1918 range, or dangerous
        scheme (file://, gopher://, dict://) - not expected by a legitimate user.
  FALSE POSITIVE: A documentation tool or content-fetching tool that is explicitly designed to fetch
        URLs the user provides; a URL that is clearly external/public; a test tool with 127.0.0.1
        documented as a valid local endpoint.

path_traversal / sensitive_path_access / credential_path_access
  REAL: A file-path arg containing ../ sequences, /etc/passwd, ~/.ssh/id_rsa, .aws/credentials,
        .env files - especially when the tool description does not indicate it reads arbitrary paths.
  FALSE POSITIVE: A filesystem or backup tool explicitly designed to read any path; a tool where
        the arg name and description make it clear arbitrary paths are expected input.

command_injection
  REAL: Shell metacharacters ($(), backtick, ;cmd, |cmd) or interpreter invocations (python -c,
        eval(), exec(), __import__) embedded in args passed to a tool that does NOT accept shell
        commands as input.
  FALSE POSITIVE: A "run_command" / "execute_shell" / "code_interpreter" tool where a shell command
        IS the expected input; a query containing a literal dollar sign for a currency value.

sql_injection
  REAL: Classic injection tokens (UNION SELECT, OR '1'='1, DROP TABLE, SLEEP(), xp_cmdshell,
        INTO OUTFILE) in an arg passed to a tool that queries a database but does NOT accept raw SQL.
  FALSE POSITIVE: A tool explicitly accepting raw SQL (e.g. "run_sql", "execute_query"); a search
        query that legitimately contains the word "SELECT" or "TABLE" in a non-SQL context.

nosql_injection
  REAL: MongoDB operator keys ($gt, $where, $regex, $ne) embedded in a value passed to a tool that
        queries a NoSQL store without expecting operator syntax.
  FALSE POSITIVE: A tool that explicitly accepts MongoDB query objects as its API contract.

ldap_injection
  REAL: LDAP filter metacharacters ()&|!* in clusters, injected into a user/group lookup tool
        that builds LDAP filters from the value.
  FALSE POSITIVE: A tool that explicitly accepts raw LDAP filter expressions.

xpath_injection
  REAL: XPath expressions (' or '1'='1, ] | //, string-length()) in args passed to an XML
        parser or XPath evaluator that does not document accepting XPath syntax.
  FALSE POSITIVE: A tool that explicitly accepts XPath expressions as input.

xxe
  REAL: DOCTYPE or ENTITY declarations, SYSTEM/PUBLIC entity references in a value fed to an
        XML parser - indicates attempt to read local files or trigger SSRF via XML parsing.
  FALSE POSITIVE: A tool that explicitly accepts XML and is documented to parse DOCTYPE/ENTITY;
        an XML schema or template tool where entity definitions are the expected input.

template_injection (SSTI)
  REAL: Template engine syntax ({{7*7}}, ${{7*7}}, <%=7*7%>, #{{7*7}}) in args passed to a tool
        that renders templates without sandboxing.
  FALSE POSITIVE: A tool that explicitly renders user-provided templates (Jinja2, Handlebars, etc.);
        a tool accepting mathematical expressions where {{...}} is a documented delimiter.

crlf_injection / header_injection
  REAL: %0d%0a or raw \\r\\n followed by a header-like "Name: value" pattern, in an arg passed
        to a tool that writes HTTP responses or sets HTTP headers.
  FALSE POSITIVE: A tool processing multiline text/body content where newlines are expected;
        a tool working with raw HTTP traffic for security testing.

prompt_injection
  REAL: "Ignore previous instructions", role-override phrases, system-delimiter tokens
        (</system>, [INST], <|im_start|>) embedded in a value that will be incorporated into
        an LLM prompt by this tool.
  FALSE POSITIVE: A tool explicitly designed to test prompt injection (security scanner); a value
        that contains those phrases as data being analyzed, not as an instruction to an LLM;
        a tool that does not involve LLMs at all.

null_byte
  REAL: \\x00 / %00 / \\u0000 in a string that will be used in a file path, database query, or
        C-library call - classic null-byte injection to truncate strings at security boundaries.
  FALSE POSITIVE: A binary-processing or hex-editor tool where null bytes are expected data.

deserialization_payload
  REAL: Java serialization magic bytes (rO0AB / aced0005), Python pickle prefix, PHP serialize
        objects, .NET BinaryFormatter payloads passed to a tool that deserializes data.
  FALSE POSITIVE: A tool that explicitly receives and processes serialized objects; a tool
        performing base64 analysis where these happen to appear in the decoded content.

windows_attack_path
  REAL: UNC paths (\\\\server\\share), Windows device names (CON, NUL, COM1) in file-path args,
        alternate data streams (::$DATA) - indicating path manipulation on Windows targets.
  FALSE POSITIVE: A tool explicitly working with Windows paths or UNC shares in a documented way.

b64_* (base64-wrapped payloads)
  REAL: Any of the above attacks encoded in base64 in a tool that decodes the value before use.
  FALSE POSITIVE: Legitimately base64-encoded binary data (images, certificates, encryption keys)
        where the decoded content only superficially resembles an attack pattern.

excessive_json_nesting
  REAL: JSON depth > 20 levels - usually a denial-of-service or parser-bomb attempt.
  FALSE POSITIVE: Rarely legitimate; only if the tool documents accepting deeply nested structures.

═══════════════════════════════════════════════════════════
REASONING STEPS - work through all of these
═══════════════════════════════════════════════════════════
1. TOOL PURPOSE: What does this tool do? Does the tool's description suggest it accepts or processes
   the kind of content that was flagged?

2. ARG ROLE: What role does the argument "{arg_path}" play? Is it a URL, a file path, a query
   string, a freeform message, a raw command? Does the arg name or description suggest it is
   expected to carry the flagged content type?

3. PATTERN PLAUSIBILITY: Given the tool purpose and arg role, is the flagged value plausible for
   a legitimate user? Or does it only make sense as an attack?

4. ATTACK SPECIFICITY: Are the flagged tokens clearly adversarial (UNION SELECT, DROP TABLE,
   169.254.169.254, ../../etc/passwd) or are they generic strings that happen to match a pattern?

5. CONTEXT COHERENCE: Does the complete value read like a genuine input or like a crafted payload
   designed to exploit a vulnerability?

6. MULTI-CATEGORY: If multiple categories fired, does that increase attack likelihood (layered
   attack) or does it suggest the pattern is noisy for this type of content?

═══════════════════════════════════════════════════════════
OUTPUT FORMAT - respond with ONLY valid JSON, no other text
═══════════════════════════════════════════════════════════
{{
  "is_attack": true,
  "confidence": 0.95,
  "reason": "Concise one-sentence explanation referencing the tool context and the specific threat"
}}

Rules:
- confidence must be a float 0.0-1.0
- reason must cite the tool context, not just restate the category name
- if the evidence is mixed or ambiguous, set is_attack=false and explain in reason
- never refuse to produce the JSON; always give a verdict"""


# ---------------------------------------------------------------------------
# LLM verification
# ---------------------------------------------------------------------------

async def _llm_verify_arg_threat(
    flagged_value: str,
    arg_path: str,
    tool_name: str,
    tool_description: str,
    categories: List[str],
    provider: str,
    model: Optional[str],
    api_key: Optional[str],
) -> Dict[str, Any]:
    prompt = _ARG_THREAT_VERIFY_PROMPT.format(
        tool_name=_sanitise_for_prompt(tool_name, 100),
        tool_description=_sanitise_for_prompt(tool_description, 300),
        arg_path=_sanitise_for_prompt(arg_path, 100),
        value=_sanitise_for_prompt(flagged_value[:400], 400),
        categories=", ".join(categories),
    )
    try:
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(
            None, _call_llm_scanner, provider, model, api_key, prompt,
        )
        parsed = _safe_json_dict(raw)
        if "is_attack" not in parsed:
            return {"is_attack": True, "confidence": 0.5, "reason": "Unparseable LLM response; defaulting to block"}
        return parsed
    except Exception as exc:
        _log.warning("LLM arg threat verification failed: %s", exc)
        return {"is_attack": True, "confidence": 0.5, "reason": "LLM verification unavailable"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def scan_args_for_threats(
    tool_name: str,
    args: Dict[str, Any],
    tool_description: str = "",
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_api_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Production-grade arg safety scan for safe_tool_call.

    Returns None when args are safe.
    Returns a threat dict when an arg must be blocked:
      {flagged_arg, flagged_value, categories, llm_verified, llm_confidence, reason}
    Without an LLM provider the result has needs_review=True so the caller can
    prompt the user to re-call with args_scan_override=True.
    """
    flagged = _scan_production_args(args)
    if not flagged:
        return None

    all_flagged = [
        {"arg": p, "value": v[:200], "categories": c}
        for p, v, c in flagged
    ]

    if llm_provider:
        for arg_path, value_snippet, categories in flagged:
            verdict = await _llm_verify_arg_threat(
                value_snippet, arg_path, tool_name, tool_description,
                categories, llm_provider, llm_model, llm_api_key,
            )
            is_attack: bool = bool(verdict.get("is_attack", True))
            confidence: float = float(verdict.get("confidence", 0.5))
            reason: str = str(verdict.get("reason", ""))

            if not is_attack:
                _log.info(
                    "LLM cleared false positive in '%s' arg '%s' (confidence %.2f): %s",
                    tool_name, arg_path, confidence, reason,
                )
                continue

            return {
                "flagged_arg": arg_path,
                "flagged_value": value_snippet[:200],
                "categories": categories,
                "all_flagged_args": all_flagged,
                "llm_verified": True,
                "llm_confidence": round(confidence, 3),
                "reason": reason or "LLM-confirmed threat",
            }

        return None

    arg_path, value_snippet, categories = flagged[0]
    return {
        "flagged_arg": arg_path,
        "flagged_value": value_snippet[:200],
        "categories": categories,
        "all_flagged_args": all_flagged,
        "llm_verified": False,
        "needs_review": True,
        "reason": "Pattern-based detection - no LLM available for verification",
    }
