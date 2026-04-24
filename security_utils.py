"""
Shared security utilities: text normalisation, credential detection, redaction.
"""

import html as _html
import re
import unicodedata
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote

_ZERO_WIDTH_RE  = re.compile("[" + "".join(chr(c) for c in [
    0x200b, 0x200c, 0x200d, 0x200e, 0x200f,  # zero-width space/joiners, LRM, RLM
    *range(0x202a, 0x202f),                    # bidi embedding/override (LRE-RLO + PDF)
    *range(0x2060, 0x2065),                    # word joiner + invisible math operators
    0xfeff,                                    # zero-width no-break space (BOM)
    0x00ad,                                    # soft hyphen
]) + "]")

_MARKDOWN_RE    = re.compile(r"[*_`~\[\]|\\]")
_MULTI_SPACE_RE = re.compile(r"\s+")
_CTRL_CHARS_RE  = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitise_for_prompt(text: str, max_len: int = 300) -> str:
    """Strip control characters, zero-width chars, and collapse whitespace before embedding text in an LLM prompt."""
    text = _CTRL_CHARS_RE.sub("", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _MULTI_SPACE_RE.sub(" ", text).strip()
    return text[:max_len]


def normalise_output(text: str) -> str:
    """
    Normalise tool OUTPUT for injection scanning.
    Handles: Unicode homoglyphs (NFKC), zero-width obfuscation, HTML entities,
    markdown formatting used to hide keywords, and whitespace collapse.
    Does NOT URL-decode - output is not URL-encoded.
    """
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _html.unescape(text)
    text = _MARKDOWN_RE.sub(" ", text)
    text = _MULTI_SPACE_RE.sub(" ", text)
    return text.strip()


def normalise_arg(s: str) -> str:
    """
    Normalise a probe ARGUMENT for blocklist pattern matching.
    Applies NFKC, zero-width removal, up to 3-pass URL decoding (handles
    double/triple encoding), and HTML entity decoding.
    Does NOT strip markdown - markdown chars may be part of the probe itself.
    Use this for vetting args BEFORE they are sent to a target server.
    """
    s = unicodedata.normalize("NFKC", s)
    s = _ZERO_WIDTH_RE.sub("", s)
    for _ in range(3):
        decoded = unquote(s)
        if decoded == s: break
        s = decoded
    s = _html.unescape(s)
    s = re.sub(r"\s+", " ", s)
    return s


_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|pwd|pass|secret|token|api[_\-.]?key|apikey|"
    r"access[_\-.]?key|access[_\-.]?secret|private[_\-.]?key|pub[_\-.]?key|"
    r"pem|cert(ificate)?|passphrase|credential[s]?|auth[_\-.]?token|"
    r"bearer|signing[_\-.]?key|encryption[_\-.]?key|ssh[_\-.]?key|"
    r"client[_\-.]?secret|consumer[_\-.]?secret|app[_\-.]?secret|"
    r"webhook[_\-.]?secret|hmac|salt|nonce|iv|master[_\-.]?key|"
    r"root[_\-.]?password|db[_\-.]?password|database[_\-.]?password|"
    r"connection[_\-.]?string|dsn|smtp[_\-.]?password|ftp[_\-.]?password|"
    r"admin[_\-.]?password|sudo[_\-.]?password|pin|otp|mfa[_\-.]?secret|"
    r"totp[_\-.]?secret|refresh[_\-.]?token|id[_\-.]?token|session[_\-.]?token|"
    r"cookie[_\-.]?secret|jwt[_\-.]?secret|encryption[_\-.]?password)",
    re.IGNORECASE,
)

_SECRET_VALUE_PATTERNS: List[re.Pattern] = [
    re.compile(r"^eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$"),     # JWT
    re.compile(r"^sk-ant-[A-Za-z0-9\-_]{20,}$"),                                  # Anthropic key
    re.compile(r"^sk-[A-Za-z0-9]{20,}$"),                                          # OpenAI key
    re.compile(r"^AKIA[0-9A-Z]{16}$"),                                             # AWS access key
    re.compile(r"^ghp_[A-Za-z0-9]{36}$"),                                          # GitHub PAT
    re.compile(r"^github_pat_[A-Za-z0-9_]{82}$"),                                  # GitHub fine-grained PAT
    re.compile(r"^ghs_[A-Za-z0-9]{36}$"),                                          # GitHub server token
    re.compile(r"^xox[bporas]-[A-Za-z0-9\-]{10,}$"),                              # Slack token
    re.compile(r"^-----BEGIN\s+(RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY-----"),  # PEM key
    re.compile(r"^[0-9a-fA-F]{256,}$"),                                            # Long hex (≥256 chars; avoids SHA-256/SHA-512 hash false positives)
    re.compile(r"^[A-Za-z0-9+/]{128,}={0,2}$"),                                   # Long base64 blob (128+ chars to skip hashes and short encoded values)
    re.compile(r"^[A-Za-z0-9\-_]{200,}$"),                                         # Generic long token (200+ to avoid matching IDs/UUIDs/short tokens)
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),                            # Bearer token in value
    re.compile(r"(?i)(password|secret|token|key)\s*[=:]\s*\S{8,}"),               # key=value in string
]

_CREDENTIAL_TEXT_RE = re.compile(
    r"(eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*"
    r"|sk-ant-[A-Za-z0-9\-_]{20,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{36}"
    r"|ghs_[A-Za-z0-9]{36}"
    r"|github_pat_[A-Za-z0-9_]{80,}"
    r"|xox[bporas]-[A-Za-z0-9\-]{10,}"
    r"|-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----[^-]+"
    r"|[0-9a-fA-F]{256,}"
    r"|[A-Za-z0-9+/]{200,}={0,2})",
)


def looks_like_secret(value: Any) -> bool:
    if not isinstance(value, str) or len(value) < 8:
        return False
    return any(p.search(value) for p in _SECRET_VALUE_PATTERNS)


def _redact_value(v: Any) -> Any:
    if isinstance(v, dict):
        return redact_args(v)
    if isinstance(v, list): return [_redact_value(i) for i in v]
    if looks_like_secret(v): return "[REDACTED]"
    return v


def redact_args(args: Dict[str, Any]) -> Dict[str, Any]:
    redacted = {}
    for k, v in args.items():
        if _SENSITIVE_KEY_RE.search(str(k)):
            redacted[k] = "[REDACTED]"
        else: redacted[k] = _redact_value(v)
    return redacted


def redact_text(text: str) -> Tuple[str, bool]:
    """Redact credential-shaped patterns from free-form text. Returns (redacted_text, was_redacted)."""
    redacted, n = _CREDENTIAL_TEXT_RE.subn("[CREDENTIAL REDACTED]", text)
    return redacted, n > 0


def redact_findings(findings: List[Dict]) -> List[Dict]:
    """Redact credential values from scan finding dicts (operates on copies)."""
    _TEXT_FIELDS = ("finding", "probe", "exploitation_scenario", "remediation")
    clean = []
    for f in findings:
        entry = dict(f)
        for field in _TEXT_FIELDS:
            if isinstance(entry.get(field), str): entry[field], _ = redact_text(entry[field])
        if isinstance(entry.get("probes"), list):
            redacted_probes = []
            for p in entry["probes"]:
                p = dict(p)
                for field in ("observation", "input_summary"):
                    if isinstance(p.get(field), str): p[field], _ = redact_text(p[field])
                redacted_probes.append(p)
            entry["probes"] = redacted_probes
        if isinstance(entry.get("state_changes_made"), list):
            entry["state_changes_made"] = [
                redact_text(s)[0] if isinstance(s, str) else s
                for s in entry["state_changes_made"]
            ]
        clean.append(entry)
    return clean
