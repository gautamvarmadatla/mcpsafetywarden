"""
Security scanner - two modes:
    LLM-based (anthropic / openai / gemini): Sends tool metadata to an LLM and asks it to reason about risks.
  Works on any server - no source code or live connection needed.

Cisco MCP Scanner (cisco):
    Uses the cisco-ai-mcp-scanner SDK: YARA rules + AST/taint analysis + optional ML engine.
  Detects hidden behaviour that metadata-only analysis cannot see.
  Requires a live connection (stdio / sse / streamable_http).
  Falls back gracefully - YARA rules run fully offline with zero API keys.
"""

import asyncio
import json
import os
import shutil
import stat
import sys
import tempfile
from typing import Any, Dict, List, Optional

from .security_utils import sanitise_for_prompt as _sanitise_for_prompt
from .security_utils import redact_text as _redact_text
from .security_utils import strip_json_fence as _strip_json_fence

SECURITY_PROMPT = """\
You are performing a static security analysis of an MCP (Model Context Protocol) server.
You have been given the names, descriptions, and input schemas of all tools exposed by this server.
You have not called any tools. All claims must be based solely on the provided metadata.

TASK
====
For each tool, determine whether its design creates meaningful security risk.
Produce one structured finding per tool. Produce a server-level summary.

SEVERITY DEFINITIONS (apply uniformly)
========================================
HIGH   - The tool's design directly enables credential exposure, arbitrary code execution,
         lateral movement, privilege escalation, or irreversible data destruction.
         Risk is present from metadata alone; exploitation requires no special preconditions.
MEDIUM - The tool has a notable attack surface that requires specific preconditions to exploit
         (e.g., attacker-controlled input, specific parameter combinations, or chained use).
LOW    - Risk is theoretical or minor. Requires unlikely preconditions or defense-in-depth failure.
NONE   - No meaningful security risk is identifiable from the tool's design.

EVIDENCE STANDARD
==================
Every finding must be grounded in one or more observable signals:
- tool name pattern (e.g., "delete_", "exec_", "read_file")
- parameter name (e.g., "command", "path", "query", "token")
- parameter type (e.g., string with no format constraint)
- description text (explicit or implied capability)

Do not claim a risk if it is not traceable to a specific signal in the provided metadata.
If evidence is weak, reflect that in the confidence score - do not suppress the finding.
If a tool has no identifiable risk signals, set risk_level to "NONE" and set
exploitation_scenario and remediation to null. Do not invent scenarios.

RISK TAGS
==========
credential_exposure   - tool can read, return, or leak secrets, tokens, or keys
arbitrary_exec        - tool can execute shell commands, scripts, or arbitrary code
data_exfiltration     - tool can send internal data to external destinations
filesystem_access     - tool has broad or unconstrained read/write access to the filesystem
lateral_movement      - tool can reach other hosts, systems, or network resources
prompt_injection      - tool accepts free-form text that influences downstream execution
privilege_escalation  - tool can modify permissions, roles, or system configuration

OUTPUT FORMAT
=============
Return ONLY valid JSON. No markdown. No text outside the JSON object.

{{
  "overall_risk_level": "<HIGH|MEDIUM|LOW|NONE>",
  "overall_risk_basis": "<one sentence: what drives the server's overall risk level>",
  "summary": "<2-3 sentences: concrete risk posture of this server based on tool set>",
  "tool_findings": [
    {{
      "name": "<tool_name>",
      "risk_level": "<HIGH|MEDIUM|LOW|NONE>",
      "confidence": <0.0-1.0>,
      "risk_tags": ["<tag from list above - empty array if risk_level is NONE>"],
      "evidence": ["<specific signal: parameter name, description phrase, or name pattern>"],
      "finding": "<concrete description of the risk grounded in a specific signal; null if NONE>",
      "exploitation_scenario": "<1-2 sentences: how a compromised agent or attacker exploits this; null if NONE>",
      "remediation": "<specific mitigation; null if NONE>",
      "evidence_basis": "<schema_inferred|name_inferred|description_inferred|combined>"
    }}
  ],
  "server_level_risks": [
    {{
      "risk": "<risk that spans multiple tools or the server as a whole>",
      "risk_level": "<HIGH|MEDIUM|LOW>",
      "tools_involved": ["<tool_name>"]
    }}
  ]
}}

RULES
=====
- Do not include risk_tags not traceable to a metadata signal.
- Do not fabricate CVE identifiers or external references.
- Do not include tool names not present in the input.
- If overall_risk_level is higher than any individual tool risk_level, explain it in server_level_risks.
- confidence reflects evidence strength, not severity. A clearly named "exec_command" tool
  warrants confidence=0.95 even when risk_level is HIGH.

Tools to analyze:
{tools_json}
"""


_LLM_HTTP_TIMEOUT = 120.0
_OLLAMA_BASE_URL  = "http://localhost:11434/v1"  # overridable via OLLAMA_BASE_URL env var


def _call_anthropic(model_id: str, api_key: Optional[str], prompt: str) -> str:
    try:
        import anthropic
    except ImportError: raise ImportError("Run: pip install anthropic")

    client = anthropic.Anthropic(api_key=api_key, timeout=_LLM_HTTP_TIMEOUT) if api_key \
        else anthropic.Anthropic(timeout=_LLM_HTTP_TIMEOUT)
    response = client.messages.create(
        model=model_id or "claude-opus-4-7",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def _call_openai(model_id: str, api_key: Optional[str], prompt: str) -> str:
    try:
        import openai
    except ImportError: raise ImportError("Run: pip install openai")

    client = openai.OpenAI(api_key=api_key, timeout=_LLM_HTTP_TIMEOUT) if api_key \
        else openai.OpenAI(timeout=_LLM_HTTP_TIMEOUT)
    response = client.chat.completions.create(
        model=model_id or "gpt-5.4",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content or ""


def _call_gemini(model_id: str, api_key: Optional[str], prompt: str) -> str:
    # Support both google-genai (new) and google-generativeai (legacy)
    key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    try:
        from google import genai
        client = genai.Client(api_key=key, http_options={"timeout": _LLM_HTTP_TIMEOUT})
        response = client.models.generate_content(
            model=model_id or "gemini-2.5-flash",
            contents=prompt,
        )
        return response.text or ""
    except ImportError: pass

    try:
        import google.generativeai as genai_legacy
        if key: genai_legacy.configure(api_key=key)
        model = genai_legacy.GenerativeModel(model_id or "gemini-2.5-flash")
        response = model.generate_content(
            prompt,
            request_options={"timeout": _LLM_HTTP_TIMEOUT},
        )
        return response.text or ""
    except ImportError: raise ImportError("Run: pip install google-genai  OR  pip install google-generativeai")


def _call_ollama(model_id: str, api_key: Optional[str], prompt: str) -> str:
    """OpenAI-compatible Ollama endpoint. No API key required; model via model_id or OLLAMA_MODEL."""
    try:
        import openai
    except ImportError: raise ImportError("Run: pip install openai")

    base_url = os.environ.get("OLLAMA_BASE_URL", _OLLAMA_BASE_URL)
    model    = model_id or os.environ.get("OLLAMA_MODEL", "llama3.1")
    client   = openai.OpenAI(api_key="ollama", base_url=base_url, timeout=_LLM_HTTP_TIMEOUT)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content or ""


LLM_PROVIDERS = {
    "anthropic": _call_anthropic,
    "openai":    _call_openai,
    "gemini":    _call_gemini,
    "ollama":    _call_ollama,
}

ALL_PROVIDERS = [
    "cisco", "snyk",
    "mcpsafety+anthropic", "mcpsafety+openai", "mcpsafety+gemini", "mcpsafety+ollama",
]


def detect_llm_provider() -> Optional[str]:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    return None


def call_llm(provider: str, model_id: Optional[str], api_key: Optional[str], prompt: str) -> str:
    """Unified LLM caller. Provider must be 'anthropic', 'openai', or 'gemini'."""
    if provider not in LLM_PROVIDERS:
            raise ValueError(
            f"Unknown LLM provider '{provider}'. Choose from: {list(LLM_PROVIDERS.keys())}"
        )
    return LLM_PROVIDERS[provider](model_id, api_key, prompt)


def _format_tools_for_prompt(tools: List[Dict[str, Any]]) -> str:
    slim = []
    for t in tools:
        slim.append({
            "name": _sanitise_for_prompt(t.get("name") or t.get("tool_name") or "", 100),
            "description": _sanitise_for_prompt(t.get("description", ""), 300),
            "parameters": list((t.get("schema") or t.get("inputSchema") or {}).get("properties", {}).keys()),
        })
    return json.dumps(slim, indent=2)


def _parse_llm_response(raw: str) -> Dict[str, Any]:
    raw = _strip_json_fence(raw.strip())
    try: return json.loads(raw)
    except json.JSONDecodeError:
        redacted_raw, _ = _redact_text(raw[:2000])
        return {
            "overall_risk_level": "UNKNOWN",
            "summary": "Failed to parse LLM response as JSON.",
            "tool_findings": [],
            "server_level_risks": [],
            "raw_response": redacted_raw,
        }


def run_security_scan(
    server_id: str,
    tools: List[Dict[str, Any]],
    provider: str,
    model_id: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Metadata-only LLM scan. Works for any server with no live connection.
    provider must be 'anthropic', 'openai', or 'gemini'.
    """
    if not tools:
            return {
            "server_id": server_id,
            "overall_risk_level": "UNKNOWN",
            "summary": "No tools found to analyze.",
            "tool_findings": [],
            "server_level_risks": [],
        }

    tools_json = _format_tools_for_prompt(tools)
    prompt = SECURITY_PROMPT.format(tools_json=tools_json)

    raw = call_llm(provider, model_id, api_key, prompt)
    findings = _parse_llm_response(raw)
    findings["server_id"] = server_id
    findings["provider"]  = provider
    findings["model"]     = model_id or "default"

    return findings



_SEVERITY_MAP = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "SAFE": "NONE",
    "UNKNOWN": "LOW",
}

_OVERALL_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def _normalize_cisco_results(server_id: str, results: list) -> Dict[str, Any]:
    """Convert cisco-ai-mcp-scanner ToolScanResult list -> our common format."""
    tool_findings = []
    worst = "NONE"

    for result in results:
        tool_risk = "NONE"
        risk_tags: List[str] = []
        finding_lines: List[str] = []

        for analyzer_name, sec_findings in (result.findings_by_analyzer or {}).items():
            for f in sec_findings:
                raw_sev = str(getattr(f, "severity", "UNKNOWN")).upper()
                mapped  = _SEVERITY_MAP.get(raw_sev, "LOW")

                if _OVERALL_ORDER[mapped] > _OVERALL_ORDER[tool_risk]: tool_risk = mapped
                if _OVERALL_ORDER[mapped] > _OVERALL_ORDER[worst]: worst = mapped

                finding_lines.append(f"[{analyzer_name}] {getattr(f, 'summary', '') or ''}")

                cat = getattr(f, "threat_category", None)
                if cat: risk_tags.append(str(cat))

        tool_findings.append({
            "name": result.tool_name,
            "risk_level": tool_risk,
            "risk_tags": list(dict.fromkeys(risk_tags)),
            "finding": " | ".join(finding_lines) or "No issues found",
            "exploitation_scenario": "",   # Cisco reports findings, not exploit narratives
            "remediation": "",
            "is_safe": getattr(result, "is_safe", tool_risk == "NONE"),
            "analyzer_status": getattr(result, "status", ""),
        })

    high_count   = sum(1 for t in tool_findings if t["risk_level"] == "HIGH")
    medium_count = sum(1 for t in tool_findings if t["risk_level"] == "MEDIUM")

    summary = (
        f"Cisco scanner analysed {len(tool_findings)} tool(s): "
        f"{high_count} HIGH, {medium_count} MEDIUM risk. "
        f"Overall risk: {worst}."
    )

    return {
        "server_id": server_id,
        "overall_risk_level": worst,
        "summary": summary,
        "tool_findings": tool_findings,
        "server_level_risks": [],
        "provider": "cisco",
        "model": "cisco-ai-mcp-scanner",
    }


def _select_cisco_analyzers(cisco_api_key: Optional[str]) -> list:
    """Choose which Cisco engines to run based on available credentials."""
    try: from mcpscanner.core.models import AnalyzerEnum
    except ImportError: return []

    # YARA + Readiness always work offline with no API keys
    analyzers = [AnalyzerEnum.YARA, AnalyzerEnum.READINESS]

    llm_key = os.environ.get("MCP_SCANNER_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if llm_key: analyzers += [AnalyzerEnum.LLM, AnalyzerEnum.BEHAVIORAL]

    if cisco_api_key or os.environ.get("MCP_SCANNER_API_KEY"): analyzers.append(AnalyzerEnum.API)

    return analyzers


async def run_cisco_scan(
    server_id: str,
    server_config: Dict[str, Any],
    cisco_api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run Cisco MCP Scanner against a live server.

Engines used (based on available credentials):
        - YARA rules        - always, fully offline
      - Readiness checks  - always, fully offline
      - LLM analysis      - if MCP_SCANNER_LLM_API_KEY or OPENAI_API_KEY is set
      - Behavioral (AST)  - same as LLM
      - Cisco ML engine   - if cisco_api_key or MCP_SCANNER_API_KEY is set

    cisco_api_key: Cisco AI Defense API key (optional - enables the cloud ML engine)
    LLM key for Cisco's internal analysis: set MCP_SCANNER_LLM_API_KEY env var
    """
    try: from mcpscanner import Config, Scanner
    except ImportError: raise ImportError("Run: pip install cisco-ai-mcp-scanner")

    key = cisco_api_key or os.environ.get("MCP_SCANNER_API_KEY") or ""
    config = Config(api_key=key)
    scanner = Scanner(config)
    analyzers = _select_cisco_analyzers(cisco_api_key)

    transport = server_config.get("transport")

    if transport == "stdio":
        from mcp import StdioServerParameters
        params = StdioServerParameters(
            command=server_config["command"],
            args=server_config.get("args") or [],
            env=server_config.get("env") or None,
        )
        results = await scanner.scan_stdio_server_tools(params, analyzers=analyzers)

    elif transport in ("sse", "streamable_http"):
        headers = server_config.get("headers") or {}
        results = await scanner.scan_remote_server_tools(
            server_config["url"],
            headers=headers or None,
            analyzers=analyzers,
        )
    else: raise ValueError(f"Unsupported transport '{transport}' for Cisco scanner.")

    return _normalize_cisco_results(server_id, results)



_SNYK_CODES: Dict[str, tuple] = {
    "E001": ("HIGH",   "prompt_injection"),
    "E002": ("HIGH",   "tool_shadowing"),
    "E004": ("HIGH",   "prompt_injection_skill"),
    "E005": ("HIGH",   "suspicious_download_url"),
    "E006": ("HIGH",   "malicious_code_pattern"),
    "W001": ("LOW",    "suspicious_words"),
    "W007": ("HIGH",   "insecure_credential_handling"),
    "W008": ("HIGH",   "hardcoded_secrets"),
    "W009": ("MEDIUM", "direct_financial_execution"),
    "W011": ("MEDIUM", "untrusted_third_party_content"),
    "W012": ("HIGH",   "unverifiable_external_dependency"),
    "W013": ("MEDIUM", "system_service_modification"),
    "W014": ("LOW",    "missing_skill_md"),
    "W015": ("MEDIUM", "untrusted_content"),
    "W016": ("LOW",    "potential_untrusted_content"),
    "W017": ("MEDIUM", "sensitive_data_exposure"),
    "W018": ("LOW",    "workspace_data_exposure"),
    "W019": ("MEDIUM", "destructive_capabilities"),
    "W020": ("LOW",    "local_destructive_capabilities"),
}

_SNYK_SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def _snyk_severity(code: str) -> str: return _SNYK_CODES.get(code, ("LOW", "unknown"))[0]


def _snyk_tag(code: str) -> str: return _SNYK_CODES.get(code, ("LOW", code.lower()))[1]


def _build_snyk_config(server_id: str, server_config: Dict[str, Any]) -> Dict[str, Any]:
    """Build a Claude Desktop-format config Snyk can parse."""
    transport = server_config.get("transport")
    entry: Dict[str, Any] = {}

    if transport == "stdio":
        entry["type"] = "stdio"
        entry["command"] = server_config["command"]
        if server_config.get("args"): entry["args"] = server_config["args"]
        if server_config.get("env"): entry["env"] = server_config["env"]

    elif transport in ("sse", "streamable_http"):
        entry["url"] = server_config["url"]
        if server_config.get("headers"): entry["headers"] = server_config["headers"]
        entry["type"] = "sse" if transport == "sse" else "http"

    else: raise ValueError(f"Unsupported transport '{transport}' for Snyk scanner.")

    return {"mcpServers": {server_id: entry}}


def _normalize_snyk_results(
    server_id: str,
    config_path: str,
    raw: Dict[str, Any],
) -> Dict[str, Any]:
    """Convert snyk-agent-scan --json output -> our common format."""
    if not isinstance(raw, dict):
        raw = {}
    # Output is keyed by absolute config path; fall back to first key
    path_data = (raw[config_path] if config_path in raw else None) or (list(raw.values())[0] if raw else {})

    top_error = path_data.get("error")
    servers   = path_data.get("servers", [])
    issues    = path_data.get("issues", [])

    tool_names: List[str] = []
    if servers:
        sig = servers[0].get("signature") or {}
        tool_names = [t.get("name", f"tool_{i}") for i, t in enumerate(sig.get("tools", []))]

    tool_map: Dict[str, Dict[str, Any]] = {}
    server_level_risks: List[str] = []
    worst = "NONE"

    for issue in issues:
        code      = issue.get("code", "")
        message   = issue.get("message", "")
        reference = issue.get("reference") or []  # [server_idx, tool_idx]

        severity = _snyk_severity(code)
        tag      = _snyk_tag(code)

        if _SNYK_SEVERITY_ORDER[severity] > _SNYK_SEVERITY_ORDER[worst]: worst = severity

        tool_name: Optional[str] = None
        if len(reference) >= 2:
            idx = reference[1]
            if isinstance(idx, int) and 0 <= idx < len(tool_names): tool_name = tool_names[idx]

        if tool_name:
            if tool_name not in tool_map:
                tool_map[tool_name] = {
                    "name": tool_name,
                    "risk_level": "NONE",
                    "risk_tags": [],
                    "finding": "",
                    "exploitation_scenario":"",
                    "remediation": "",
                }
            entry = tool_map[tool_name]
            if _SNYK_SEVERITY_ORDER[severity] > _SNYK_SEVERITY_ORDER[entry["risk_level"]]: entry["risk_level"] = severity
            if tag not in entry["risk_tags"]: entry["risk_tags"].append(tag)
            prefix = f"[{code}] "
            entry["finding"] += ("" if not entry["finding"] else " | ") + prefix + message
        else: server_level_risks.append(f"[{code}] {message}")

    all_findings = list(tool_map.values())
    found = {t["name"] for t in all_findings}
    for name in tool_names:
        if name not in found:
            all_findings.append({
                "name": name,
                "risk_level": "NONE",
                "risk_tags": [],
                "finding": "No issues found",
                "exploitation_scenario": "",
                "remediation": "",
            })

    if top_error:
        err_msg = top_error.get("message") if isinstance(top_error, dict) else str(top_error)
        server_level_risks.insert(0, f"[scan_error] {err_msg}")

    high   = sum(1 for t in all_findings if t["risk_level"] == "HIGH")
    medium = sum(1 for t in all_findings if t["risk_level"] == "MEDIUM")

    return {
        "server_id": server_id,
        "overall_risk_level": worst,
"summary":
            (
            f"Snyk agent-scan: {high} HIGH, {medium} MEDIUM risk across "
            f"{len(all_findings)} tool(s). Overall: {worst}."
        ),
        "tool_findings": all_findings,
        "server_level_risks": server_level_risks,
        "provider": "snyk",
        "model": "snyk-agent-scan",
    }


async def run_snyk_scan(
    server_id: str,
    server_config: Dict[str, Any],
    snyk_token: Optional[str] = None,
    timeout: int = 120,
) -> Dict[str, Any]:
    """
    Run Snyk agent-scan against a server via subprocess.

    Detects: prompt injection (E001), tool shadowing (E002), toxic data flows,
    hardcoded secrets, insecure credential handling, malicious skill patterns.

snyk_token:
        Snyk API token - required for prompt-injection (E001) detection,
                optional for structural/offline checks.
                Falls back to SNYK_TOKEN env var.

    Invocation priority: snyk-agent-scan -> uvx snyk-agent-scan@latest
    """
    config = _build_snyk_config(server_id, server_config)

    tmpdir = None
    config_path = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="mcp_wrapper_snyk_")
        _is_windows = os.name == "nt"
        if _is_windows:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "run_snyk_scan: os.chmod is a no-op on Windows. "
                "The temp config file containing server credentials is readable by any local user "
                "until the scan completes. Ensure no untrusted users share this host."
            )
        try:
            os.chmod(tmpdir, stat.S_IRWXU)
        except OSError:
            pass

        config_path = os.path.join(tmpdir, "config.json")
        with open(config_path, "w") as f:
            json.dump(config, f)
        try:
            os.chmod(config_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        env = {k: v for k, v in os.environ.items() if k in (
            "PATH", "HOME", "TEMP", "TMP", "SYSTEMROOT", "COMSPEC",
            "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
            "USERNAME", "USER", "LOGNAME", "LNAME",
        )}
        token = snyk_token or os.environ.get("SNYK_TOKEN")
        if not token:
            raise ValueError(
                "SNYK_TOKEN is required for snyk-agent-scan. "
                "Set the SNYK_TOKEN environment variable or pass snyk_token. "
                "Obtain a token at https://app.snyk.io/account"
            )
        env["SNYK_TOKEN"] = token

        storage_file = os.path.join(tmpdir, "snyk-state.json")
        base_args = [config_path, "--json", "--storage-file", storage_file]
        candidates: list[list[str]] = []
        bin_path = shutil.which("snyk-agent-scan")
        if bin_path:
            candidates.append([bin_path] + base_args)
        candidates.append([sys.executable, "-m", "agent_scan.cli"] + base_args)
        candidates.append(["uvx", "snyk-agent-scan@latest"] + base_args)

        last_error = ""
        for cmd in candidates:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    env=env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    raise TimeoutError(
                        f"snyk-agent-scan timed out after {timeout}s. "
                        "Try increasing timeout or check server connectivity."
                    )

                raw_out = stdout.decode().strip()
                if not raw_out:
                    last_error = stderr.decode().strip() or "No output from snyk-agent-scan"
                    continue

                try:
                    raw = json.loads(raw_out)
                except json.JSONDecodeError:
                    last_error = f"Could not parse snyk-agent-scan output: {raw_out[:300]}"
                    continue

                return _normalize_snyk_results(server_id, config_path, raw)

            except FileNotFoundError:
                last_error = f"Command not found: {cmd[0]}"
                continue

        raise RuntimeError(
            f"snyk-agent-scan not available. {last_error}\n"
            "Install with: pip install snyk-agent-scan  OR  uvx snyk-agent-scan@latest"
        )

    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
