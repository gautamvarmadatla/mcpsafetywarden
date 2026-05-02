"""Scan known MCP client config files to discover locally installed MCP servers."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

_log = logging.getLogger(__name__)

_IS_WIN = sys.platform == "win32"
_IS_MAC = sys.platform == "darwin"
_CURRENT_OS = "win" if _IS_WIN else ("mac" if _IS_MAC else "linux")

_HOME = Path.home()
_APPDATA = Path(os.environ.get("APPDATA") or str(_HOME / "AppData" / "Roaming"))
_PROGRAMDATA = Path(os.environ.get("PROGRAMDATA") or "C:/ProgramData")
_MAC_SUPPORT = _HOME / "Library" / "Application Support"


def _w(*parts: str) -> Path:
    return _APPDATA.joinpath(*parts)


def _m(*parts: str) -> Path:
    return _MAC_SUPPORT.joinpath(*parts)


def _u(*parts: str) -> Path:
    return _HOME.joinpath(*parts)


_REGISTRY: List[Dict[str, Any]] = [
    {
        "id": "vscode",
        "name": "VS Code",
        "paths": [
            {
                "path": _w("Code", "User", "mcp.json"),
                "key": "servers",
                "scope": "user",
                "confidence": "verified",
                "os": "win",
            },
            {
                "path": _m("Code", "User", "mcp.json"),
                "key": "servers",
                "scope": "user",
                "confidence": "verified",
                "os": "mac",
            },
            {
                "path": _u(".config", "Code", "User", "mcp.json"),
                "key": "servers",
                "scope": "user",
                "confidence": "verified",
                "os": "linux",
            },
            {
                "path": ".vscode/mcp.json",
                "key": "servers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
        ],
    },
    {
        "id": "claude-desktop",
        "name": "Claude Desktop",
        "paths": [
            {
                "path": _w("Claude", "claude_desktop_config.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": "win",
            },
            {
                "path": _m("Claude", "claude_desktop_config.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": "mac",
            },
            {
                "path": _u(".config", "Claude", "claude_desktop_config.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "linux",
            },
        ],
    },
    {
        "id": "claude-code",
        "name": "Claude Code CLI",
        "paths": [
            {"path": _u(".claude.json"), "key": "mcpServers", "scope": "user", "confidence": "verified", "os": None},
            {
                "path": ".mcp.json",
                "key": "mcpServers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
            {
                "path": _m("ClaudeCode", "managed-mcp.json"),
                "key": "mcpServers",
                "scope": "enterprise",
                "confidence": "verified",
                "os": "mac",
            },
            {
                "path": "/etc/claude-code/managed-mcp.json",
                "key": "mcpServers",
                "scope": "enterprise",
                "confidence": "verified",
                "os": "linux",
            },
            {
                "path": r"C:\Program Files\ClaudeCode\managed-mcp.json",
                "key": "mcpServers",
                "scope": "enterprise",
                "confidence": "verified",
                "os": "win",
            },
            {
                "path": r"C:\ProgramData\ClaudeCode\managed-mcp.json",
                "key": "mcpServers",
                "scope": "enterprise",
                "confidence": "verified",
                "os": "win",
            },
        ],
    },
    {
        "id": "cursor",
        "name": "Cursor",
        "paths": [
            {
                "path": _u(".cursor", "mcp.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": ".cursor/mcp.json",
                "key": "mcpServers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
        ],
    },
    {
        "id": "opencode",
        "name": "OpenCode",
        "paths": [
            {
                "path": _u(".config", "opencode", "opencode.json"),
                "key": "mcp",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": "opencode.json",
                "key": "mcp",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
            {
                "path": "opencode.jsonc",
                "key": "mcp",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
        ],
    },
    {
        "id": "gemini-cli",
        "name": "Gemini CLI",
        "paths": [
            {
                "path": _u(".gemini", "settings.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": ".gemini/settings.json",
                "key": "mcpServers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
        ],
    },
    {
        "id": "zed",
        "name": "Zed",
        "paths": [
            {
                "path": _w("Zed", "settings.json"),
                "key": "context_servers",
                "scope": "user",
                "confidence": "ecosystem_verified",
                "os": "win",
            },
            {
                "path": _m("Zed", "settings.json"),
                "key": "context_servers",
                "scope": "user",
                "confidence": "verified",
                "os": "mac",
            },
            {
                "path": _u(".config", "zed", "settings.json"),
                "key": "context_servers",
                "scope": "user",
                "confidence": "verified",
                "os": "linux",
            },
            {
                "path": ".zed/settings.json",
                "key": "context_servers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
        ],
    },
    {
        "id": "cline",
        "name": "Cline",
        "paths": [
            {
                "path": _w(
                    "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "win",
            },
            {
                "path": _m(
                    "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "mac",
            },
            {
                "path": _u(
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                    "cline_mcp_settings.json",
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "linux",
            },
            {
                "path": _u(".cline", "data", "settings", "cline_mcp_settings.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
        ],
    },
    {
        "id": "goose",
        "name": "Goose",
        "paths": [
            {
                "path": _w("Block", "goose", "config", "config.yaml"),
                "key": "extensions",
                "scope": "user",
                "confidence": "verified",
                "os": "win",
                "format": "yaml",
            },
            {
                "path": _u(".config", "goose", "config.yaml"),
                "key": "extensions",
                "scope": "user",
                "confidence": "verified",
                "os": "mac",
                "format": "yaml",
            },
            {
                "path": _u(".config", "goose", "config.yaml"),
                "key": "extensions",
                "scope": "user",
                "confidence": "verified",
                "os": "linux",
                "format": "yaml",
            },
        ],
    },
    {
        "id": "continue",
        "name": "Continue.dev",
        "paths": [
            {
                "path": _u(".continue", "config.yaml"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
                "format": "yaml",
            },
            {
                "path": _u(".continue", "config.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified_legacy",
                "os": None,
            },
            {
                "path": ".continue/mcpServers",
                "key": "__file__",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
                "glob": "*.yaml",
                "format": "yaml",
            },
        ],
    },
    {
        "id": "roo-code",
        "name": "Roo Code",
        "paths": [
            {
                "path": _w(
                    "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": "win",
            },
            {
                "path": _m(
                    "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": "mac",
            },
            {
                "path": _u(
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                    "mcp_settings.json",
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": "linux",
            },
            {
                "path": _w(
                    "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json"
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "win",
            },
            {
                "path": _m(
                    "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json"
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "mac",
            },
            {
                "path": _u(
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                    "cline_mcp_settings.json",
                ),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "linux",
            },
            {
                "path": ".roo/mcp.json",
                "key": "mcpServers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
        ],
    },
    {
        "id": "windsurf",
        "name": "Windsurf",
        "paths": [
            {
                "path": _u(".codeium", "windsurf", "mcp_config.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
        ],
    },
    {
        "id": "amazon-q",
        "name": "Amazon Q",
        "paths": [
            {
                "path": _u(".aws", "amazonq", "mcp.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": _u(".aws", "amazonq", "default.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": _u(".aws", "amazonq", "agents", "default.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": ".amazonq/mcp.json",
                "key": "mcpServers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
            {
                "path": ".amazonq/default.json",
                "key": "mcpServers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
        ],
    },
    {
        "id": "kiro",
        "name": "Kiro",
        "paths": [
            {
                "path": _u(".kiro", "settings", "mcp.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": ".kiro/settings/mcp.json",
                "key": "mcpServers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
        ],
    },
    {
        "id": "github-copilot",
        "name": "GitHub Copilot",
        "paths": [
            {
                "path": _u(".copilot", "mcp-config.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
        ],
    },
    {
        "id": "amp",
        "name": "Amp",
        "paths": [
            {
                "path": _u(".config", "amp", "settings.json"),
                "key": "amp.mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": _u(".config", "amp", "settings.jsonc"),
                "key": "amp.mcpServers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
            },
            {
                "path": ".amp/settings.json",
                "key": "amp.mcpServers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
            },
            {
                "path": _m("ampcode", "managed-settings.json"),
                "key": "amp.mcpServers",
                "scope": "enterprise",
                "confidence": "verified",
                "os": "mac",
            },
            {
                "path": "/etc/ampcode/managed-settings.json",
                "key": "amp.mcpServers",
                "scope": "enterprise",
                "confidence": "verified",
                "os": "linux",
            },
            {
                "path": str(_PROGRAMDATA / "ampcode" / "managed-settings.json"),
                "key": "amp.mcpServers",
                "scope": "enterprise",
                "confidence": "verified",
                "os": "win",
            },
        ],
    },
    {
        "id": "antigravity",
        "name": "Antigravity",
        "paths": [
            {
                "path": _u(".gemini", "antigravity", "mcp_config.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": None,
            },
        ],
    },
    {
        "id": "codex-cli",
        "name": "Codex CLI",
        "paths": [
            {
                "path": _u(".codex", "config.toml"),
                "key": "mcp_servers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
                "format": "toml",
            },
            {
                "path": ".codex/config.toml",
                "key": "mcp_servers",
                "scope": "project",
                "confidence": "verified",
                "os": None,
                "relative": True,
                "format": "toml",
            },
        ],
    },
    {
        "id": "5ire",
        "name": "5ire",
        "paths": [
            {
                "path": _w("5ire", "mcp.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "win",
                "activation_state_only": True,
            },
            {
                "path": _m("5ire", "mcp.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "mac",
                "activation_state_only": True,
            },
            {
                "path": _u(".config", "5ire", "mcp.json"),
                "key": "mcpServers",
                "scope": "user",
                "confidence": "community",
                "os": "linux",
                "activation_state_only": True,
            },
        ],
    },
    {
        "id": "witsy",
        "name": "Witsy",
        "paths": [
            {
                "path": _w("Witsy", "settings.json"),
                "key": "witsy",
                "scope": "user",
                "confidence": "community",
                "os": "win",
            },
            {
                "path": _m("Witsy", "settings.json"),
                "key": "witsy",
                "scope": "user",
                "confidence": "community",
                "os": "mac",
            },
            {
                "path": _u(".config", "Witsy", "settings.json"),
                "key": "witsy",
                "scope": "user",
                "confidence": "community",
                "os": "linux",
            },
        ],
    },
    {
        "id": "docker-desktop-mcp",
        "name": "Docker Desktop MCP Toolkit",
        "paths": [
            {
                "path": _u(".docker", "mcp", "catalogs", "docker-mcp.yaml"),
                "key": "servers",
                "scope": "user",
                "confidence": "verified",
                "os": None,
                "format": "yaml",
                "activation_state_only": True,
            },
        ],
    },
]


_MCP_IMAGE_PREFIXES = (
    "mcp/",
    "mcp-server",
    "modelcontextprotocol/",
    "ghcr.io/github/github-mcp-server",
)
_MCP_CMD_RE = re.compile(
    r"@modelcontextprotocol/|mcp-server[-_]|\bmcp\b.{0,30}server|uvx\s+mcp|python\s+-m\s+mcp",
    re.IGNORECASE,
)
_MCP_ENV_PREFIXES = ("MCP_", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
_COMPOSE_FILENAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
_DYNAMIC_FILENAMES = frozenset({"mcp.json", ".mcp.json", "mcp-config.json", "mcp-servers.json"})
_DYNAMIC_MAX_DEPTH = 3
_DYNAMIC_MAX_FILE_BYTES = 256 * 1024
_DYNAMIC_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        ".gradle",
        ".tox",
    }
)


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def _strip_jsonc(text: str) -> str:
    result: list = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == '"':
            result.append(text[i])
            i += 1
            while i < n:
                c = text[i]
                result.append(c)
                i += 1
                if c == "\\" and i < n:
                    result.append(text[i])
                    i += 1
                elif c == '"':
                    break
        elif text[i : i + 2] == "//":
            while i < n and text[i] != "\n":
                i += 1
        elif text[i : i + 2] == "/*":
            i += 2
            while i < n and text[i : i + 2] != "*/":
                i += 1
            i += 2
        else:
            result.append(text[i])
            i += 1
    return "".join(result)


def _parse_json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return json.loads(_strip_jsonc(text))
        except Exception:
            return None


def _parse_yaml(text: str) -> Any:
    try:
        import yaml

        return yaml.safe_load(text) or {}
    except ImportError:
        _log.debug("discovery: PyYAML not installed, cannot parse YAML config")
        return None
    except Exception as exc:
        _log.debug("discovery: YAML parse error: %s", exc)
        return None


def _parse_toml(path: Path) -> Any:
    try:
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                _log.debug("discovery: no TOML library available (tomllib/tomli)")
                return None
        return tomllib.loads(path.read_bytes().decode("utf-8", errors="replace"))
    except Exception as exc:
        _log.debug("discovery: TOML parse error %s: %s", path, exc)
        return None


def _extract_servers(data: Any, key: str) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}

    if key == "amp.mcpServers":
        amp = data.get("amp") or {}
        servers = amp.get("mcpServers") if isinstance(amp, dict) else None
        return servers if isinstance(servers, dict) else {}

    if key == "witsy":
        result: Dict[str, Any] = {}
        top = data.get("mcpServers") or {}
        if isinstance(top, dict):
            result.update(top)
        mcp_block = data.get("mcp") or {}
        if isinstance(mcp_block, dict):
            arr = mcp_block.get("servers") or []
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict) and item.get("name"):
                        result.setdefault(item["name"], item)
        return result

    if key == "extensions":
        items = data.get("extensions") or []
        if not isinstance(items, list):
            return {}
        out: Dict[str, Any] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name:
                continue
            t = item.get("type", "stdio")
            if t == "builtin":
                continue
            if item.get("enabled") is False:
                continue
            out[name] = item
        return out

    if key == "__file__":
        if isinstance(data, dict) and (data.get("command") or data.get("url") or data.get("cmd")):
            name = str(data.get("name") or "server")
            return {name: data}
        return {}

    if "." in key:
        head, _, tail = key.partition(".")
        nested = data.get(head)
        return _extract_servers(nested, tail) if isinstance(nested, dict) else {}

    val = data.get(key)
    if isinstance(val, dict):
        return val
    if isinstance(val, list):
        out2: Dict[str, Any] = {}
        for item in val:
            if isinstance(item, dict) and item.get("name"):
                out2[item["name"]] = item
        return out2
    return {}


def _normalize_entry(
    client_id: str,
    client_name: str,
    server_name: str,
    raw: Any,
    config_path: str,
    scope: str,
    confidence: str,
    activation_state_only: bool,
) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None

    command_raw = raw.get("command") or raw.get("cmd")
    url = raw.get("url") or raw.get("serverUrl")

    if isinstance(command_raw, dict):
        command = command_raw.get("path") or command_raw.get("cmd")
        raw_args = command_raw.get("args")
        env_raw = command_raw.get("env")
        env: Dict[str, str] = {str(k): str(v) for k, v in env_raw.items()} if isinstance(env_raw, dict) else {}
    else:
        command = str(command_raw) if command_raw is not None else None
        raw_args = raw.get("args")
        env_raw = raw.get("env") or raw.get("envs")
        env = {str(k): str(v) for k, v in env_raw.items()} if isinstance(env_raw, dict) else {}

    args = [raw_args] if isinstance(raw_args, str) else (list(raw_args) if isinstance(raw_args, list) else [])
    headers_raw = raw.get("headers")
    headers: Dict[str, str] = {str(k): str(v) for k, v in headers_raw.items()} if isinstance(headers_raw, dict) else {}

    if not command and not url:
        image = raw.get("image")
        if image:
            command = "docker"
            args = ["run", "--rm", "-i", str(image)]
        elif not activation_state_only:
            return None

    raw_type = raw.get("type") or raw.get("transport") or ""
    if url:
        transport = "sse" if raw_type.lower() == "sse" else "streamable_http"
    else:
        transport = "stdio"

    discovery_id = f"{client_id}:{scope}:{server_name}"

    return {
        "discovery_id": discovery_id,
        "client": client_id,
        "client_name": client_name,
        "scope": scope,
        "config_path": config_path,
        "server_name": server_name,
        "transport": transport,
        "command": command,
        "args": args,
        "url": url,
        "env": env,
        "env_keys": sorted(env.keys()),
        "headers": headers,
        "headers_keys": sorted(headers.keys()),
        "confidence": confidence,
        "activation_state_only": activation_state_only,
    }


def make_server_id(client_id: str, server_name: str) -> str:
    safe_client = re.sub(r"[^a-zA-Z0-9_]", "_", client_id)
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", server_name)
    sid = f"{safe_client}__{safe_name}"
    return sid[:256]


def _make_infra_entry(
    client_id: str,
    client_name: str,
    server_name: str,
    transport: str,
    command: Optional[str],
    args: List[str],
    url: Optional[str],
    env: Dict[str, str],
    config_path: str,
    scope: str,
    confidence: str,
    registered_server_ids: Optional[Set[str]],
) -> Dict[str, Any]:
    suggested_id = make_server_id(client_id, server_name)
    return {
        "discovery_id": f"{client_id}:{scope}:{server_name}",
        "client": client_id,
        "client_name": client_name,
        "scope": scope,
        "config_path": config_path,
        "server_name": server_name,
        "transport": transport,
        "command": command,
        "args": args,
        "url": url,
        "env": env,
        "env_keys": sorted(env.keys()),
        "headers": {},
        "headers_keys": [],
        "confidence": confidence,
        "activation_state_only": False,
        "suggested_server_id": suggested_id,
        "registered": suggested_id in registered_server_ids if registered_server_ids is not None else False,
    }


def _discover_compose(cwd: Path, registered_server_ids: Optional[Set[str]]) -> List[Dict[str, Any]]:
    for filename in _COMPOSE_FILENAMES:
        compose_path = cwd / filename
        if not compose_path.exists():
            continue
        text = _read_text(compose_path)
        if not text:
            continue
        data = _parse_yaml(text)
        if not isinstance(data, dict):
            continue
        services = data.get("services") or {}
        if not isinstance(services, dict):
            break
        results: List[Dict[str, Any]] = []
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            image = svc.get("image") or ""
            cmd_parts = svc.get("command") or svc.get("entrypoint") or []
            if isinstance(cmd_parts, str):
                cmd_parts = cmd_parts.split()
            cmd_str = " ".join(str(c) for c in cmd_parts)
            env_raw = svc.get("environment") or {}
            if isinstance(env_raw, list):
                env: Dict[str, str] = {}
                for item in env_raw:
                    if isinstance(item, str) and "=" in item:
                        k, _, v = item.partition("=")
                        env[k] = v
            elif isinstance(env_raw, dict):
                env = {str(k): str(v) for k, v in env_raw.items() if v is not None}
            else:
                env = {}
            is_mcp = (
                any(image.lower().startswith(p) for p in _MCP_IMAGE_PREFIXES)
                or bool(_MCP_CMD_RE.search(cmd_str))
                or any(k.startswith("MCP_") for k in env)
            )
            if not is_mcp:
                continue
            ports = svc.get("ports") or []
            url: Optional[str] = None
            if ports:
                first = ports[0]
                if isinstance(first, str) and ":" in first:
                    url = f"http://localhost:{first.split(':')[0]}/mcp"
                elif isinstance(first, int):
                    url = f"http://localhost:{first}/mcp"
            transport = "streamable_http" if url else "stdio"
            command: Optional[str] = None
            svc_args: List[str] = []
            if not url and cmd_parts:
                command = str(cmd_parts[0])
                svc_args = [str(c) for c in cmd_parts[1:]]
            elif not url and not cmd_parts and image:
                command = "docker"
                svc_args = ["run", "--rm", "-i", image]
            results.append(
                _make_infra_entry(
                    "docker-compose",
                    "Docker Compose",
                    svc_name,
                    transport,
                    command,
                    svc_args,
                    url,
                    env,
                    str(compose_path),
                    "project",
                    "inferred",
                    registered_server_ids,
                )
            )
        return results
    return []


def _process_server_name(cmdline: List[Any]) -> str:
    cmd_str = " ".join(str(c) for c in cmdline)
    m = re.search(r"@modelcontextprotocol/([\w-]+)", cmd_str)
    if m:
        return m.group(1)
    m = re.search(r"mcp[-_]server[-_]([\w-]+)", cmd_str, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"uvx\s+(mcp[\w-]+)", cmd_str, re.IGNORECASE)
    if m:
        return m.group(1)
    return Path(str(cmdline[0])).stem or "unknown"


def _discover_processes(registered_server_ids: Optional[Set[str]]) -> List[Dict[str, Any]]:
    try:
        import psutil  # type: ignore
    except ImportError:
        return []
    results: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmdline = proc.info.get("cmdline") or []
            if not cmdline:
                continue
            cmd_str = " ".join(str(c) for c in cmdline)
            if not _MCP_CMD_RE.search(cmd_str):
                continue
            norm = " ".join(str(c) for c in cmdline[:6])
            if norm in seen:
                continue
            seen.add(norm)
            transport = "stdio"
            url: Optional[str] = None
            for i, arg in enumerate(cmdline):
                if str(arg) == "--transport" and i + 1 < len(cmdline):
                    t = str(cmdline[i + 1])
                    if t in ("sse", "streamable_http"):
                        transport = t
                elif str(arg).startswith("--port="):
                    url = f"http://localhost:{str(arg).split('=', 1)[1]}/mcp"
                    transport = "streamable_http"
                elif str(arg) == "--port" and i + 1 < len(cmdline):
                    url = f"http://localhost:{cmdline[i + 1]}/mcp"
                    transport = "streamable_http"
            try:
                raw_env = proc.environ() or {}
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                raw_env = {}
            env = {k: v for k, v in raw_env.items() if any(k.startswith(p) for p in _MCP_ENV_PREFIXES)}
            server_name = _process_server_name(cmdline)
            results.append(
                _make_infra_entry(
                    "process",
                    "Running Process",
                    server_name,
                    transport,
                    str(cmdline[0]) if not url else None,
                    [str(c) for c in cmdline[1:]] if not url else [],
                    url,
                    env,
                    f"pid:{proc.info['pid']}",
                    "runtime",
                    "inferred",
                    registered_server_ids,
                )
            )
        except Exception:
            continue
    return results


def _discover_docker_containers(registered_server_ids: Optional[Set[str]]) -> List[Dict[str, Any]]:
    try:
        ids_result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if ids_result.returncode != 0 or not ids_result.stdout.strip():
            return []
    except Exception:
        return []
    container_ids = ids_result.stdout.strip().splitlines()
    try:
        inspect_result = subprocess.run(
            ["docker", "inspect"] + container_ids,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if inspect_result.returncode != 0:
            return []
        inspected = json.loads(inspect_result.stdout)
    except Exception as exc:
        _log.debug("discovery: docker inspect failed: %s", exc)
        return []
    results: List[Dict[str, Any]] = []
    for container in inspected:
        try:
            cfg = container.get("Config") or {}
            image = cfg.get("Image") or ""
            labels = cfg.get("Labels") or {}
            cmd = cfg.get("Cmd") or []
            entrypoint = cfg.get("Entrypoint") or []
            env_list = cfg.get("Env") or []
            name = (container.get("Name") or "").lstrip("/")
            cmd_str = " ".join(str(c) for c in (entrypoint + cmd))
            env: Dict[str, str] = {}
            for item in env_list:
                if isinstance(item, str) and "=" in item:
                    k, _, v = item.partition("=")
                    if k.startswith("MCP_") or any(k.startswith(p) for p in _MCP_ENV_PREFIXES):
                        env[k] = v
            is_mcp = (
                any(image.lower().startswith(p) for p in _MCP_IMAGE_PREFIXES)
                or any("mcp" in str(v).lower() for v in labels.values())
                or any("mcp" in k.lower() for k in labels)
                or bool(_MCP_CMD_RE.search(cmd_str))
                or bool(env)
            )
            if not is_mcp:
                continue
            ports = (container.get("NetworkSettings") or {}).get("Ports") or {}
            url: Optional[str] = None
            for bindings in ports.values():
                if bindings:
                    host_port = bindings[0].get("HostPort")
                    if host_port:
                        url = f"http://localhost:{host_port}/mcp"
                        break
            transport = "streamable_http" if url else "stdio"
            server_name = name or image.split("/")[-1].split(":")[0]
            results.append(
                _make_infra_entry(
                    "docker",
                    "Docker Container",
                    server_name,
                    transport,
                    None,
                    [],
                    url,
                    env,
                    f"container:{(container.get('Id') or '')[:12]}",
                    "runtime",
                    "inferred",
                    registered_server_ids,
                )
            )
        except Exception as exc:
            _log.debug("discovery: container parse error: %s", exc)
    return results


def _discover_dynamic(cwd: Path, registered_server_ids: Optional[Set[str]]) -> List[Dict[str, Any]]:
    candidates: List[Path] = []
    seen_paths: Set[str] = set()

    def _scan(base: Path, depth: int) -> None:
        if depth > _DYNAMIC_MAX_DEPTH:
            return
        try:
            for entry in base.iterdir():
                if entry.is_dir() and entry.name not in _DYNAMIC_SKIP_DIRS:
                    _scan(entry, depth + 1)
                elif entry.is_file() and (
                    entry.name in _DYNAMIC_FILENAMES or (entry.suffix == ".json" and "mcp" in entry.stem.lower())
                ):
                    candidates.append(entry)
        except PermissionError:
            pass

    _scan(cwd, 0)

    for key, val in os.environ.items():
        if any(key.startswith(p) for p in ("MCP_CONFIG", "MCP_SERVERS", "CLAUDE_MCP", "CURSOR_MCP")) and val:
            p = Path(val)
            if p.exists() and p.is_file():
                candidates.append(p)

    results: List[Dict[str, Any]] = []
    for f in candidates:
        path_str = str(f.resolve())
        if path_str in seen_paths:
            continue
        seen_paths.add(path_str)
        try:
            if f.stat().st_size > _DYNAMIC_MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read_text(f)
        if not text:
            continue
        data = _parse_json(text)
        if not isinstance(data, dict):
            continue
        for key in ("mcpServers", "mcp_servers", "servers", "context_servers"):
            for sname, entry in _extract_servers(data, key).items():
                norm = _normalize_entry(
                    "dynamic",
                    "Config File",
                    sname,
                    entry,
                    path_str,
                    "project",
                    "inferred",
                    False,
                )
                if norm is None:
                    continue
                suggested_id = make_server_id("dynamic", sname)
                norm["suggested_server_id"] = suggested_id
                norm["registered"] = (
                    suggested_id in registered_server_ids if registered_server_ids is not None else False
                )
                results.append(norm)
    return results


def _load_path(
    path_def: Dict[str, Any],
    cwd: Path,
    include_community: bool,
) -> List[Dict[str, Any]]:
    """Load and parse a single path definition, returning raw server entries."""
    confidence = path_def.get("confidence", "community")
    if not include_community and confidence in ("community",):
        return []

    os_filter = path_def.get("os")
    if os_filter is not None and os_filter != _CURRENT_OS:
        return []

    is_relative = path_def.get("relative", False)
    glob_pattern = path_def.get("glob")
    fmt = path_def.get("format", "json")
    key = path_def["key"]

    raw_path = path_def["path"]

    if is_relative:
        base = cwd / str(raw_path)
        if glob_pattern:
            files = list(base.glob(glob_pattern)) if base.is_dir() else []
        else:
            files = [base] if base.exists() else []
    else:
        p = raw_path if isinstance(raw_path, Path) else Path(str(raw_path))
        files = [p] if p.exists() else []

    results = []
    for f in files:
        if fmt == "yaml":
            text = _read_text(f)
            if text is None:
                continue
            data = _parse_yaml(text)
        elif fmt == "toml":
            data = _parse_toml(f)
        else:
            text = _read_text(f)
            if text is None:
                continue
            data = _parse_json(text)

        if data is None:
            _log.debug("Config file %s yielded no parseable data; skipping.", f)
            continue

        servers_map = _extract_servers(data, key)
        for name, entry in servers_map.items():
            if key == "__file__" and not (isinstance(entry, dict) and entry.get("name")):
                name = f.stem
            results.append(
                {
                    "server_name": name,
                    "entry": entry,
                    "config_path": str(f),
                    "scope": path_def["scope"],
                    "confidence": confidence,
                    "activation_state_only": path_def.get("activation_state_only", False),
                }
            )

    return results


def discover_mcp_servers(
    client_filter: Optional[str] = None,
    include_project: bool = True,
    include_community: bool = True,
    cwd: Optional[Path] = None,
    registered_server_ids: Optional[Set[str]] = None,
    include_compose: bool = True,
    include_dynamic: bool = True,
    include_processes: bool = False,
    include_containers: bool = False,
) -> List[Dict[str, Any]]:
    if cwd is None:
        cwd = Path.cwd()

    seen: Dict[str, Dict[str, Any]] = {}

    for client in _REGISTRY:
        cid = client["id"]
        if client_filter and cid != client_filter:
            continue

        for path_def in client["paths"]:
            scope = path_def.get("scope", "user")
            if scope == "project" and not include_project:
                continue

            raw_entries = _load_path(path_def, cwd, include_community)
            for raw in raw_entries:
                normalised = _normalize_entry(
                    client_id=cid,
                    client_name=client["name"],
                    server_name=raw["server_name"],
                    raw=raw["entry"],
                    config_path=raw["config_path"],
                    scope=raw["scope"],
                    confidence=raw["confidence"],
                    activation_state_only=raw["activation_state_only"],
                )
                if normalised is None:
                    continue

                did = normalised["discovery_id"]
                if did not in seen:
                    suggested_id = make_server_id(cid, raw["server_name"])
                    normalised["suggested_server_id"] = suggested_id
                    normalised["registered"] = (
                        suggested_id in registered_server_ids if registered_server_ids is not None else False
                    )
                    seen[did] = normalised

    if include_compose:
        for entry in _discover_compose(cwd, registered_server_ids):
            seen.setdefault(entry["discovery_id"], entry)

    if include_dynamic:
        for entry in _discover_dynamic(cwd, registered_server_ids):
            seen.setdefault(entry["discovery_id"], entry)

    if include_processes:
        for entry in _discover_processes(registered_server_ids):
            seen.setdefault(entry["discovery_id"], entry)

    if include_containers:
        for entry in _discover_docker_containers(registered_server_ids):
            seen.setdefault(entry["discovery_id"], entry)

    return list(seen.values())
