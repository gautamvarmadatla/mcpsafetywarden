"""Source code reconnaissance for MCP servers.

Stage 0b: fetches source from GitHub and runs up to 6 analysis layers:
  L1  Shannon entropy + known secret-format detection (Python AST + TypeScript regex)
  L2  Static analysis: import capabilities, taint flows, dangerous sinks (Python AST / TypeScript regex)
  L3  Description vs implementation mismatch (read-only claims vs write/exec sinks)
  RP  SHA-256 rug-pull detection (stored in DB, alerts on hash change)
  L4  Bandit SAST via subprocess (Python only; optional)
  L5  Semgrep taint analysis via subprocess (Python + TypeScript; optional)
  L6  LLM false-positive reduction and cross-function reasoning (optional)

Supported languages: Python (.py) and TypeScript/JavaScript (.ts, .tsx, .js, .jsx).

All layers are non-fatal. Total budget is enforced by a 150-second wait_for in the caller.
"""

import ast
import asyncio
import hashlib
import json
import logging
import math
import os
import re
import shutil
import stat
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from . import database as db
from .security_utils import _SENSITIVE_KEY_RE, sanitise_for_prompt, strip_json_fence

_log = logging.getLogger(__name__)

_MAX_FILES = 40
_MAX_FILE_BYTES = 50 * 1024
_GITHUB_FETCH_TIMEOUT = 60
_BANDIT_TIMEOUT = 30
_SEMGREP_TIMEOUT = 45
_LLM_TIMEOUT = 30

_EXCLUDE_PATH_RE = re.compile(
    r"(tests?[_/]|spec[s_/]|docs?/|\.github/|migrations?[_/]|venv/|\.venv/|__pycache__/|"
    r"setup\.py$|conf(?:ig)?\.py$|examples?/|fixtures?/)",
    re.IGNORECASE,
)

_PRIORITY_NAMES = frozenset({
    "server.py", "main.py", "core.py", "middleware.py", "app.py",
    "handler.py", "router.py", "proxy.py", "gateway.py", "agent.py",
    "tools.py", "tool.py", "commands.py", "command.py",
    "server.ts", "main.ts", "core.ts", "middleware.ts", "app.ts",
    "handler.ts", "router.ts", "proxy.ts", "gateway.ts", "agent.ts",
    "tools.ts", "tool.ts", "index.ts", "index.js",
    "server.js", "main.js", "app.js",
})
_DEPRIORITY_NAMES = frozenset({"__init__.py", "__main__.py", "types.ts", "types.js"})

_PY_EXTS = frozenset({".py"})
_TS_EXTS = frozenset({".ts", ".tsx", ".js", ".jsx"})

_TS_EXCLUDE_PATH_RE = re.compile(
    r"(node_modules/|dist/|build/|\.next/|out/|coverage/|\.d\.ts$|"
    r"\.min\.[jt]sx?$|__tests__/|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|\.stories\.[jt]sx?$)",
    re.IGNORECASE,
)

_TS_CAPABILITY_IMPORTS: Dict[str, str] = {
    "child_process": "shell_exec",
    "shelljs": "shell_exec",
    "execa": "shell_exec",
    "cross-spawn": "shell_exec",
    "fs": "file_ops",
    "fs/promises": "file_ops",
    "path": "file_ops",
    "glob": "file_ops",
    "axios": "outbound_http",
    "node-fetch": "outbound_http",
    "got": "outbound_http",
    "superagent": "outbound_http",
    "undici": "outbound_http",
    "https": "outbound_network",
    "http": "outbound_network",
    "http2": "outbound_network",
    "net": "outbound_network",
    "tls": "outbound_network",
    "ssh2": "ssh_access",
    "sqlite3": "database",
    "better-sqlite3": "database",
    "pg": "database",
    "mysql2": "database",
    "mongodb": "database",
    "mongoose": "database",
    "redis": "database",
    "ioredis": "database",
    "aws-sdk": "cloud_access",
    "@aws-sdk/": "cloud_access",
    "@google-cloud/": "cloud_access",
    "@azure/": "cloud_access",
    "jsonwebtoken": "auth",
    "passport": "auth",
    "dockerode": "container_access",
    "@modelcontextprotocol/sdk": "mcp_framework",
    "fastmcp": "mcp_framework",
    "crypto": "crypto",
    "bcrypt": "crypto",
    "bcryptjs": "crypto",
}

_TS_DANGEROUS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\('), "shell_exec"),
    (re.compile(r'\beval\s*\('), "code_eval"),
    (re.compile(r'\bnew\s+Function\s*\('), "code_eval"),
    (re.compile(r'\bvm\.(?:runIn|compile|Script)\b'), "code_eval"),
    (re.compile(r'\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\('), "file_write"),
    (re.compile(r'\b(?:unlink|unlinkSync|rmdir|rmdirSync|rm)\s*\('), "file_delete"),
    (re.compile(r'\bdeserialize\s*\('), "deserialization"),
]

_TS_IMPORT_RE = re.compile(
    r"""(?:^[ \t]*import\s+[\s\S]*?from\s+['"]([@\w/.\-]+)['"]|(?:require|import)\s*\(\s*['"]([@\w/.\-]+)['"]\s*\))""",
    re.MULTILINE,
)
_TS_MCP_TOOL_RE = re.compile(r"""(?:server\.tool|\.tool)\s*\(\s*['"]([\w\-]+)['"]""")
_TS_FUNC_RE = re.compile(
    r"""(?:(?:async\s+)?function\s+(\w+)\s*\(|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\()"""
)
_TS_STRING_RE = re.compile(r"""(?:"(?:[^"\n\\]|\\.)*"|'(?:[^'\n\\]|\\.)*')""")

_CAPABILITY_IMPORTS: Dict[str, str] = {
    "subprocess": "shell_exec",
    "shutil": "file_ops",
    "pathlib": "file_ops",
    "socket": "outbound_network",
    "ssl": "outbound_network",
    "httpx": "outbound_http",
    "requests": "outbound_http",
    "urllib": "outbound_http",
    "aiohttp": "outbound_http",
    "paramiko": "ssh_access",
    "fabric": "ssh_access",
    "sqlite3": "database",
    "sqlalchemy": "database",
    "psycopg2": "database",
    "pymongo": "database",
    "redis": "database",
    "boto3": "cloud_access",
    "botocore": "cloud_access",
    "azure": "cloud_access",
    "google.cloud": "cloud_access",
    "pickle": "deserialization",
    "marshal": "deserialization",
    "dill": "deserialization",
    "cryptography": "crypto",
    "jwt": "auth",
    "docker": "container_access",
    "kubernetes": "container_access",
    "smtplib": "email_access",
    "ftplib": "ftp_access",
    "mcp": "mcp_framework",
    "os": "file_ops",
}

_DANGEROUS_SINK_MAP: Dict[Tuple[str, str], str] = {
    ("subprocess", "run"): "shell_exec",
    ("subprocess", "call"): "shell_exec",
    ("subprocess", "Popen"): "shell_exec",
    ("subprocess", "check_output"): "shell_exec",
    ("subprocess", "check_call"): "shell_exec",
    ("os", "system"): "shell_exec",
    ("os", "popen"): "shell_exec",
    ("os", "execv"): "shell_exec",
    ("os", "execve"): "shell_exec",
    ("os", "execvp"): "shell_exec",
    ("builtins", "eval"): "code_eval",
    ("builtins", "exec"): "code_eval",
    ("builtins", "open"): "file_open",
    ("pickle", "loads"): "deserialization",
    ("pickle", "load"): "deserialization",
    ("marshal", "loads"): "deserialization",
    ("yaml", "load"): "yaml_load",
    ("requests", "get"): "outbound_http",
    ("requests", "post"): "outbound_http",
    ("requests", "put"): "outbound_http",
    ("requests", "delete"): "outbound_http",
    ("httpx", "get"): "outbound_http",
    ("httpx", "post"): "outbound_http",
    ("httpx", "put"): "outbound_http",
    ("socket", "connect"): "outbound_network",
    ("shutil", "rmtree"): "file_delete",
    ("os", "remove"): "file_delete",
    ("os", "unlink"): "file_delete",
    ("os", "rmdir"): "file_delete",
}

_KNOWN_SECRET_FORMATS = [
    re.compile(r"^eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$"),
    re.compile(r"^sk-ant-[A-Za-z0-9\-_]{20,}$"),
    re.compile(r"^sk-[A-Za-z0-9]{20,}$"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^ghp_[A-Za-z0-9]{36}$"),
    re.compile(r"^xox[bporas]-[A-Za-z0-9\-]{10,}$"),
    re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----"),
]

_ENTROPY_THRESHOLD = 4.5
_MIN_SECRET_LEN = 20


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def _detect_github_url(
    server_config: Dict[str, Any],
    github_url: Optional[str],
) -> Optional[str]:
    if github_url:
        return github_url
    for key in ("github_url", "source_url", "repo_url"):
        val = server_config.get(key)
        if val and "github.com" in str(val):
            return val
    return None


async def _detect_github_url_from_pypi(server_config: Dict[str, Any]) -> Optional[str]:
    args = server_config.get("args") or []
    candidates = [
        a for a in args
        if isinstance(a, str) and re.match(r"^[a-z0-9][a-z0-9\-_.]+$", a, re.IGNORECASE)
    ]
    if not candidates:
        return None
    async with httpx.AsyncClient(timeout=10) as client:
        for pkg in candidates[:3]:
            try:
                resp = await client.get(f"https://pypi.org/pypi/{pkg}/json")
                if resp.status_code != 200:
                    continue
                info = resp.json().get("info", {})
                for url in (info.get("project_urls") or {}).values():
                    if "github.com" in (url or ""):
                        return url
                home = info.get("home_page") or ""
                if "github.com" in home:
                    return home
            except Exception:
                pass
    return None


def _parse_github_owner_repo(url: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"https?://github\.com/([^/]+)/([^/\s#?]+)", url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    repo = re.sub(r"\.git$", "", repo)
    return owner, repo


def _file_priority(path: str, size: int) -> tuple:
    """Lower tuple = higher fetch priority."""
    depth = path.count("/")
    name = os.path.basename(path)
    name_tier = -1 if name in _PRIORITY_NAMES else (1 if name in _DEPRIORITY_NAMES else 0)
    return (depth, name_tier, -size)


async def _fetch_source_files(owner: str, repo: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    api_headers: Dict[str, str] = {"Accept": "application/vnd.github+json"}
    if gh_token:
        api_headers["Authorization"] = f"Bearer {gh_token}"
    async with httpx.AsyncClient(timeout=_GITHUB_FETCH_TIMEOUT) as client:
        try:
            tree_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD",
                params={"recursive": "1"},
                headers=api_headers,
            )
            if tree_resp.status_code != 200:
                return result
            tree_data = tree_resp.json()
            if tree_data.get("truncated"):
                _log.warning(
                    "GitHub tree response truncated for %s/%s - large repo, some files may be missed",
                    owner, repo,
                )
        except Exception as exc:
            _log.debug("GitHub tree fetch failed for %s/%s: %s", owner, repo, exc)
            return result

        candidates = []
        for item in tree_data.get("tree", []):
            if item.get("type") != "blob":
                continue
            path = item["path"]
            ext = os.path.splitext(path)[1].lower()
            if item.get("size", 0) > _MAX_FILE_BYTES:
                continue
            if ext in _PY_EXTS and not _EXCLUDE_PATH_RE.search(path):
                candidates.append(item)
            elif ext in _TS_EXTS and not _EXCLUDE_PATH_RE.search(path) and not _TS_EXCLUDE_PATH_RE.search(path):
                candidates.append(item)

        candidates.sort(key=lambda item: _file_priority(item["path"], item.get("size", 0)))

        raw_headers = {"Authorization": f"Bearer {gh_token}"} if gh_token else {}
        for item in candidates[:_MAX_FILES]:
            path = item["path"]
            try:
                raw_resp = await client.get(
                    f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}",
                    headers=raw_headers,
                )
                if raw_resp.status_code == 200:
                    content = raw_resp.text
                    if len(content.encode()) <= _MAX_FILE_BYTES:
                        result[path] = content
            except Exception as exc:
                _log.debug("Failed to fetch %s: %s", path, exc)

    return result


def _entropy_secret_scan(source_files: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path, content in source_files.items():
        try:
            tree = ast.parse(content, filename=path)
        except SyntaxError:
            continue

        parent_map: Dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parent_map[id(child)] = node

        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            s = node.value
            if len(s) < _MIN_SECRET_LEN:
                continue

            matched_pattern = False
            for pattern in _KNOWN_SECRET_FORMATS:
                if pattern.search(s):
                    findings.append({
                        "layer": "entropy",
                        "name": "hardcoded_secret_pattern",
                        "finding": f"Known secret format detected in {path}:{getattr(node, 'lineno', '?')}",
                        "severity": "HIGH",
                        "file": path,
                        "lineno": getattr(node, "lineno", 0),
                    })
                    matched_pattern = True
                    break

            if not matched_pattern:
                entropy = _shannon_entropy(s)
                if entropy >= _ENTROPY_THRESHOLD:
                    parent = parent_map.get(id(node))
                    var_name = ""
                    if isinstance(parent, ast.Assign):
                        for t in parent.targets:
                            if isinstance(t, ast.Name):
                                var_name = t.id
                            elif isinstance(t, ast.Attribute):
                                var_name = t.attr
                    elif isinstance(parent, ast.keyword):
                        var_name = parent.arg or ""
                    if var_name and _SENSITIVE_KEY_RE.search(var_name):
                        findings.append({
                            "layer": "entropy",
                            "name": "high_entropy_secret",
                            "finding": (
                                f"High-entropy value (entropy={entropy:.1f}) assigned to "
                                f"sensitive name '{var_name}' in {path}:{getattr(node, 'lineno', '?')}"
                            ),
                            "severity": "MEDIUM",
                            "file": path,
                            "lineno": getattr(node, "lineno", 0),
                        })
    return findings


def _ts_entropy_scan(source_files: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path, content in source_files.items():
        if os.path.splitext(path)[1].lower() not in _TS_EXTS:
            continue
        for m in _TS_STRING_RE.finditer(content):
            s = m.group(0)[1:-1]
            if len(s) < _MIN_SECRET_LEN:
                continue
            lineno = content[:m.start()].count("\n") + 1
            matched = False
            for pattern in _KNOWN_SECRET_FORMATS:
                if pattern.search(s):
                    findings.append({
                        "layer": "entropy",
                        "name": "hardcoded_secret_pattern",
                        "finding": f"Known secret format detected in {path}:{lineno}",
                        "severity": "HIGH",
                        "file": path,
                        "lineno": lineno,
                    })
                    matched = True
                    break
            if not matched:
                entropy = _shannon_entropy(s)
                if entropy >= _ENTROPY_THRESHOLD:
                    preceding = content[max(0, m.start() - 100):m.start()]
                    vm = re.search(r'(?:const|let|var)\s+(\w+)\s*[=:]\s*$', preceding.rstrip())
                    var_name = vm.group(1) if vm else ""
                    if var_name and _SENSITIVE_KEY_RE.search(var_name):
                        findings.append({
                            "layer": "entropy",
                            "name": "high_entropy_secret",
                            "finding": (
                                f"High-entropy value (entropy={entropy:.1f}) assigned to "
                                f"sensitive name '{var_name}' in {path}:{lineno}"
                            ),
                            "severity": "MEDIUM",
                            "file": path,
                            "lineno": lineno,
                        })
    return findings


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self._imports: Dict[str, Tuple[str, Optional[str]]] = {}
        self.import_capabilities: Set[str] = set()
        self.dangerous_sinks: List[Dict[str, Any]] = []
        self.taint_flows: List[Dict[str, Any]] = []
        self.mcp_tool_functions: List[str] = []

        self._current_func: Optional[str] = None
        self._current_params: Set[str] = set()
        self._tainted_vars: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".")[0]
            self._imports[local_name] = (alias.name, None)
            cap = self._mod_capability(alias.name)
            if cap:
                self.import_capabilities.add(cap)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local_name = alias.asname or alias.name
            self._imports[local_name] = (module, alias.name)
        cap = self._mod_capability(module)
        if cap:
            self.import_capabilities.add(cap)
        self.generic_visit(node)

    def _mod_capability(self, module: str) -> Optional[str]:
        for key, cap in _CAPABILITY_IMPORTS.items():
            if module == key or module.startswith(key + "."):
                return cap
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        saved_func = self._current_func
        saved_params = self._current_params
        saved_tainted = self._tainted_vars

        is_mcp_tool = False
        for deco in node.decorator_list:
            try:
                deco_str = ast.unparse(deco)
                if ".tool" in deco_str or deco_str in ("tool", "mcp_tool"):
                    is_mcp_tool = True
                    break
            except Exception:
                pass

        if is_mcp_tool and node.name not in self.mcp_tool_functions:
            self.mcp_tool_functions.append(node.name)

        self._current_func = node.name
        params: Set[str] = set()
        for arg in (node.args.args + node.args.posonlyargs + node.args.kwonlyargs):
            if arg.arg not in ("self", "cls"):
                params.add(arg.arg)
        if node.args.vararg:
            params.add(node.args.vararg.arg)
        if node.args.kwarg:
            params.add(node.args.kwarg.arg)
        self._current_params = params
        self._tainted_vars = set(params)

        self.generic_visit(node)

        self._current_func = saved_func
        self._current_params = saved_params
        self._tainted_vars = saved_tainted

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._current_func and self._tainted_vars:
            rhs_names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
            if rhs_names & self._tainted_vars:
                for target in node.targets:
                    for name_node in ast.walk(target):
                        if isinstance(name_node, ast.Name):
                            self._tainted_vars.add(name_node.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink_type = self._sink_type(node.func)
        if sink_type:
            lineno = getattr(node, "lineno", 0)
            func_ctx = self._current_func or "<module>"

            if sink_type == "yaml_load":
                safe = False
                for kw in node.keywords:
                    if kw.arg == "Loader" and kw.value:
                        try:
                            if "Safe" in ast.unparse(kw.value):
                                safe = True
                        except Exception:
                            pass
                if len(node.args) >= 2:
                    try:
                        if "Safe" in ast.unparse(node.args[1]):
                            safe = True
                    except Exception:
                        pass
                if not safe:
                    self.dangerous_sinks.append({
                        "function": func_ctx, "sink": "unsafe_yaml_load", "lineno": lineno,
                    })
                    if self._current_func and self._tainted_vars:
                        arg_names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                        if arg_names & self._tainted_vars:
                            self.taint_flows.append({
                                "function": func_ctx, "sink": "unsafe_yaml_load", "lineno": lineno,
                            })
            else:
                self.dangerous_sinks.append({
                    "function": func_ctx, "sink": sink_type, "lineno": lineno,
                })
                if self._current_func and self._tainted_vars:
                    arg_names: Set[str] = set()
                    for arg in node.args:
                        for n in ast.walk(arg):
                            if isinstance(n, ast.Name):
                                arg_names.add(n.id)
                    for kw in node.keywords:
                        if kw.value:
                            for n in ast.walk(kw.value):
                                if isinstance(n, ast.Name):
                                    arg_names.add(n.id)
                    if arg_names & self._tainted_vars:
                        self.taint_flows.append({
                            "function": func_ctx, "sink": sink_type, "lineno": lineno,
                        })

        self.generic_visit(node)

    def _sink_type(self, func_node: ast.expr) -> Optional[str]:
        if isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                obj = func_node.value.id
                method = func_node.attr
                imported = self._imports.get(obj)
                if imported:
                    mod = imported[0]
                    st = _DANGEROUS_SINK_MAP.get((mod, method))
                    if st:
                        return st
                return _DANGEROUS_SINK_MAP.get((obj, method))
        elif isinstance(func_node, ast.Name):
            name = func_node.id
            imported = self._imports.get(name)
            if imported:
                mod, attr = imported
                if attr:
                    return _DANGEROUS_SINK_MAP.get((mod, attr))
            return _DANGEROUS_SINK_MAP.get(("builtins", name))
        return None


def _ast_deep_analysis(
    source_files: Dict[str, str],
) -> Dict[str, Any]:
    all_capabilities: Set[str] = set()
    all_sinks: List[Dict[str, Any]] = []
    all_flows: List[Dict[str, Any]] = []
    all_mcp_fns: List[str] = []

    for path, content in source_files.items():
        try:
            tree = ast.parse(content, filename=path)
        except SyntaxError as exc:
            _log.debug("AST parse error in %s: %s", path, exc)
            continue

        visitor = _SecurityVisitor()
        visitor.visit(tree)

        all_capabilities |= visitor.import_capabilities
        all_sinks.extend({**s, "file": path} for s in visitor.dangerous_sinks)
        all_flows.extend({**f, "file": path} for f in visitor.taint_flows)
        for fn in visitor.mcp_tool_functions:
            if fn not in all_mcp_fns:
                all_mcp_fns.append(fn)

    return {
        "import_capabilities": sorted(all_capabilities),
        "dangerous_sinks": all_sinks,
        "taint_flows": all_flows,
        "mcp_tool_functions": all_mcp_fns,
    }


def _ts_analysis(source_files: Dict[str, str]) -> Dict[str, Any]:
    all_capabilities: Set[str] = set()
    all_sinks: List[Dict[str, Any]] = []
    all_flows: List[Dict[str, Any]] = []
    all_mcp_fns: List[str] = []

    for path, content in source_files.items():
        if os.path.splitext(path)[1].lower() not in _TS_EXTS:
            continue
        lines = content.splitlines()

        for m in _TS_IMPORT_RE.finditer(content):
            mod = (m.group(1) or m.group(2) or "").strip()
            for key, cap in _TS_CAPABILITY_IMPORTS.items():
                prefix = key if key.endswith("/") else key + "/"
                if mod == key or mod.startswith(prefix):
                    all_capabilities.add(cap)
                    break

        for m in _TS_MCP_TOOL_RE.finditer(content):
            fn_name = m.group(1).strip()
            if fn_name not in all_mcp_fns:
                all_mcp_fns.append(fn_name)

        for pattern, sink_type in _TS_DANGEROUS_PATTERNS:
            for m in pattern.finditer(content):
                lineno = content[:m.start()].count("\n") + 1
                func_name = "<module>"
                for fm in _TS_FUNC_RE.finditer(content[:m.start()]):
                    func_name = fm.group(1) or fm.group(2) or "<module>"

                all_sinks.append({
                    "function": func_name,
                    "sink": sink_type,
                    "lineno": lineno,
                    "file": path,
                })

                sink_line = lines[lineno - 1] if lineno <= len(lines) else ""
                context = "\n".join(lines[max(0, lineno - 8):lineno])
                params: Set[str] = set()
                for pm in re.finditer(
                    r'(?:\bfunction\s+\w+\s*\(([^)]+)\)|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(([^)]+)\)\s*=>)',
                    context,
                ):
                    raw = pm.group(1) or pm.group(2) or ""
                    for p in raw.split(","):
                        pname = re.sub(r'[?:=].*', '', p).strip().lstrip(".")
                        if pname and re.match(r'^\w+$', pname) and pname not in ("this", "self"):
                            params.add(pname)
                if params and any(p in sink_line for p in params):
                    all_flows.append({
                        "function": func_name,
                        "sink": sink_type,
                        "lineno": lineno,
                        "file": path,
                    })

    return {
        "import_capabilities": sorted(all_capabilities),
        "dangerous_sinks": all_sinks,
        "taint_flows": all_flows,
        "mcp_tool_functions": all_mcp_fns,
    }


def _description_mismatch(
    import_capabilities: List[str],
    live_tools: List[Dict[str, Any]],
    all_sinks: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sink_types = {s["sink"] for s in all_sinks}
    caps_set = set(import_capabilities)
    seen_mismatch_types: Set[str] = set()

    for tool in live_tools:
        name = tool.get("tool_name") or tool.get("name") or ""
        desc = (tool.get("description") or "").lower()
        if not desc:
            continue

        if any(w in desc for w in (
            "read only", "read-only", "readonly", "non-destructive",
            "only reads", "no side effect", "does not modify",
        )):
            risky = [s for s in ("shell_exec", "code_eval", "file_delete", "deserialization") if s in sink_types]
            key = f"read_only_mismatch:{','.join(sorted(risky))}"
            if risky and key not in seen_mismatch_types:
                seen_mismatch_types.add(key)
                findings.append({
                    "layer": "description_mismatch",
                    "name": "read_only_claim_mismatch",
                    "finding": (
                        f"Tool '{name}' claims read-only/non-destructive but codebase uses: "
                        f"{', '.join(risky)}"
                    ),
                    "severity": "HIGH",
                    "tool": name,
                })

        if any(w in desc for w in ("local only", "no network", "offline", "no http", "no external")):
            net_caps = [c for c in ("outbound_http", "outbound_network") if c in caps_set]
            key = f"local_only_mismatch:{','.join(sorted(net_caps))}"
            if net_caps and key not in seen_mismatch_types:
                seen_mismatch_types.add(key)
                findings.append({
                    "layer": "description_mismatch",
                    "name": "local_only_claim_mismatch",
                    "finding": (
                        f"Tool '{name}' claims local-only but codebase imports outbound network libraries: "
                        f"{', '.join(net_caps)}"
                    ),
                    "severity": "MEDIUM",
                    "tool": name,
                })

        if any(w in desc for w in ("sandboxed", "no execution", "no shell", "no command execution")):
            exec_sinks = [s for s in ("shell_exec", "code_eval") if s in sink_types]
            key = f"sandbox_mismatch:{','.join(sorted(exec_sinks))}"
            if exec_sinks and key not in seen_mismatch_types:
                seen_mismatch_types.add(key)
                findings.append({
                    "layer": "description_mismatch",
                    "name": "sandboxed_claim_mismatch",
                    "finding": (
                        f"Tool '{name}' claims sandboxed/no execution but codebase uses: "
                        f"{', '.join(exec_sinks)}"
                    ),
                    "severity": "HIGH",
                    "tool": name,
                })

    return findings


async def _check_rug_pull_hash(
    server_id: str,
    source_files: Dict[str, str],
    github_url: str,
) -> Optional[Dict[str, Any]]:
    sorted_content = json.dumps(
        {k: source_files[k] for k in sorted(source_files)},
        sort_keys=True,
    )
    current_hash = hashlib.sha256(sorted_content.encode()).hexdigest()
    file_paths = sorted(source_files.keys())

    loop = asyncio.get_running_loop()
    existing = await loop.run_in_executor(None, db.get_source_hash, server_id)
    await loop.run_in_executor(
        None, db.upsert_source_hash, server_id, github_url, current_hash, file_paths
    )

    if existing and existing["files_hash"] != current_hash:
        return {
            "layer": "rug_pull",
            "name": "source_code_changed",
            "finding": (
                f"Source code hash changed since last scan "
                f"(prev: {existing['files_hash'][:12]}... -> now: {current_hash[:12]}...). "
                f"Last seen: {existing.get('last_checked_at', 'unknown')}."
            ),
            "severity": "HIGH",
            "previous_hash": existing["files_hash"],
            "current_hash": current_hash,
        }
    return None


async def _run_bandit(source_files: Dict[str, str]) -> List[Dict[str, Any]]:
    py_files = {k: v for k, v in source_files.items() if k.endswith(".py")}
    if not py_files:
        return []
    findings: List[Dict[str, Any]] = []
    tmpdir = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="mcp_bandit_")
        os.chmod(tmpdir, stat.S_IRWXU)

        flat_to_orig: Dict[str, str] = {}
        for path, content in py_files.items():
            flat_name = path.replace("/", "_").replace("\\", "_")
            flat_to_orig[flat_name] = path
            dest = os.path.join(tmpdir, flat_name)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)

        proc = await asyncio.create_subprocess_exec(
            "bandit", "-r", tmpdir, "-f", "json", "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=_BANDIT_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return findings

        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore"))
        except (json.JSONDecodeError, ValueError):
            return findings

        sev_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        for result in data.get("results", []):
            sev = sev_map.get(result.get("issue_severity", ""), "LOW")
            flat = os.path.basename(result.get("filename", ""))
            findings.append({
                "layer": "bandit",
                "name": result.get("test_id", "bandit_finding"),
                "finding": sanitise_for_prompt(result.get("issue_text", ""), 200),
                "severity": sev,
                "file": flat_to_orig.get(flat, flat),
                "lineno": result.get("line_number", 0),
                "cwe": (result.get("issue_cwe") or {}).get("id"),
            })
    except FileNotFoundError:
        _log.debug("bandit not installed - skipping L4")
    except Exception as exc:
        _log.debug("bandit scan failed: %s", exc)
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return findings


async def _run_semgrep(source_files: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    tmpdir = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="mcp_semgrep_")
        os.chmod(tmpdir, stat.S_IRWXU)

        flat_to_orig: Dict[str, str] = {}
        for path, content in source_files.items():
            flat_name = path.replace("/", "_").replace("\\", "_")
            flat_to_orig[flat_name] = path
            dest = os.path.join(tmpdir, flat_name)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)

        has_py = any(p.endswith(".py") for p in source_files)
        has_ts = any(os.path.splitext(p)[1].lower() in _TS_EXTS for p in source_files)
        rules_dir = os.path.join(os.path.dirname(__file__), "semgrep_rules")
        cmd = ["semgrep", "--json", "--quiet"]
        if os.path.isdir(rules_dir) and has_py:
            cmd.extend(["--config", rules_dir])
        elif has_py:
            cmd.extend(["--config", "p/python"])
        if has_ts:
            cmd.extend(["--config", "p/typescript", "--config", "p/nodejs"])
        cmd.extend(["--config", "p/secrets"])
        cmd.append(tmpdir)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=_SEMGREP_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return findings

        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore"))
        except (json.JSONDecodeError, ValueError):
            return findings

        for result in data.get("results", []):
            meta = result.get("extra", {})
            raw_sev = (meta.get("severity") or "WARNING").upper()
            sev = "HIGH" if raw_sev in ("ERROR", "HIGH") else "MEDIUM" if raw_sev == "WARNING" else "LOW"
            flat = os.path.basename(result.get("path", ""))
            findings.append({
                "layer": "semgrep",
                "name": result.get("check_id", "semgrep_finding"),
                "finding": sanitise_for_prompt(meta.get("message", ""), 200),
                "severity": sev,
                "file": flat_to_orig.get(flat, flat),
                "lineno": (result.get("start") or {}).get("line", 0),
            })
    except FileNotFoundError:
        _log.debug("semgrep not installed - skipping L5")
    except Exception as exc:
        _log.debug("semgrep scan failed: %s", exc)
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return findings


async def _run_llm_analysis(
    ast_result: Dict[str, Any],
    existing_findings: List[Dict[str, Any]],
    llm_provider: str,
    model_id: Optional[str],
    api_key: Optional[str],
) -> List[Dict[str, Any]]:
    from .scanner import call_llm

    taint_flows = ast_result.get("taint_flows", [])[:10]
    capabilities = ast_result.get("import_capabilities", [])
    mcp_fns = ast_result.get("mcp_tool_functions", [])

    safe_flows = [
        {
            "function": sanitise_for_prompt(f.get("function", ""), 50),
            "sink": f.get("sink", ""),
            "lineno": f.get("lineno", 0),
        }
        for f in taint_flows
    ]
    safe_findings = [
        {
            "layer": f.get("layer", ""),
            "name": sanitise_for_prompt(f.get("name", ""), 50),
            "finding": sanitise_for_prompt(f.get("finding", ""), 150),
            "severity": f.get("severity", ""),
        }
        for f in existing_findings[:10]
    ]

    prompt = (
        "You are a security researcher reviewing static analysis of an MCP server.\n\n"
        f"Import capabilities: {', '.join(capabilities)}\n"
        f"MCP tool functions: {', '.join(mcp_fns[:10])}\n"
        f"Taint flows (param -> dangerous sink):\n{json.dumps(safe_flows, indent=2)}\n"
        f"Existing findings:\n{json.dumps(safe_findings, indent=2)}\n\n"
        "Identify false positives and critical issues pattern matching cannot reason about. "
        "Focus on cross-function data flows and context the static tools missed.\n\n"
        'Return ONLY valid JSON array. Each item: {"action": "confirm"|"false_positive"|"new_finding", '
        '"name": str, "finding": str, "severity": "HIGH"|"MEDIUM"|"LOW", "rationale": str}'
    )

    loop = asyncio.get_running_loop()
    try:
        raw = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: call_llm(llm_provider, model_id, api_key, prompt)),
            timeout=_LLM_TIMEOUT,
        )
        raw = strip_json_fence(raw.strip())
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return []
        findings: List[Dict[str, Any]] = []
        for item in parsed:
            if isinstance(item, dict) and item.get("action") == "new_finding":
                findings.append({
                    "layer": "llm",
                    "name": sanitise_for_prompt(item.get("name", "llm_finding"), 80),
                    "finding": sanitise_for_prompt(item.get("finding", ""), 200),
                    "severity": item.get("severity", "MEDIUM"),
                    "rationale": sanitise_for_prompt(item.get("rationale", ""), 150),
                })
        return findings
    except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as exc:
        _log.debug("LLM analysis failed: %s", exc)
        return []


async def run_source_recon(
    server_id: str,
    server_config: Dict[str, Any],
    tools: List[Dict[str, Any]],
    github_url: Optional[str] = None,
    llm_provider: Optional[str] = None,
    model_id: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Stage 0b: source code reconnaissance for an MCP server.

    Returns a dict with github_url, findings list, import_capabilities, taint_flows,
    dangerous_sinks, mcp_tool_functions, rug_pull_alert, layers_run, and files_analyzed.
    Returns github_url=None if no source could be located.
    """
    result: Dict[str, Any] = {
        "github_url": None,
        "language": "unknown",
        "findings": [],
        "import_capabilities": [],
        "dangerous_sinks": [],
        "taint_flows": [],
        "mcp_tool_functions": [],
        "rug_pull_alert": False,
        "layers_run": [],
        "files_analyzed": 0,
    }

    url = _detect_github_url(server_config, github_url)
    if not url:
        try:
            url = await _detect_github_url_from_pypi(server_config)
        except Exception:
            pass

    if not url:
        _log.debug("source_recon: no GitHub URL for server=%s", server_id)
        return result

    parsed = _parse_github_owner_repo(url)
    if not parsed:
        _log.debug("source_recon: cannot parse GitHub URL: %s", url)
        return result

    owner, repo = parsed
    result["github_url"] = f"https://github.com/{owner}/{repo}"

    try:
        source_files = await asyncio.wait_for(
            _fetch_source_files(owner, repo),
            timeout=_GITHUB_FETCH_TIMEOUT,
        )
    except asyncio.TimeoutError:
        _log.debug("source_recon: fetch timed out for %s/%s", owner, repo)
        return result
    except Exception as exc:
        _log.debug("source_recon: fetch failed: %s", exc)
        return result

    if not source_files:
        _log.debug("source_recon: no source files found for %s/%s", owner, repo)
        return result

    py_files = {k: v for k, v in source_files.items() if k.endswith(".py")}
    ts_files = {k: v for k, v in source_files.items() if os.path.splitext(k)[1].lower() in _TS_EXTS}
    result["language"] = (
        "python+typescript" if py_files and ts_files
        else "typescript" if ts_files
        else "python"
    )
    result["files_analyzed"] = len(source_files)
    all_findings: List[Dict[str, Any]] = []

    try:
        l1 = _entropy_secret_scan(py_files) + _ts_entropy_scan(ts_files)
        all_findings.extend(l1)
        result["layers_run"].append("entropy")
        _log.debug("source_recon L1: %d findings", len(l1))
    except Exception as exc:
        _log.debug("source_recon L1 failed: %s", exc)

    ast_result: Dict[str, Any] = {
        "import_capabilities": [], "dangerous_sinks": [],
        "taint_flows": [], "mcp_tool_functions": [],
    }
    try:
        merged_caps: Set[str] = set()
        merged_sinks: List[Dict[str, Any]] = []
        merged_flows: List[Dict[str, Any]] = []
        merged_fns: List[str] = []
        if py_files:
            py_ast = _ast_deep_analysis(py_files)
            merged_caps |= set(py_ast["import_capabilities"])
            merged_sinks.extend(py_ast["dangerous_sinks"])
            merged_flows.extend(py_ast["taint_flows"])
            for fn in py_ast["mcp_tool_functions"]:
                if fn not in merged_fns:
                    merged_fns.append(fn)
        if ts_files:
            ts_ast = _ts_analysis(ts_files)
            merged_caps |= set(ts_ast["import_capabilities"])
            merged_sinks.extend(ts_ast["dangerous_sinks"])
            merged_flows.extend(ts_ast["taint_flows"])
            for fn in ts_ast["mcp_tool_functions"]:
                if fn not in merged_fns:
                    merged_fns.append(fn)
        ast_result = {
            "import_capabilities": sorted(merged_caps),
            "dangerous_sinks": merged_sinks,
            "taint_flows": merged_flows,
            "mcp_tool_functions": merged_fns,
        }
        result["import_capabilities"] = ast_result["import_capabilities"]
        result["dangerous_sinks"] = ast_result["dangerous_sinks"]
        result["taint_flows"] = ast_result["taint_flows"]
        result["mcp_tool_functions"] = ast_result["mcp_tool_functions"]
        result["layers_run"].append("ast")
        _log.debug(
            "source_recon L2: %d capabilities, %d sinks, %d taint flows",
            len(ast_result["import_capabilities"]),
            len(ast_result["dangerous_sinks"]),
            len(ast_result["taint_flows"]),
        )
    except Exception as exc:
        _log.debug("source_recon L2 failed: %s", exc)

    try:
        l3 = _description_mismatch(
            ast_result.get("import_capabilities", []),
            tools,
            ast_result.get("dangerous_sinks", []),
        )
        all_findings.extend(l3)
        result["layers_run"].append("description_mismatch")
        _log.debug("source_recon L3: %d mismatch findings", len(l3))
    except Exception as exc:
        _log.debug("source_recon L3 failed: %s", exc)

    try:
        rug_pull = await _check_rug_pull_hash(server_id, source_files, result["github_url"])
        if rug_pull:
            all_findings.append(rug_pull)
            result["rug_pull_alert"] = True
        result["layers_run"].append("rug_pull")
    except Exception as exc:
        _log.debug("source_recon rug pull check failed: %s", exc)

    try:
        l4_coro = asyncio.create_task(_run_bandit(source_files))
        l5_coro = asyncio.create_task(_run_semgrep(source_files))
        l4, l5 = await asyncio.gather(l4_coro, l5_coro, return_exceptions=True)
        if isinstance(l4, list) and l4:
            all_findings.extend(l4)
            result["layers_run"].append("bandit")
        elif isinstance(l4, BaseException):
            _log.debug("bandit task raised: %s", l4)
        if isinstance(l5, list) and l5:
            all_findings.extend(l5)
            result["layers_run"].append("semgrep")
        elif isinstance(l5, BaseException):
            _log.debug("semgrep task raised: %s", l5)
    except Exception as exc:
        _log.debug("source_recon L4/L5 failed: %s", exc)

    if llm_provider and (ast_result.get("taint_flows") or all_findings):
        try:
            l6 = await _run_llm_analysis(ast_result, all_findings, llm_provider, model_id, api_key)
            if l6:
                all_findings.extend(l6)
                result["layers_run"].append("llm")
        except Exception as exc:
            _log.debug("source_recon L6 failed: %s", exc)

    seen: Set[Tuple[str, str]] = set()
    unique: List[Dict[str, Any]] = []
    for f in all_findings:
        key = (f.get("name", ""), (f.get("finding", ""))[:80])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result["findings"] = unique
    _log.info(
        "source_recon: server=%s files=%d findings=%d layers=%s",
        server_id, result["files_analyzed"], len(unique), result["layers_run"],
    )
    return result
