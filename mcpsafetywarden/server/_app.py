import asyncio
import collections
import hmac
import logging
import os as _os
import time
from typing import Dict, Optional

from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp


_log = logging.getLogger(__name__)

_SHELL_INTERPS = frozenset(
    {
        "bash",
        "sh",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "cmd",
        "powershell",
        "pwsh",
    }
)
_SHELL_EVAL_FLAGS = frozenset({"-c", "/c", "/k", "-e", "-enc", "-encodedcommand", "-command"})

_LLM_SHORTHANDS: frozenset = frozenset({"anthropic", "openai", "gemini", "ollama"})

_PREFLIGHT_SCAN_TIMEOUT_S = 60
_preflight_scan_locks: Dict[str, asyncio.Lock] = {}

_MGMT_RATE_LIMIT_MAX = 10
_MGMT_RATE_LIMIT_WINDOW_S = 60
_GLOBAL_RATE_LIMIT_MAX = 100
_MGMT_DICT_MAX_ENTRIES = 5_000
_mgmt_call_times: Dict[str, collections.deque] = {}
_global_call_times: collections.deque = collections.deque(maxlen=_GLOBAL_RATE_LIMIT_MAX)
_bg_scan_status: Dict[str, str] = {}

_MAX_SERVER_ID_LEN = 256
_MAX_COMMAND_LEN = 1024
_MAX_URL_LEN = 2048
_MAX_ARGS_COUNT = 50
_MAX_ARG_LEN = 1024
_MAX_ENV_VARS = 50
_MAX_HEADER_PAIRS = 20


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Rejects HTTP requests whose Authorization header does not match MCP_AUTH_TOKEN."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        super().__init__(app)
        self._token_bytes = token.encode()

    async def dispatch(self, request, call_next):
        auth = request.headers.get("Authorization", "")
        candidate = auth[7:].encode() if auth.startswith("Bearer ") else b""
        expected = self._token_bytes
        if len(candidate) != len(expected) or not hmac.compare_digest(candidate, expected):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return await call_next(request)


mcp = FastMCP(
    "mcpsafetywarden",
    instructions=(
        "Security proxy that wraps MCP servers to enforce risk gating, behavioral profiling, "
        "and security scanning before any tool is called. "
        "All tool calls to wrapped servers MUST go through safe_tool_call, never directly. "
        "ENTRY POINT - pick the right starting point based on what you have: "
        "- User mentions a server by name/URL but it is not registered -> onboard_server (one-shot preferred) or register_server. "
        "- User asks what servers are available on this machine -> discover_servers -> onboard_discovered_servers. "
        "- Server is already registered and user wants to call a tool -> safe_tool_call directly. "
        "- User has a GitHub URL but no local setup (server not running) -> security_scan_server(github_url=...) for source-only scan, then user fixes local setup, then onboard_server. "
        "- User wants a security audit of an already-registered server -> security_scan_server(server_id=...). "
        "- User wants to check for drift since last scan -> check_server_drift. "
        "FLOWS after entry: "
        "(1) discover_servers -> onboard_discovered_servers -> safe_tool_call. "
        "(2) onboard_server -> review scan in response -> set_tool_policy('block') for HIGH-risk tools -> safe_tool_call. "
        "(3) register_server -> security_scan_server -> get_security_scan (poll every 30s) -> set_tool_policy('block') -> safe_tool_call. "
        "(4) safe_tool_call blocked -> safe_tool_call(approved=True) | safe_tool_call(use_alternative=X) | suggest_safer_alternative. "
        "(5) check_server_drift severity MEDIUM+ -> security_scan_server -> get_security_scan -> update policies. "
        "NEVER: "
        "- Call preflight_tool_call before safe_tool_call (safe_tool_call runs it internally). "
        "- Skip security_scan_server for an untrusted server that was just registered. "
        "- Call wrapped server tools directly - always use safe_tool_call. "
        "- Pass provider= to security_scan_server unless the user explicitly names one (omit it to auto-detect from env keys). "
        "- Call set_tool_policy after a source-only scan (no server is registered, policies do not apply)."
    ),
)


def create_http_app(transport: str = "streamable_http") -> ASGIApp:
    """Return the FastMCP ASGI app, optionally wrapped with BearerAuthMiddleware.

    transport: "streamable_http" (default) or "sse"
    """
    token = _os.environ.get("MCP_AUTH_TOKEN", "")
    base = mcp.streamable_http_app() if transport == "streamable_http" else mcp.sse_app()
    if token:
        return BearerAuthMiddleware(base, token)
    _log.warning(
        "MCP_AUTH_TOKEN is not set - HTTP transport is open to any client. "
        "Set this variable or place an auth proxy in front."
    )
    return base


def _check_mgmt_rate_limit(key: str) -> Optional[str]:
    now = time.monotonic()

    while _global_call_times and now - _global_call_times[0] > _MGMT_RATE_LIMIT_WINDOW_S:
        _global_call_times.popleft()
    if len(_global_call_times) >= _GLOBAL_RATE_LIMIT_MAX:
        return (
            f"Server-wide rate limit exceeded ({_GLOBAL_RATE_LIMIT_MAX} calls/{_MGMT_RATE_LIMIT_WINDOW_S}s). "
            f"Retry after {int(_MGMT_RATE_LIMIT_WINDOW_S - (now - _global_call_times[0]))}s."
        )

    if len(_mgmt_call_times) >= _MGMT_DICT_MAX_ENTRIES and key not in _mgmt_call_times:
        _mgmt_call_times.pop(next(iter(_mgmt_call_times)), None)
    times = _mgmt_call_times.setdefault(key, collections.deque(maxlen=_MGMT_RATE_LIMIT_MAX))
    while times and now - times[0] > _MGMT_RATE_LIMIT_WINDOW_S:
        times.popleft()
    if len(times) >= _MGMT_RATE_LIMIT_MAX:
        return f"Rate limit exceeded for {key}. Retry after {int(_MGMT_RATE_LIMIT_WINDOW_S - (now - times[0]))}s."

    _global_call_times.append(now)
    times.append(now)
    return None


def main():
    transport = _os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        mcp.run()
    else:
        import uvicorn

        host = _os.environ.get("MCP_HOST", "127.0.0.1")
        try:
            port = int(_os.environ.get("MCP_PORT", "8000"))
        except ValueError:
            _log.error("Invalid MCP_PORT=%r, defaulting to 8000", _os.environ.get("MCP_PORT"))
            port = 8000
        t = "streamable_http" if transport in ("http", "streamable_http") else "sse"
        uvicorn.run(create_http_app(t), host=host, port=port)
