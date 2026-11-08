import functools
import inspect
import json
import logging
from typing import Annotated, Any, Callable, Dict, List, Optional, Type

from ._sdk import Context
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..core import database as db
from ..core.mcp_compat import mfield
from ..core.security_utils import looks_like_secret as _looks_like_secret
from ._app import mcp

_log = logging.getLogger(__name__)

_SECRET_KEY_HINTS = ("api_key", "token", "secret", "password", "credential")
_REDACT_WHOLE = frozenset({"env", "headers"})
_MAX_AUDIT_ARGS_BYTES = 4096


class ToolOutput(BaseModel):
    """Fields shared by every Safety Warden tool result. Tools add their own fields on top."""

    model_config = ConfigDict(extra="allow")

    error: Optional[str] = Field(
        None, description="Present only when the call failed. Read hint and next_step to recover."
    )
    hint: Optional[str] = Field(None, description="Actionable recovery guidance accompanying an error.")
    next_step: Optional[str] = Field(None, description="The tool call to make next to recover or continue.")


class ListOutput(ToolOutput):
    """Result of a tool whose text payload is a bare JSON array."""

    items: Optional[List[Dict[str, Any]]] = None
    count: Optional[int] = None


def _redact(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if lowered in _REDACT_WHOLE and isinstance(value, dict):
        return {k: "***" for k in value}
    if any(h in lowered for h in _SECRET_KEY_HINTS) and value is not None:
        return "***"
    if isinstance(value, dict):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, key) for v in value]
    if isinstance(value, str) and _looks_like_secret(value):
        return "***"
    return value


def _outcome(data: Dict[str, Any]) -> str:
    if data.get("error"):
        return "error"
    if data.get("blocked"):
        return "blocked"
    if data.get("quarantined"):
        return "quarantined"
    return "ok"


def _client_name(ctx: Optional[Context]) -> Optional[str]:
    try:
        info = mfield(ctx.session.client_params, "clientInfo")
        return f"{info.name}/{info.version}" if info.version else info.name
    except Exception:
        return None


def _audit(tool: str, kwargs: Dict[str, Any], data: Dict[str, Any], ctx: Optional[Context]) -> None:
    try:
        args_json = json.dumps(_redact(kwargs), default=str)
        if len(args_json) > _MAX_AUDIT_ARGS_BYTES:
            args_json = json.dumps({"truncated": args_json[:_MAX_AUDIT_ARGS_BYTES]})
        db.record_audit(
            tool=tool,
            client=_client_name(ctx),
            server_id=kwargs.get("server_id"),
            target_tool=kwargs.get("tool_name"),
            args_json=args_json,
            outcome=_outcome(data),
            detail=data.get("error") or data.get("reason"),
        )
    except Exception as exc:
        _log.warning("audit write failed for %s: %s", tool, exc)


def server_not_found(server_id: str) -> Dict[str, Any]:
    """Error payload for an unknown server_id that lists the valid ones."""
    known = sorted(s["server_id"] for s in db.list_servers())
    return {
        "error": f"Server '{server_id}' is not registered.",
        "registered_servers": known[:50],
        "hint": (
            "Use one of registered_servers, or register this server first."
            if known
            else "No servers are registered yet."
        ),
        "next_step": "list_servers" if known else "onboard_server",
    }


def tool_not_found(server_id: str, tool_name: str) -> Dict[str, Any]:
    """Error payload for an unknown tool that lists the server's tools, or the valid servers."""
    if not db.get_server(server_id):
        return server_not_found(server_id)
    names = sorted(t["tool_name"] for t in db.list_tools(server_id))
    if not names:
        return {
            "error": f"Server '{server_id}' has no known tools.",
            "hint": "The server's tools have not been discovered yet.",
            "next_step": f"inspect_server(server_id='{server_id}')",
        }
    close = [n for n in names if tool_name.lower() in n.lower() or n.lower() in tool_name.lower()]
    payload: Dict[str, Any] = {
        "error": f"Tool '{tool_name}' not found on server '{server_id}'.",
        "available_tools": names[:100],
        "hint": "Use an exact name from available_tools. If the server changed, re-inspect it.",
        "next_step": f"inspect_server(server_id='{server_id}')",
    }
    if close:
        payload["did_you_mean"] = close[:5]
    return payload


def _structured(text: str, output: Type[ToolOutput], list_key: Optional[str], flag_errors: bool) -> CallToolResult:
    try:
        data: Any = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        data = {"error": "Tool returned non-JSON output.", "raw": str(text)[:2000]}
    if isinstance(data, list):
        data = {list_key or "items": data, "count": len(data)}
    if not isinstance(data, dict):
        data = {"value": data}
    try:
        output.model_validate(data)
    except ValidationError as exc:
        bad = {str(e["loc"][0]) for e in exc.errors() if e.get("loc")}
        _log.warning("%s output failed schema validation for fields %s; omitting them", output.__name__, bad)
        data = {k: v for k, v in data.items() if k not in bad}
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structuredContent=data,
        isError=flag_errors and bool(data.get("error")),
    )


def warden_tool(
    output: Type[ToolOutput],
    *,
    title: str,
    read_only: bool = False,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = False,
    list_key: Optional[str] = None,
    flag_errors: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a JSON-string tool with MCP as a structured tool and return it unchanged.

    The module-level function keeps returning the JSON string so internal callers and
    tests are unaffected. The registered wrapper returns the identical text plus
    structuredContent validated against output, sets isError on failures, carries tool
    annotations and a title, and writes an audit row for every non-read-only call.
    """

    annotations = ToolAnnotations(
        title=title,
        readOnlyHint=read_only,
        destructiveHint=False if read_only else destructive,
        idempotentHint=idempotent,
        openWorldHint=open_world,
    )

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)
        tool_name = fn.__name__

        def finish(text: str, kwargs: Dict[str, Any], ctx: Optional[Context]) -> CallToolResult:
            result = _structured(text, output, list_key, flag_errors)
            if not read_only:
                _audit(tool_name, kwargs, mfield(result, "structuredContent") or {}, ctx)
            return result

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def wrapper(*args: Any, ctx: Optional[Context] = None, **kwargs: Any) -> CallToolResult:
                bound = sig.bind(*args, **kwargs)
                return finish(await fn(*args, **kwargs), dict(bound.arguments), ctx)

        else:

            @functools.wraps(fn)
            def wrapper(*args: Any, ctx: Optional[Context] = None, **kwargs: Any) -> CallToolResult:
                bound = sig.bind(*args, **kwargs)
                return finish(fn(*args, **kwargs), dict(bound.arguments), ctx)

        params = list(sig.parameters.values())
        params.append(inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Context))
        return_annotation = Annotated[CallToolResult, output]
        wrapper.__signature__ = sig.replace(parameters=params, return_annotation=return_annotation)
        wrapper.__annotations__ = {
            **{p.name: p.annotation for p in params if p.annotation is not inspect.Parameter.empty},
            "return": return_annotation,
        }
        del wrapper.__wrapped__

        mcp.tool(
            name=tool_name,
            title=title,
            description=inspect.cleandoc(fn.__doc__ or ""),
            annotations=annotations,
            structured_output=True,
        )(wrapper)
        return fn

    return decorator
