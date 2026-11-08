"""Helpers that work with both mcp 1.x and mcp 2.x client and type APIs."""

import re
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

_CAMEL = re.compile(r"(?<!^)(?=[A-Z])")


def mfield(obj: Any, name: str, default: Any = None) -> Any:
    """Read a protocol field by its camelCase wire name from an mcp 1.x or 2.x model."""
    if obj is None:
        return default
    if hasattr(obj, name):
        return getattr(obj, name)
    return getattr(obj, _CAMEL.sub("_", name).lower(), default)


def dump(obj: Any) -> Any:
    """Serialise an mcp model with camelCase wire names on both SDK majors."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(by_alias=True, exclude_none=True, mode="json")
    return obj


@asynccontextmanager
async def streamable_http_streams(url: str, headers: Optional[Dict[str, str]] = None):
    from mcp.client.streamable_http import streamable_http_client

    if not headers:
        async with streamable_http_client(url) as streams:
            yield streams[0], streams[1]
        return

    from mcp.shared._httpx_utils import create_mcp_http_client

    http_client = create_mcp_http_client(headers=headers)
    http_client.follow_redirects = False
    async with http_client:
        async with streamable_http_client(url, http_client=http_client) as streams:
            yield streams[0], streams[1]
