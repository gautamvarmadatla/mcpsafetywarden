"""
Shared pytest fixtures and config for all mcpsafetywarden test modules.
Tests run against DeepWiki (https://mcp.deepwiki.com/mcp) - public, no auth required.
"""
import asyncio
import json
import os
import pytest
import pytest_asyncio

pytestmark = pytest.mark.asyncio

API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
HAS_KEY = bool(API_KEY)
needs_key = pytest.mark.skipif(not HAS_KEY, reason="ANTHROPIC_API_KEY not set")

SERVER     = "deepwiki-test"
SERVER_URL = "https://mcp.deepwiki.com/mcp"
TOOL_READ  = "read_wiki_structure"
TOOL_CONT  = "read_wiki_contents"
TOOL_ASK   = "ask_question"
REPO       = "modelcontextprotocol/python-sdk"


def j(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        pytest.fail(f"Result is not valid JSON: {e}\nRaw: {raw[:500]}")


def assert_no_error(d: dict):
    assert "error" not in d, f"Unexpected error: {d['error']}"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def registered_server():
    from mcpsafetywarden.server import register_server, list_servers
    existing = j(list_servers())
    ids = [s["server_id"] for s in (existing if isinstance(existing, list) else existing.get("servers", []))]
    if SERVER not in ids:
        result = j(await register_server(
            server_id=SERVER,
            transport="streamable_http",
            url=SERVER_URL,
            auto_inspect=True,
        ))
        assert "error" not in result, f"register_server failed: {result}"
    return SERVER
