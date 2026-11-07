"""MCP-level contract tests: tool metadata, structured output, actionable errors and the audit log.

These run against an isolated temporary database and an in-memory MCP client session,
so they exercise exactly what an MCP client receives.
"""

import asyncio
import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session


@pytest.fixture()
def seeded_db(tmp_path, monkeypatch):
    from mcpsafetywarden.core import database

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "contract.db")
    monkeypatch.setattr(database, "_initialized", False)
    database.upsert_server("alpha", "stdio", command="alpha-server")
    database.upsert_tool("alpha", "read_file", "Read a file", {}, {})
    database.upsert_tool("alpha", "write_file", "Write a file", {}, {})
    return database


def _call(name, args=None):
    from mcpsafetywarden.server import mcp

    async def run():
        async with create_connected_server_and_client_session(mcp._mcp_server) as session:
            return await session.call_tool(name, args or {})

    return asyncio.run(run())


def _tools():
    from mcpsafetywarden.server import mcp

    return asyncio.run(mcp.list_tools())


def test_every_tool_declares_a_full_contract():
    tools = _tools()
    assert len(tools) >= 26
    for t in tools:
        props = t.inputSchema.get("properties", {})
        assert t.title, t.name
        assert t.annotations is not None and t.annotations.readOnlyHint is not None, t.name
        assert "ctx" not in props, t.name
        undocumented = [k for k, v in props.items() if not v.get("description")]
        assert not undocumented, f"{t.name}: {undocumented}"
        out = t.outputSchema.get("properties", {})
        assert {"error", "hint", "next_step"} <= set(out), t.name
        assert len(out) > 3, t.name


def test_read_only_and_destructive_hints_are_consistent():
    tools = {t.name: t.annotations for t in _tools()}
    for name in ("list_servers", "get_security_scan", "get_audit_log", "discover_servers"):
        assert tools[name].readOnlyHint is True and tools[name].destructiveHint is False
    for name in ("safe_tool_call", "set_tool_policy", "run_replay_test", "security_scan_server"):
        assert tools[name].readOnlyHint is False and tools[name].destructiveHint is True


def test_structured_content_accompanies_unchanged_text(seeded_db):
    r = _call("list_servers")
    assert r.isError is False
    assert isinstance(json.loads(r.content[0].text), list)
    assert r.structuredContent["count"] == 1
    assert r.structuredContent["servers"][0]["server_id"] == "alpha"


def test_list_server_tools_pages_with_total(seeded_db):
    r = _call("list_server_tools", {"server_id": "alpha", "limit": 1, "offset": 1})
    assert r.structuredContent["total"] == 2
    assert len(r.structuredContent["tools"]) == 1


def test_unknown_tool_error_lists_valid_names(seeded_db):
    r = _call("set_tool_policy", {"server_id": "alpha", "tool_name": "write", "policy": "block"})
    assert r.isError is True
    sc = r.structuredContent
    assert sc["available_tools"] == ["read_file", "write_file"]
    assert "write_file" in sc["did_you_mean"]
    assert sc["next_step"]


def test_unknown_server_error_lists_registered_servers(seeded_db):
    r = _call("list_server_tools", {"server_id": "alphaa"})
    assert r.isError is True
    assert r.structuredContent["registered_servers"] == ["alpha"]


def test_invalid_enum_is_rejected_before_running(seeded_db):
    r = _call("set_tool_policy", {"server_id": "alpha", "tool_name": "write_file", "policy": "maybe"})
    assert r.isError is True
    assert seeded_db.get_tool_policy("alpha", "write_file") is None


def test_writes_are_audited_and_reads_are_not(seeded_db):
    _call("list_servers")
    _call("set_tool_policy", {"server_id": "alpha", "tool_name": "write_file", "policy": "block"})
    _call("set_tool_policy", {"server_id": "alpha", "tool_name": "nope", "policy": "block"})
    log = _call("get_audit_log").structuredContent
    assert log["total"] == 2
    newest, oldest = log["entries"]
    assert oldest["tool"] == "set_tool_policy" and oldest["outcome"] == "ok"
    assert oldest["server_id"] == "alpha" and oldest["target_tool"] == "write_file"
    assert oldest["args"]["policy"] == "block"
    assert oldest["client"]
    assert newest["outcome"] == "error"


def test_audit_redacts_secrets(seeded_db):
    _call(
        "register_server",
        {
            "server_id": "gamma",
            "command": "gamma-server",
            "env": {"API_KEY": "sk-live-abcdefghijklmnopqrstuvwxyz123456"},
            "classify_api_key": "sk-ant-abcdefghijklmnopqrstuvwxyz",
            "auto_inspect": False,
        },
    )
    entry = _call("get_audit_log", {"tool": "register_server"}).structuredContent["entries"][0]
    raw = json.dumps(entry)
    assert "abcdefghijklmnopqrstuvwxyz" not in raw
    assert entry["args"]["env"] == {"API_KEY": "***"}
    assert entry["args"]["classify_api_key"] == "***"


def test_direct_python_calls_still_return_json_strings(seeded_db):
    from mcpsafetywarden.server import list_servers, set_tool_policy

    assert isinstance(list_servers(), str)
    assert json.loads(set_tool_policy("alpha", "write_file", "block"))["policy"] == "block"
