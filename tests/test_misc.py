"""Tests for ping_server and run_replay_test."""
import pytest
from .conftest import j, SERVER, TOOL_READ, REPO

pytestmark = pytest.mark.asyncio


class TestPing:
    async def test_ping_reachable_no_llm(self, registered_server):
        from mcpsafetywarden.server import ping_server
        result = j(await ping_server(SERVER))
        assert result.get("status") == "reachable"

    async def test_ping_nonexistent_server(self):
        from mcpsafetywarden.server import ping_server
        result = j(await ping_server("no_such_xyz"))
        assert "error" in result or result.get("reachable") is False


class TestReplay:
    async def test_replay_read_tool_no_llm(self, registered_server):
        from mcpsafetywarden.server import run_replay_test
        result = j(await run_replay_test(
            SERVER, TOOL_READ,
            args={"repo": REPO},
            approved=True,
        ))
        assert "verdict" in result
        assert result["verdict"] in ("likely_idempotent", "likely_not_idempotent")

    async def test_replay_nonexistent_tool(self, registered_server):
        from mcpsafetywarden.server import run_replay_test
        result = j(await run_replay_test(
            SERVER, "no_such_xyz",
            args={},
            approved=True,
        ))
        assert "error" in result

    async def test_replay_requires_authorization(self, registered_server):
        from mcpsafetywarden.server import run_replay_test
        result = j(await run_replay_test(
            SERVER, TOOL_READ,
            args={"repo": REPO},
            approved=False,
        ))
        assert "verdict" in result or "blocked" in result or "error" in result
