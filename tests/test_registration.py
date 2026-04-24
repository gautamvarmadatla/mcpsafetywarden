"""Tests for server registration, inspection, and onboarding."""
import pytest
from .conftest import j, needs_key, SERVER, SERVER_URL, TOOL_READ, API_KEY

pytestmark = pytest.mark.asyncio


class TestList:
    async def test_list_servers_no_llm(self, registered_server):
        from mcpsafetywarden.server import list_servers
        result = j(list_servers())
        servers = result if isinstance(result, list) else result.get("servers", [])
        ids = [s["server_id"] for s in servers]
        assert SERVER in ids

    async def test_list_server_tools_no_llm(self, registered_server):
        from mcpsafetywarden.server import list_server_tools
        result = j(list_server_tools(SERVER))
        assert "tools" in result
        names = [t["tool_name"] for t in result["tools"]]
        assert TOOL_READ in names

    async def test_list_nonexistent_server(self):
        from mcpsafetywarden.server import list_server_tools
        result = j(list_server_tools("no_such_server_xyz"))
        assert "error" in result

    async def test_list_tool_has_effect_class(self, registered_server):
        from mcpsafetywarden.server import list_server_tools
        result = j(list_server_tools(SERVER))
        for tool in result["tools"]:
            assert "effect_class" in tool, f"Missing effect_class on {tool['tool_name']}"
            assert tool["effect_class"] in (
                "read_only", "additive_write", "mutating_write",
                "external_action", "destructive", "unknown"
            )

    async def test_list_tool_has_risk_level(self, registered_server):
        from mcpsafetywarden.server import list_server_tools
        result = j(list_server_tools(SERVER))
        for tool in result["tools"]:
            assert "risk_level" in tool, f"Missing risk_level on {tool['tool_name']}"


class TestInspect:
    async def test_inspect_no_llm(self, registered_server):
        from mcpsafetywarden.server import inspect_server
        result = j(await inspect_server(SERVER))
        assert "tools_discovered" in result or "tools" in result

    @needs_key
    async def test_inspect_with_llm(self, registered_server):
        from mcpsafetywarden.server import inspect_server
        result = j(await inspect_server(
            SERVER,
            classify_provider="anthropic",
            classify_api_key=API_KEY,
        ))
        assert "tools_discovered" in result or "tools" in result

    async def test_inspect_nonexistent(self):
        from mcpsafetywarden.server import inspect_server
        result = j(await inspect_server("no_such_xyz"))
        assert "error" in result


class TestRegister:
    async def test_register_no_inspect(self):
        from mcpsafetywarden.server import register_server
        result = j(await register_server(
            server_id="deepwiki-reg-noinspect",
            transport="streamable_http",
            url=SERVER_URL,
            auto_inspect=False,
        ))
        assert "error" not in result

    @needs_key
    async def test_register_with_llm_classify(self):
        from mcpsafetywarden.server import register_server
        result = j(await register_server(
            server_id="deepwiki-reg-llm",
            transport="streamable_http",
            url=SERVER_URL,
            auto_inspect=True,
            classify_provider="anthropic",
            classify_api_key=API_KEY,
        ))
        assert "error" not in result

    async def test_register_missing_url_for_http(self):
        from mcpsafetywarden.server import register_server
        result = j(await register_server(
            server_id="bad-no-url",
            transport="streamable_http",
        ))
        assert "error" in result

    async def test_register_missing_command_for_stdio(self):
        from mcpsafetywarden.server import register_server
        result = j(await register_server(
            server_id="bad-no-cmd",
            transport="stdio",
        ))
        assert "error" in result

    async def test_register_shell_eval_rejected(self):
        from mcpsafetywarden.server import register_server
        result = j(await register_server(
            server_id="bad-shell",
            transport="stdio",
            command="bash",
            args=["-c", "echo hi"],
        ))
        assert "error" in result or "not permitted" in str(result).lower()


class TestOnboard:
    async def test_onboard_no_scan_no_llm(self):
        from mcpsafetywarden.server import onboard_server
        result = j(await onboard_server(
            server_id="deepwiki-onboard-nollm",
            transport="streamable_http",
            url=SERVER_URL,
        ))
        assert "error" not in result or "already" in str(result).lower()

    @needs_key
    async def test_onboard_with_scan(self):
        from mcpsafetywarden.server import onboard_server
        result = j(await onboard_server(
            server_id="deepwiki-onboard-scan",
            transport="streamable_http",
            url=SERVER_URL,
            scan_provider="anthropic",
            scan_api_key=API_KEY,
            confirm_scan_authorized=True,
        ))
        assert "error" not in result

    async def test_onboard_bad_url(self):
        from mcpsafetywarden.server import onboard_server
        result = j(await onboard_server(
            server_id="bad-url-test",
            transport="streamable_http",
            url="https://this.does.not.exist.invalid/mcp",
        ))
        reg = result.get("register", {})
        assert "error" in result or "error" in reg or "inspect_error" in reg
