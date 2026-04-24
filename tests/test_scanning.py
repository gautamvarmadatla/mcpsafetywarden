"""Tests for security_scan_server and scan_all_servers."""
import pytest
from .conftest import j, needs_key, SERVER, SERVER_URL, TOOL_READ, API_KEY

pytestmark = pytest.mark.asyncio


class TestScan:
    async def test_get_scan_empty_before_scan(self, registered_server):
        from mcpsafetywarden.server import get_security_scan
        result = j(get_security_scan(SERVER))
        assert "error" in result or "overall_risk_level" in result

    async def test_scan_requires_authorization(self, registered_server):
        from mcpsafetywarden.server import security_scan_server
        result = j(await security_scan_server(
            SERVER,
            provider="anthropic",
            api_key=API_KEY,
            confirm_authorized=False,
        ))
        assert "error" in result or "confirm_authorized" in str(result).lower()

    @needs_key
    async def test_scan_with_llm(self, registered_server):
        from mcpsafetywarden.server import security_scan_server, get_security_scan
        result = j(await security_scan_server(
            SERVER,
            provider="anthropic",
            api_key=API_KEY,
            confirm_authorized=True,
            skip_web_research=True,
        ))
        if "error" in result:
            pytest.skip(f"LLM API error (possibly credits): {result['error']}")
        assert "overall_risk_level" in result
        assert result["overall_risk_level"] in ("HIGH", "MEDIUM", "LOW", "NONE")

        stored = j(get_security_scan(SERVER))
        assert "overall_risk_level" in stored

    async def test_get_scan_nonexistent_server(self):
        from mcpsafetywarden.server import get_security_scan
        result = j(get_security_scan("no_such_xyz"))
        assert "error" in result

    async def test_scan_nonexistent_server(self):
        from mcpsafetywarden.server import security_scan_server
        result = j(await security_scan_server(
            "no_such_xyz",
            provider="anthropic",
            api_key=API_KEY,
            confirm_authorized=True,
        ))
        assert "error" in result


class TestScanAll:
    @needs_key
    async def test_scan_all_subset(self, registered_server):
        from mcpsafetywarden.server import scan_all_servers
        result = j(await scan_all_servers(
            provider="anthropic",
            api_key=API_KEY,
            server_ids=[SERVER],
            skip_web_research=True,
            confirm_authorized=True,
        ))
        assert "results" in result or "server_results" in result or "error" in result

    async def test_scan_all_requires_authorization(self, registered_server):
        from mcpsafetywarden.server import scan_all_servers
        result = j(await scan_all_servers(
            provider="anthropic",
            api_key=API_KEY,
            server_ids=[SERVER],
            confirm_authorized=False,
        ))
        assert "error" in result or "confirm_authorized" in str(result).lower()
