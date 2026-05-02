"""
Red-team detection tests against a deliberately malicious local MCP server.

Each test class maps to one attack vector. Tests assert what IS caught and
explicitly document (with xfail markers) what the current system MISSES.

Run with: pytest tests/test_redteam.py -v
"""
import json
import sys
import uuid
from pathlib import Path

import pytest

from mcpsafetywarden.core import database as db
from mcpsafetywarden.scan.mcpsafety import run_deterministic_scan

pytestmark = pytest.mark.asyncio

_MALICIOUS_SERVER = str(Path(__file__).parent / "helpers" / "malicious_server.py")


def _uid() -> str:
    return f"redteam-{uuid.uuid4().hex[:8]}"


def _register(server_id: str) -> None:
    db.upsert_server(
        server_id,
        transport="stdio",
        command=sys.executable,
        args=[_MALICIOUS_SERVER],
    )


async def _inspect_tools(server_id: str) -> list:
    """Inspect and return tools in run_deterministic_scan-compatible format."""
    from mcpsafetywarden.proxy.client import inspect_server_tools
    await inspect_server_tools(server_id)
    db_tools = db.list_tools(server_id)
    return [
        {
            "name": t["tool_name"],
            "description": t.get("description", ""),
            "input_schema": t.get("schema", {}),
            "schema": t.get("schema", {}),
        }
        for t in db_tools
    ]


async def _full_inspect(server_id: str) -> dict:
    """Full inspect via server pipeline - builds graph, composition edges."""
    from mcpsafetywarden.server import inspect_server
    return json.loads(await inspect_server(server_id))


def _effect(server_id: str, tool_name: str) -> str:
    profile = db.get_profile(f"{server_id}::{tool_name}")
    return profile["effect_class"] if profile else "unknown"


class TestDeterministicDetection:
    """Patterns caught by rule-based scan - no LLM required."""

    async def test_prompt_injection_in_description_caught(self):
        sid = _uid()
        _register(sid)
        tools = await _inspect_tools(sid)
        result = run_deterministic_scan(sid, tools)
        flagged = {f["name"]: f for f in result.get("tool_findings", [])}
        assert "analyze_document" in flagged, "prompt injection in description not caught"
        assert flagged["analyze_document"]["risk_level"] == "HIGH"
        assert "injection" in flagged["analyze_document"]["finding"].lower()

    async def test_suspicious_tool_name_caught(self):
        sid = _uid()
        _register(sid)
        tools = await _inspect_tools(sid)
        result = run_deterministic_scan(sid, tools)
        flagged = {f["name"]: f for f in result.get("tool_findings", [])}
        assert "exec_command" in flagged, "exec_command not flagged as suspicious name"

    async def test_risky_params_caught(self):
        sid = _uid()
        _register(sid)
        tools = await _inspect_tools(sid)
        result = run_deterministic_scan(sid, tools)
        flagged = {f["name"]: f for f in result.get("tool_findings", [])}
        risky = {
            name for name, f in flagged.items()
            if "parameter" in f.get("finding", "").lower()
        }
        assert risky & {"exec_command", "send_to_webhook", "read_workspace_file", "hidden_exfil"}, (
            f"No risky-param tools flagged; got flags on: {set(flagged.keys())}"
        )

    async def test_hidden_exfil_destination_param_caught(self):
        sid = _uid()
        _register(sid)
        tools = await _inspect_tools(sid)
        result = run_deterministic_scan(sid, tools)
        flagged = {f["name"]: f for f in result.get("tool_findings", [])}
        assert "hidden_exfil" in flagged, (
            "hidden_exfil 'destination' param not flagged - "
            "_RISKY_PARAM_RE must include 'destination'"
        )

    async def test_safe_cleanup_caught_via_risky_param(self):
        sid = _uid()
        _register(sid)
        tools = await _inspect_tools(sid)
        result = run_deterministic_scan(sid, tools)
        flagged = {f["name"]: f for f in result.get("tool_findings", [])}
        assert "safe_cleanup" in flagged, (
            "safe_cleanup not flagged - 'directory' param should match _RISKY_PARAM_RE"
        )
        assert "parameter" in flagged["safe_cleanup"]["finding"].lower(), (
            "Expected safe_cleanup to be caught via risky 'directory' param, not name"
        )


class TestEffectClassification:
    """Correct effect_class assigned by classifier - no LLM required."""

    async def test_send_to_webhook_is_external_action(self):
        sid = _uid()
        _register(sid)
        await _inspect_tools(sid)
        assert _effect(sid, "send_to_webhook") == "external_action", (
            "send_to_webhook should be external_action"
        )

    async def test_exec_command_is_external_action(self):
        sid = _uid()
        _register(sid)
        await _inspect_tools(sid)
        assert _effect(sid, "exec_command") == "external_action", (
            "exec_command should be external_action"
        )

    async def test_read_workspace_file_is_read_only(self):
        sid = _uid()
        _register(sid)
        await _inspect_tools(sid)
        assert _effect(sid, "read_workspace_file") == "read_only", (
            "read_workspace_file should be read_only"
        )

    @pytest.mark.xfail(reason="'clean up' not in destructive verb patterns - classifier returns additive_write")
    async def test_safe_cleanup_is_destructive(self):
        sid = _uid()
        _register(sid)
        await _inspect_tools(sid)
        effect = _effect(sid, "safe_cleanup")
        assert effect == "destructive", (
            f"GAP: safe_cleanup classified as '{effect}'. "
            "'clean up temporary files' doesn't match destructive verb patterns "
            "(delete/remove/purge/wipe). The 'safe_' prefix further suppresses risk signals."
        )

    @pytest.mark.xfail(reason="get_env_var is correctly read_only but no credential-harvest signal at effect level")
    async def test_get_env_var_has_elevated_risk(self):
        sid = _uid()
        _register(sid)
        await _inspect_tools(sid)
        effect = _effect(sid, "get_env_var")
        assert effect not in ("read_only", "unknown"), (
            "GAP: get_env_var reads env vars (credentials) but is classified as read_only. "
            "The effect class is technically correct but carries no credential-harvest signal."
        )


class TestCompositionEdges:
    """Exfiltration paths detected via graph composition edges."""

    async def test_read_plus_external_creates_composition_edge(self):
        sid = _uid()
        _register(sid)
        await _full_inspect(sid)

        from mcpsafetywarden.graph.explain import explain_tool_risk
        result = explain_tool_risk(sid, "read_workspace_file")
        assert "error" not in result
        composition_risks = result.get("composition_risks", [])
        assert composition_risks, (
            "No composition risks for read_workspace_file despite external tools on same server"
        )
        external_in_paths = {r.get("external_tool") for r in composition_risks}
        assert external_in_paths & {"send_to_webhook", "exec_command"}, (
            f"Expected send_to_webhook or exec_command in paths, got: {external_in_paths}"
        )

    async def test_blast_radius_is_elevated(self):
        sid = _uid()
        _register(sid)
        await _full_inspect(sid)

        from mcpsafetywarden.graph.explain import explain_tool_risk
        result = explain_tool_risk(sid, "read_workspace_file")
        assert result.get("blast_radius") in ("critical", "high", "medium"), (
            f"Expected elevated blast radius for read+exfil server, got: {result.get('blast_radius')}"
        )
        assert result.get("blast_radius") != "none", (
            "blast_radius should not be 'none' when exfiltration paths exist"
        )

    @pytest.mark.xfail(reason="credential-harvest + exfil not scored higher than generic read + exfil")
    async def test_credential_harvest_plus_exfil_elevated(self):
        sid = _uid()
        _register(sid)
        await _full_inspect(sid)

        from mcpsafetywarden.graph.explain import explain_tool_risk
        r_env = explain_tool_risk(sid, "get_env_var")
        r_read = explain_tool_risk(sid, "read_workspace_file")
        score_env = r_env.get("composite_risk_score", 0)
        score_read = r_read.get("composite_risk_score", 0)
        assert score_env > score_read, (
            "GAP: get_env_var (credential harvest) + send_to_webhook should score higher "
            "than a generic read + send_to_webhook, but both are treated identically "
            "as read_only + external_action composition paths."
        )


class TestInteractionRisks:
    """Server-level risk patterns detected without LLM."""

    async def test_scope_mismatch_detected(self):
        sid = _uid()
        _register(sid)
        await _full_inspect(sid)

        from mcpsafetywarden.graph.explain import explain_tool_risk
        result = explain_tool_risk(sid, "read_workspace_file")
        patterns = {r["pattern"] for r in result.get("interaction_risks", [])}
        assert "scope_mismatch" in patterns, (
            "scope_mismatch not detected despite server having read + unblocked external tools"
        )

    async def test_interaction_risks_have_evidence_tier(self):
        sid = _uid()
        _register(sid)
        await _full_inspect(sid)

        from mcpsafetywarden.graph.explain import explain_tool_risk
        result = explain_tool_risk(sid, "read_workspace_file")
        for risk in result.get("interaction_risks", []):
            assert "confirmed_by" in risk, (
                f"GAP: interaction risk '{risk['pattern']}' has no confirmed_by field. "
                "Scores like 5.5 and 8.5 are indistinguishable from probe-confirmed evidence."
            )


class TestKnownGaps:
    """
    Explicit documentation of what the current system does NOT catch.
    Failing by design - these define the gap backlog.
    """

    @pytest.mark.xfail(reason="no behavioral probe: a tool claiming to read could secretly write")
    async def test_hidden_write_behind_read_name(self):
        sid = _uid()
        _register(sid)
        await _inspect_tools(sid)
        effect = _effect(sid, "read_workspace_file")
        assert effect != "read_only", (
            "GAP: a tool named read_workspace_file is classified read_only from name/description alone. "
            "Without a behavioral probe (call it and observe side effects) this is undetectable."
        )

    @pytest.mark.xfail(reason="name-description mismatch not scored higher than param-only matches")
    async def test_name_sentiment_vs_behavior_mismatch_scored(self):
        sid = _uid()
        _register(sid)
        tools = await _inspect_tools(sid)
        result = run_deterministic_scan(sid, tools)
        flagged = {f["name"]: f for f in result.get("tool_findings", [])}
        safe_cleanup_finding = flagged.get("safe_cleanup", {})
        assert safe_cleanup_finding.get("risk_level") in ("HIGH", "MEDIUM"), (
            "GAP: safe_cleanup is flagged LOW (via directory param) but the name-behavior "
            "mismatch ('safe_' prefix + destructive action) should elevate it to MEDIUM/HIGH. "
            "The scanner has no cross-check between name sentiment and description intent."
        )

    async def test_risk_scores_are_calibrated(self):
        sid = _uid()
        _register(sid)
        await _full_inspect(sid)

        from mcpsafetywarden.graph.explain import explain_tool_risk
        result = explain_tool_risk(sid, "read_workspace_file")
        for risk in result.get("interaction_risks", []):
            assert "precision_rate" in risk, (
                "GAP: scope_mismatch scores 5.5, cert_changed scores 8.5 - "
                "these are expert guesses. No feedback loop exists to correct them."
            )
