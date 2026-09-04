"""Dashboard REST API tests against an isolated temporary database."""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

HEADERS = {"x-warden-client": "dashboard"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from mcpsafetywarden.core import database

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "dash.db")
    monkeypatch.setattr(database, "_initialized", False)

    database.upsert_server("alpha", "stdio", command="alpha-server")
    database.upsert_server("beta", "streamable_http", url="https://beta.example/mcp")
    read_id = database.upsert_tool("alpha", "read_file", "Read a file", {}, {})
    database.upsert_tool("alpha", "write_file", "Write a file", {}, {})
    database.upsert_tool("beta", "post_message", "Post a message", {}, {})
    database.set_tool_policy("alpha", "write_file", "block")
    database.record_run(read_id, {"path": "a"}, True, False, 12.0, 40, "h", "ok")
    database.record_run(read_id, {"path": "b"}, False, True, 30.0, 0, "h", "", "boom")
    database.store_security_scan(
        "alpha",
        {
            "provider": "rules",
            "overall_risk_level": "HIGH",
            "summary": "Write access is unconstrained.",
            "tool_findings": [
                {"name": "write_file", "risk_level": "HIGH", "finding": "Any path is writable."},
                {"name": "read_file", "risk_level": "LOW", "finding": "Reads any file."},
            ],
            "server_level_risks": [{"risk": "Read then write chain", "risk_level": "MEDIUM"}],
        },
    )

    from mcpsafetywarden import dashboard

    dashboard._scan_state.update({"current": None, "queue": [], "results": {}})
    with TestClient(dashboard.api) as c:
        yield c


def test_writes_require_dashboard_header(client):
    body = {"server_id": "alpha", "tool_name": "read_file", "policy": "block"}
    assert client.post("/api/policies", json=body).status_code == 403
    assert client.post("/api/policies", json=body, headers=HEADERS).status_code == 200


def test_cross_origin_write_is_rejected(client):
    body = {"server_id": "alpha", "tool_name": "read_file", "policy": "block"}
    r = client.post("/api/policies", json=body, headers={**HEADERS, "origin": "https://evil.example"})
    assert r.status_code == 403


def test_loopback_dev_proxy_origin_is_allowed(client):
    body = {"server_id": "alpha", "tool_name": "read_file", "policy": "allow"}
    local = {**HEADERS, "origin": "http://localhost:5173", "host": "127.0.0.1:7070"}
    assert client.post("/api/policies", json=body, headers=local).status_code == 200
    rebound = {**HEADERS, "origin": "http://attacker.example:7070", "host": "127.0.0.1:7070"}
    assert client.post("/api/policies", json=body, headers=rebound).status_code == 403


def test_tool_search_and_policy_filter_are_paginated_in_sql(client):
    r = client.get("/api/tools", params={"q": "file"}).json()
    assert r["total"] == 2
    assert {t["tool_name"] for t in r["items"]} == {"read_file", "write_file"}

    blocked = client.get("/api/tools", params={"policy": "block", "limit": 1}).json()
    assert blocked["total"] == 1
    assert blocked["items"][0]["tool_name"] == "write_file"

    unset = client.get("/api/tools", params={"policy": "none"}).json()
    assert unset["total"] == 2


def test_tool_activity_counts_recent_runs(client):
    r = client.get("/api/tools/activity", params={"days": 7}).json()
    assert len(r["days"]) == 7
    assert r["days"][-1] == datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert sum(r["tools"]["alpha::read_file"]) == 2
    assert sum(r["servers"]["alpha"]) == 2


def test_overview_reports_finding_counts_and_tool_risk(client):
    o = client.get("/api/overview").json()
    assert o["finding_counts"] == {"HIGH": 1, "LOW": 1}
    assert o["tool_risk_distribution"]["HIGH"] == 1
    assert o["tool_risk_distribution"]["NONE"] == 1
    assert o["last_scan_at"]


def test_findings_include_counts_by_level(client):
    r = client.get("/api/findings", params={"risk_level": "HIGH"}).json()
    assert r["total"] == 1
    assert r["counts"] == {"HIGH": 1, "LOW": 1}
    assert r["server_risks"][0]["risk"] == "Read then write chain"


def test_scans_require_authorization_and_run_in_order(client, monkeypatch):
    import mcpsafetywarden.server as srv

    seen = []

    async def fake_scan(server_id, confirm_authorized, background):
        assert confirm_authorized is True and background is False
        seen.append(server_id)
        await asyncio.sleep(0.01)
        return json.dumps({"overall_risk_level": "LOW"})

    monkeypatch.setattr(srv, "security_scan_server", fake_scan)

    assert client.post("/api/servers/alpha/scan", json={}, headers=HEADERS).status_code == 400
    assert (
        client.post("/api/servers/missing/scan", json={"confirm_authorized": True}, headers=HEADERS).status_code == 404
    )

    r = client.post(
        "/api/scans", json={"confirm_authorized": True, "server_ids": ["alpha", "beta", "ghost"]}, headers=HEADERS
    )
    assert r.json()["queued"] == ["alpha", "beta"]

    deadline = time.time() + 5
    status = client.get("/api/scans/status").json()
    while (status["current"] or status["queue"]) and time.time() < deadline:
        time.sleep(0.05)
        status = client.get("/api/scans/status").json()
    assert seen == ["alpha", "beta"]
    assert status["results"]["alpha"]["status"] == "completed"


def test_clear_scan_queue(client):
    from mcpsafetywarden import dashboard

    dashboard._scan_state["queue"].extend(["alpha", "beta"])
    r = client.delete("/api/scans/queue", headers=HEADERS).json()
    assert r["cleared"] == 2
    assert r["queue"] == []


def test_register_validates_input(client, monkeypatch):
    import mcpsafetywarden.server as srv

    async def fake_register(**kwargs):
        return json.dumps({"server_id": kwargs["server_id"], "tools_discovered": 0})

    monkeypatch.setattr(srv, "register_server", fake_register)

    assert client.post("/api/servers", json={"server_id": "gamma"}, headers=HEADERS).status_code == 400
    bad = {"server_id": "gamma", "transport": "ftp", "url": "ftp://x"}
    assert client.post("/api/servers", json=bad, headers=HEADERS).status_code == 400
    ok = {"server_id": "gamma", "transport": "stdio", "command": "gamma-server"}
    assert client.post("/api/servers", json=ok, headers=HEADERS).json()["server_id"] == "gamma"


def test_runs_stats_bucket_recent_runs(client):
    r = client.get("/api/runs/stats", params={"hours": 24}).json()
    assert sum(b["runs"] for b in r["series"]) == 2
    assert sum(b["failures"] for b in r["series"]) == 1
    hour = datetime.now(timezone.utc) - timedelta(hours=1)
    assert all(b["hour"] >= hour.strftime("%Y-%m-%dT00:00:00")[:10] for b in r["series"])


def test_runs_page_backwards_with_before_id(client):
    first = client.get("/api/runs", params={"limit": 1}).json()
    assert first["total"] == 2 and len(first["items"]) == 1
    older = client.get("/api/runs", params={"limit": 1, "before_id": first["items"][0]["run_id"]}).json()
    assert len(older["items"]) == 1
    assert older["items"][0]["run_id"] < first["items"][0]["run_id"]


def test_runs_cursor_follows_timestamp_order(client):
    from mcpsafetywarden.core import database

    conn = database.get_connection()
    ids = [r[0] for r in conn.execute("SELECT run_id FROM tool_runs ORDER BY run_id").fetchall()]
    conn.execute("UPDATE tool_runs SET timestamp=? WHERE run_id=?", ("2026-01-02T00:00:00+00:00", ids[0]))
    conn.execute("UPDATE tool_runs SET timestamp=? WHERE run_id=?", ("2026-01-01T00:00:00+00:00", ids[1]))
    conn.commit()
    conn.close()

    first = client.get("/api/runs", params={"limit": 1}).json()["items"][0]
    assert first["run_id"] == ids[0]
    rest = client.get("/api/runs", params={"limit": 5, "before_id": first["run_id"], "before_ts": first["timestamp"]}).json()
    assert [r["run_id"] for r in rest["items"]] == [ids[1]]


def test_scan_lookup_can_return_null_for_unscanned_servers(client):
    assert client.get("/api/servers/beta/scan").status_code == 404
    r = client.get("/api/servers/beta/scan", params={"missing_ok": True})
    assert r.status_code == 200 and r.json() is None
    assert client.get("/api/servers/alpha/scan", params={"missing_ok": True}).json()["overall_risk_level"] == "HIGH"
