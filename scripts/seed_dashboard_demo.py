"""Fill a throwaway database with realistic demo data for dashboard development.

Usage:
    MCP_DB_PATH=/tmp/warden-demo.db python scripts/seed_dashboard_demo.py
    MCP_DB_PATH=/tmp/warden-demo.db mcpsafetywarden dashboard

Refuses to run without MCP_DB_PATH so it never touches a real database.
"""

import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

if not os.environ.get("MCP_DB_PATH"):
    sys.exit("Set MCP_DB_PATH to a throwaway database path first.")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcpsafetywarden.core import database as db  # noqa: E402
from mcpsafetywarden.graph import builder, store  # noqa: E402
from mcpsafetywarden.inventory.models import InventoryObject, InventoryRelation  # noqa: E402

random.seed(7)
NOW = datetime.now(timezone.utc)

SERVERS = [
    ("github", "streamable_http", None, [], "https://api.githubcopilot.com/mcp/"),
    ("filesystem", "stdio", "npx", ["-y", "@modelcontextprotocol/server-filesystem", "~/projects"], None),
    ("postgres", "stdio", "uvx", ["mcp-server-postgres", "postgresql://localhost/app"], None),
    ("fetch", "stdio", "uvx", ["mcp-server-fetch"], None),
    ("slack", "sse", None, [], "http://127.0.0.1:8081/sse"),
    ("memory", "stdio", "npx", ["-y", "@modelcontextprotocol/server-memory"], None),
]

TOOLS = [
    ("github", "get_file_contents", "Get the contents of a file or directory from a GitHub repository.", "read_only", "none", 540, 0.002, 120, 310),
    ("github", "create_issue", "Create a new issue in a GitHub repository.", "additive_write", "low", 212, 0.005, 180, 420),
    ("github", "push_files", "Push multiple files to a GitHub repository in a single commit.", "mutating_write", "medium", 38, 0.026, 640, 1900),
    ("github", "merge_pull_request", "Merge a pull request.", "mutating_write", "medium", 12, 0.0, 520, 880),
    ("github", "delete_repository", "Delete a repository. This action cannot be undone.", "destructive", "high", 0, 0.0, None, None),
    ("filesystem", "read_file", "Read the complete contents of a file from the file system.", "read_only", "none", 802, 0.001, 4, 11),
    ("filesystem", "write_file", "Create a new file or overwrite an existing file with new content.", "mutating_write", "high", 96, 0.01, 6, 18),
    ("filesystem", "move_file", "Move or rename files and directories.", "mutating_write", "medium", 14, 0.0, 5, 9),
    ("filesystem", "list_directory", "Get a detailed listing of all files and directories in a path.", "read_only", "none", 311, 0.0, 3, 7),
    ("postgres", "execute_sql", "Execute any SQL statement against the connected database.", "destructive", "high", 57, 0.07, 22, 140),
    ("postgres", "query", "Run a read-only SQL query.", "read_only", "none", 233, 0.004, 14, 60),
    ("postgres", "list_tables", "List tables in the public schema.", "read_only", "none", 41, 0.0, 18, 30),
    ("fetch", "fetch", "Fetch a URL from the internet and extract its contents as markdown.", "external_action", "medium", 143, 0.035, 480, 2200),
    ("slack", "post_message", "Post a new message to a Slack channel.", "external_action", "low", 64, 0.0, 210, 560),
    ("slack", "list_channels", "List public channels in the workspace.", "read_only", "none", 22, 0.0, 190, 300),
    ("memory", "read_graph", "Read the entire knowledge graph.", "read_only", "none", 48, 0.0, 9, 21),
    ("memory", "create_entities", "Create multiple new entities in the knowledge graph.", "additive_write", "low", 31, 0.0, 10, 19),
    ("memory", "delete_entities", "Delete multiple entities and their relations.", "destructive", "medium", 3, 0.0, 11, 14),
]

FINDINGS = {
    "postgres": ("CRITICAL", [
        ("execute_sql", "CRITICAL", "Arbitrary SQL execution, including DDL and DROP.", ["arbitrary_exec"], ["T1485"],
         "A prompt-injected instruction asks the agent to clean up stale rows and it issues DROP TABLE sessions.",
         "Block execute_sql and route reads through the query tool, or connect with a SELECT-only role."),
    ], [{"risk": "Connection role owns the schema, so any write tool can alter tables.", "risk_level": "HIGH", "tools_involved": ["execute_sql"]}]),
    "github": ("CRITICAL", [
        ("delete_repository", "CRITICAL", "Irreversible repository deletion with no confirmation step.", ["arbitrary_exec"], ["T1485"],
         "An agent asked to tidy up forks deletes a production repository.",
         "Keep the tool blocked and require manual approval for deletions."),
        ("push_files", "HIGH", "Pushes directly to protected branches.", ["tool_poisoning"], [],
         "A poisoned issue asks the agent to hotfix main, landing unreviewed code.",
         "Require a feature-branch prefix via policy and rely on branch protection."),
        ("get_file_contents", "LOW", "Unbounded output can flood the context window.", [], ["T1499"],
         "A multi-megabyte file pushes earlier instructions out of the context.",
         "Set an output size limit for this tool."),
    ], [{"risk": "Content read with get_file_contents can steer push_files.", "risk_level": "HIGH", "tools_involved": ["get_file_contents", "push_files"]}]),
    "filesystem": ("HIGH", [
        ("write_file", "HIGH", "Write path is not constrained to the configured roots.", ["filesystem_access"], [],
         "A crafted path like ../../.bashrc overwrites shell startup files.",
         "Pin allowed directories and reject paths containing '..'."),
    ], [{"risk": "read_file plus write_file allows copying secrets into tracked files.", "risk_level": "MEDIUM", "tools_involved": ["read_file", "write_file"]}]),
    "fetch": ("HIGH", [
        ("fetch", "HIGH", "Requests can reach internal and link-local addresses.", ["credential_exposure", "data_exfiltration"], [],
         "A malicious page instructs the agent to fetch the cloud metadata endpoint.",
         "Restrict fetch to public hosts or run it without access to internal ranges."),
    ], []),
    "slack": ("MEDIUM", [
        ("post_message", "MEDIUM", "Messages can carry workspace data to external channels.", ["data_exfiltration"], [],
         "Data read from another tool is posted to a shared external channel.",
         "Limit the channel argument to an allowlist of internal channels."),
    ], []),
    "memory": ("LOW", [
        ("delete_entities", "MEDIUM", "Bulk deletion accepts an unbounded list.", [], ["T1485"],
         "One call can wipe the knowledge graph.", "Cap the list length through a policy."),
    ], []),
}

POLICIES = [("github", "delete_repository", "block"), ("postgres", "execute_sql", "block"),
            ("memory", "delete_entities", "block"), ("filesystem", "write_file", "allow"),
            ("github", "create_issue", "allow"), ("fetch", "fetch", "allow")]


def seed() -> None:
    for sid, transport, command, args, url in SERVERS:
        db.upsert_server(sid, transport, command=command, args=args, url=url)
        builder.on_server_registered(sid, transport, command, url)

    stamps = []
    for sid, name, desc, effect, destr, runs, fail, p50, p95 in TOOLS:
        tool_id = db.upsert_tool(sid, name, desc, {"type": "object"}, {})
        db.upsert_profile(tool_id, {
            "effect_class": effect, "retry_safety": "safe" if effect == "read_only" else "unsafe",
            "destructiveness": destr, "open_world": effect == "external_action", "output_risk": "low",
            "latency_p50_ms": p50, "latency_p95_ms": p95, "failure_rate": fail, "output_size_p95_bytes": 4096,
            "schema_stability": "stable", "confidence": {"effect_class": 0.9}, "evidence": [], "run_count": runs,
        })
        for _ in range(min(runs, 60)):
            ok = random.random() > max(fail, 0.01) * 3
            run_id = db.record_run(tool_id, {"n": random.randint(1, 999)}, ok, not ok and random.random() < 0.5,
                                   (p50 or 20) * random.uniform(0.6, 2.2), random.randint(80, 60000), "h",
                                   "ok" if ok else "", "" if ok else random.choice(["Timeout after 10s", "422 Unprocessable Entity"]))
            ts = NOW - timedelta(days=random.choices(range(7), weights=[6, 5, 4, 3, 3, 2, 2])[0], hours=random.uniform(0, 23.9))
            stamps.append((ts.isoformat(), run_id))
    conn = db.get_connection()
    conn.executemany("UPDATE tool_runs SET timestamp=? WHERE run_id=?", stamps)
    conn.commit()
    conn.close()

    for sid, _, _, _, _ in SERVERS:
        rows = [t for t in TOOLS if t[0] == sid]
        builder.on_tools_inspected(sid, [{"tool_name": t[1], "description": t[2], "effect_class": t[3], "destructiveness": t[4]} for t in rows], tamper_check=False)
        db.upsert_tool_snapshot(sid, {t[1]: db.make_hash(t[2]) for t in rows[:-1]} if sid == "github" else {t[1]: db.make_hash(t[2]) for t in rows})

    db.upsert_tool_snapshot("github", {t[1]: db.make_hash(t[2]) for t in TOOLS if t[0] == "github"})

    for sid, (overall, findings, server_risks) in FINDINGS.items():
        report = {
            "provider": "mcpsafety+rules", "overall_risk_level": overall,
            "summary": f"{sid} exposes tools that can change or leak data. The riskiest are listed with fixes.",
            "tool_findings": [
                {"name": n, "risk_level": lvl, "finding": f, "risk_tags": tags, "mitre_techniques": mitre,
                 "exploitation_scenario": x, "remediation": r, "evidence_basis": "static_analysis"}
                for n, lvl, f, tags, mitre, x, r in findings
            ],
            "server_level_risks": server_risks,
        }
        db.store_security_scan(sid, report)
        builder.on_scan_stored(sid, report)

    for sid, tool, policy in POLICIES:
        db.set_tool_policy(sid, tool, policy)

    for disc_id, client, client_name, path, servers in [
        ("disc-claude", "claude-desktop", "Claude Desktop", "~/AppData/Roaming/Claude/claude_desktop_config.json", ["github", "filesystem", "fetch", "slack"]),
        ("disc-cursor", "cursor", "Cursor", "~/.cursor/mcp.json", ["filesystem", "postgres", "memory"]),
    ]:
        for sid in servers:
            did = f"{disc_id}-{sid}"
            db.upsert_discovered_server({"discovery_id": did, "client": client, "client_name": client_name, "scope": "user",
                                         "config_path": path, "server_name": sid, "transport": "stdio", "command": "npx",
                                         "args": [], "confidence": "official"})
            conn = db.get_connection()
            conn.execute("UPDATE discovered_servers SET registered_server_id=? WHERE discovery_id=?", (sid, did))
            conn.commit()
            conn.close()
            builder.on_server_discovered(did, client, client_name, sid, sid)
    db.upsert_discovered_server({"discovery_id": "disc-cursor-brave", "client": "cursor", "client_name": "Cursor", "scope": "user",
                                 "config_path": "~/.cursor/mcp.json", "server_name": "brave-search", "transport": "stdio",
                                 "command": "npx", "args": ["-y", "@modelcontextprotocol/server-brave-search"], "confidence": "official"})

    for sid, key in [("github", "GITHUB_PERSONAL_ACCESS_TOKEN"), ("postgres", "DATABASE_URL"), ("slack", "SLACK_BOT_TOKEN")]:
        builder.on_credentials_detected(sid, [key], [])

    for sid, pkg, eco in [("filesystem", "@modelcontextprotocol/server-filesystem", "npm"), ("postgres", "mcp-server-postgres", "pypi"),
                          ("fetch", "mcp-server-fetch", "pypi"), ("memory", "@modelcontextprotocol/server-memory", "npm")]:
        pid = f"package::{eco}::{pkg}"
        store.upsert_object(InventoryObject(id=pid, type="package", name=pkg, source="demo", metadata={"ecosystem": eco, "server_id": sid}))
        store.upsert_relation(InventoryRelation(source_id=sid, target_id=pid, relation="depends_on", metadata={}))

    for src, dst, rel in [("fetch::fetch", "slack::post_message", "cross_server_exfil"),
                          ("filesystem::read_file", "slack::post_message", "cross_server_exfil"),
                          ("github::get_file_contents", "github::push_files", "can_exfiltrate")]:
        store.upsert_relation(InventoryRelation(source_id=src, target_id=dst, relation=rel,
                                                metadata={"risk_level": "HIGH", "reason": "Untrusted content can reach an outbound or write action."}))

    print(json.dumps({"db": str(db.DB_PATH), "servers": len(SERVERS), "tools": len(TOOLS)}))


if __name__ == "__main__":
    seed()
