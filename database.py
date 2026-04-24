import logging
import os
import sqlite3
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional at-rest encryption for env_json / headers_json.
# Generate a key:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Then set: MCP_DB_ENCRYPTION_KEY=<generated_key>
# ---------------------------------------------------------------------------
_fernet = None
try:
    _key = os.environ.get("MCP_DB_ENCRYPTION_KEY")
    if _key:
        from cryptography.fernet import Fernet as _Fernet
        _fernet = _Fernet(_key.encode() if isinstance(_key, str) else _key)
except Exception as _fernet_err:
    _log.warning(
        "MCP_DB_ENCRYPTION_KEY is set but Fernet init failed (%s) - credentials stored plaintext.",
        _fernet_err,
    )

_MAX_SCHEMA_BYTES = 65_536  # 64 KB - oversized schemas are discarded to prevent DB bloat


def _encrypt_field(plaintext: str) -> str:
    """Encrypt a field for at-rest storage. Returns plaintext when encryption is not configured."""
    if _fernet is None:
        return plaintext
    return _fernet.encrypt(plaintext.encode()).decode()


def _decrypt_field(ciphertext: str) -> str:
    """Decrypt a stored field. Falls back to returning ciphertext for pre-encryption rows."""
    if _fernet is None:
        return ciphertext
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except Exception as _dec_err:
        _log.error(
            "_decrypt_field failed - key rotation or data corruption: %s. "
            "Check MCP_DB_ENCRYPTION_KEY. Returning empty string to prevent garbled data.",
            _dec_err,
        )
        return "{}"


def _jloads(s: str, default: Any) -> Any:
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError) as exc:
        _log.warning("_jloads: failed to parse stored JSON (%s) - returning default. Data may be corrupted or from a key rotation.", exc)
        return default

DB_PATH = Path(__file__).parent / "behavior_profiles.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript("""
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS servers (
                server_id     TEXT PRIMARY KEY,
                transport     TEXT NOT NULL CHECK(transport IN ('stdio', 'sse', 'streamable_http')),
                command       TEXT,
                args_json     TEXT DEFAULT '[]',
                url           TEXT,
                env_json      TEXT DEFAULT '{}',
                headers_json  TEXT DEFAULT '{}',
                registered_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tools (
                tool_id          TEXT PRIMARY KEY,
                server_id        TEXT NOT NULL REFERENCES servers(server_id),
                tool_name        TEXT NOT NULL,
                description      TEXT DEFAULT '',
                schema_json      TEXT DEFAULT '{}',
                annotations_json TEXT DEFAULT '{}',
                schema_hash      TEXT NOT NULL,
                discovered_at    TEXT NOT NULL,
                UNIQUE(server_id, tool_name)
            );

            CREATE TABLE IF NOT EXISTS tool_runs (
                run_id             INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_id            TEXT NOT NULL,
                args_hash          TEXT,
                args_json          TEXT,
                timestamp          TEXT NOT NULL,
                success            INTEGER NOT NULL,
                is_tool_error      INTEGER DEFAULT 0,
                latency_ms         REAL,
                output_size        INTEGER,
                output_schema_hash TEXT,
                output_preview     TEXT,
                notes              TEXT
            );

            CREATE TABLE IF NOT EXISTS behavior_profiles (
                tool_id               TEXT PRIMARY KEY REFERENCES tools(tool_id),
                effect_class          TEXT DEFAULT 'unknown',
                retry_safety          TEXT DEFAULT 'unknown',
                destructiveness       TEXT DEFAULT 'unknown',
                open_world            INTEGER DEFAULT 0,
                output_risk           TEXT DEFAULT 'unknown',
                latency_p50_ms        REAL,
                latency_p95_ms        REAL,
                failure_rate          REAL DEFAULT 0.0,
                output_size_p95_bytes INTEGER,
                schema_stability      REAL DEFAULT 1.0,
                confidence_json       TEXT DEFAULT '{}',
                evidence_json         TEXT DEFAULT '[]',
                run_count             INTEGER DEFAULT 0,
                updated_at            TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_scans (
                scan_id              INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id            TEXT NOT NULL,
                provider             TEXT NOT NULL,
                model_id             TEXT,
                overall_risk_level   TEXT,
                summary_text         TEXT,
                tool_findings_json   TEXT DEFAULT '[]',
                server_risks_json    TEXT DEFAULT '[]',
                raw_report_json      TEXT,
                scanned_at           TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tool_policies (
                server_id  TEXT NOT NULL,
                tool_name  TEXT NOT NULL,
                policy     TEXT NOT NULL CHECK(policy IN ('allow', 'block')),
                set_at     TEXT NOT NULL,
                PRIMARY KEY (server_id, tool_name)
            );

            CREATE INDEX IF NOT EXISTS idx_tool_runs_tool_id
                ON tool_runs(tool_id);
            CREATE INDEX IF NOT EXISTS idx_security_scans_server_scanned
                ON security_scans(server_id, scanned_at);
        """)
        conn.commit()
    finally:
        conn.close()
    # Restrict DB file to owner-only (no-op on Windows; meaningful on POSIX).
    try:
        DB_PATH.chmod(0o600)
    except OSError as e:
        _log.warning("Could not set restrictive permissions on %s: %s", DB_PATH, e)


def make_hash(data: Any) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]


def upsert_server(
    server_id: str,
    transport: str,
    command: Optional[str] = None,
    args: Optional[List[str]] = None,
    url: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO servers
                (server_id, transport, command, args_json, url, env_json, headers_json, registered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                transport=excluded.transport, command=excluded.command,
                args_json=excluded.args_json, url=excluded.url,
                env_json=excluded.env_json, headers_json=excluded.headers_json
            """,
            (
                server_id, transport, command,
                json.dumps(args or []),
                url,
                _encrypt_field(json.dumps(env or {})),
                _encrypt_field(json.dumps(headers or {})),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally: conn.close()


def get_server(server_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM servers WHERE server_id = ?", (server_id,)).fetchone()
        if row is None: return None
        d = dict(row)
        d["args"] = _jloads(d.pop("args_json", "[]"), [])
        d["env"] = _jloads(_decrypt_field(d.pop("env_json", "{}")), {})
        d["headers"] = _jloads(_decrypt_field(d.pop("headers_json", "{}")), {})
        return d
    finally: conn.close()


def list_servers() -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT s.*, COUNT(t.tool_id) AS tool_count
            FROM servers s
            LEFT JOIN tools t ON t.server_id = s.server_id
            GROUP BY s.server_id
            ORDER BY s.registered_at DESC
            """
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["args"] = _jloads(d.pop("args_json", "[]"), [])
            d["env"] = _jloads(_decrypt_field(d.pop("env_json", "{}")), {})
            d["headers"] = _jloads(_decrypt_field(d.pop("headers_json", "{}")), {})
            result.append(d)
        return result
    finally: conn.close()


def upsert_tool(
    server_id: str,
    tool_name: str,
    description: str,
    schema: Dict[str, Any],
    annotations: Dict[str, Any],
) -> str:
    if "::" in server_id or "::" in tool_name:
        raise ValueError("server_id and tool_name must not contain '::'")

    schema_hash = make_hash(schema)
    schema_json = json.dumps(schema)
    if len(schema_json.encode()) > _MAX_SCHEMA_BYTES:
        _log.warning(
            "Schema for %s::%s exceeds %d bytes; storing empty schema.",
            server_id, tool_name, _MAX_SCHEMA_BYTES,
        )
        schema_json = "{}"
        schema_hash = "OVERSIZED"

    # Stable ID - does NOT include schema_hash so that schema changes don't orphan
    # historical behavior_profiles and tool_runs rows.  schema_hash is stored
    # separately in the tools row for change-detection purposes.
    tool_id = f"{server_id}::{tool_name}"
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO tools
                (tool_id, server_id, tool_name, description, schema_json, annotations_json, schema_hash, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id, tool_name) DO UPDATE SET
                description=excluded.description, schema_json=excluded.schema_json,
                annotations_json=excluded.annotations_json, schema_hash=excluded.schema_hash
            """,
            (
                tool_id, server_id, tool_name, description,
                schema_json, json.dumps(annotations), schema_hash,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally: conn.close()
    return tool_id


def get_tool(server_id: str, tool_name: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM tools WHERE server_id = ? AND tool_name = ?",
            (server_id, tool_name),
        ).fetchone()
        if row is None: return None
        d = dict(row)
        d["schema"] = _jloads(d.pop("schema_json", "{}"), {})
        d["annotations"] = _jloads(d.pop("annotations_json", "{}"), {})
        return d
    finally: conn.close()


def list_tools(server_id: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM tools WHERE server_id = ? ORDER BY tool_name", (server_id,)
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["schema"] = _jloads(d.pop("schema_json", "{}"), {})
            d["annotations"] = _jloads(d.pop("annotations_json", "{}"), {})
            result.append(d)
        return result
    finally: conn.close()



def record_run(
    tool_id: str,
    args: Dict[str, Any],
    success: bool,
    is_tool_error: bool,
    latency_ms: float,
    output_size: int,
    output_schema_hash: str,
    output_preview: str,
    notes: str = "",
) -> int:
    args_hash = make_hash(args)
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO tool_runs
                (tool_id, args_hash, args_json, timestamp, success, is_tool_error,
                 latency_ms, output_size, output_schema_hash, output_preview, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tool_id, args_hash, json.dumps(args, default=str),
                datetime.now(timezone.utc).isoformat(),
                1 if success else 0,
                1 if is_tool_error else 0,
                latency_ms, output_size, output_schema_hash,
                (output_preview or "")[:500],
                notes,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally: conn.close()


def get_runs(tool_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM tool_runs WHERE tool_id = ? ORDER BY timestamp DESC LIMIT ?",
            (tool_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()



def upsert_profile(tool_id: str, profile: Dict[str, Any]) -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO behavior_profiles
                (tool_id, effect_class, retry_safety, destructiveness, open_world,
                 output_risk, latency_p50_ms, latency_p95_ms, failure_rate,
                 output_size_p95_bytes, schema_stability, confidence_json, evidence_json,
                 run_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tool_id) DO UPDATE SET
                effect_class=excluded.effect_class, retry_safety=excluded.retry_safety,
                destructiveness=excluded.destructiveness, open_world=excluded.open_world,
                output_risk=excluded.output_risk, latency_p50_ms=excluded.latency_p50_ms,
                latency_p95_ms=excluded.latency_p95_ms, failure_rate=excluded.failure_rate,
                output_size_p95_bytes=excluded.output_size_p95_bytes,
                schema_stability=excluded.schema_stability,
                confidence_json=excluded.confidence_json, evidence_json=excluded.evidence_json,
                run_count=excluded.run_count, updated_at=excluded.updated_at
            """,
            (
                tool_id,
                profile.get("effect_class", "unknown"),
                profile.get("retry_safety", "unknown"),
                profile.get("destructiveness", "unknown"),
                1 if profile.get("open_world", False) else 0,
                profile.get("output_risk", "unknown"),
                profile.get("latency_p50_ms"),
                profile.get("latency_p95_ms"),
                profile.get("failure_rate", 0.0),
                profile.get("output_size_p95_bytes"),
                profile.get("schema_stability", 1.0),
                json.dumps(profile.get("confidence", {})),
                json.dumps(profile.get("evidence", [])),
                profile.get("run_count", 0),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally: conn.close()


def get_profile(tool_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM behavior_profiles WHERE tool_id = ?", (tool_id,)
        ).fetchone()
        if row is None: return None
        d = dict(row)
        d["confidence"] = _jloads(d.pop("confidence_json", "{}"), {})
        d["evidence"] = _jloads(d.pop("evidence_json", "[]"), [])
        d["open_world"] = bool(d["open_world"])
        return d
    finally: conn.close()



def store_security_scan(server_id: str, findings: Dict[str, Any]) -> int:
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO security_scans
                (server_id, provider, model_id, overall_risk_level, summary_text,
                 tool_findings_json, server_risks_json, raw_report_json, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                findings.get("provider", "unknown"),
                findings.get("model"),
                findings.get("overall_risk_level"),
                findings.get("summary"),
                json.dumps(findings.get("tool_findings", [])),
                json.dumps(findings.get("server_level_risks", [])),
                json.dumps(findings),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally: conn.close()


def get_latest_security_scan(server_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT * FROM security_scans
            WHERE server_id = ?
            ORDER BY scanned_at DESC LIMIT 1
            """,
            (server_id,),
        ).fetchone()
        if row is None: return None
        d = dict(row)
        d["tool_findings"]      = _jloads(d.pop("tool_findings_json", "[]"), [])
        d["server_level_risks"] = _jloads(d.pop("server_risks_json", "[]"), [])
        d.pop("raw_report_json", None)
        return d
    finally: conn.close()


def get_tool_security_finding(server_id: str, tool_name: str) -> Optional[Dict[str, Any]]:
    scan = get_latest_security_scan(server_id)
    if not scan: return None
    for finding in scan.get("tool_findings", []):
        if finding.get("name") == tool_name: return finding
    return None


def set_tool_policy(server_id: str, tool_name: str, policy: Optional[str]) -> None:
    conn = get_connection()
    try:
        if policy is None:
            conn.execute(
                "DELETE FROM tool_policies WHERE server_id = ? AND tool_name = ?",
                (server_id, tool_name),
            )
        else:
            conn.execute(
                """
                INSERT INTO tool_policies (server_id, tool_name, policy, set_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(server_id, tool_name) DO UPDATE SET policy=excluded.policy, set_at=excluded.set_at
                """,
                (server_id, tool_name, policy, datetime.now(timezone.utc).isoformat()),
            )
        conn.commit()
    finally: conn.close()


def get_tool_policy(server_id: str, tool_name: str) -> Optional[str]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT policy FROM tool_policies WHERE server_id = ? AND tool_name = ?",
            (server_id, tool_name),
        ).fetchone()
        return row["policy"] if row else None
    finally: conn.close()
