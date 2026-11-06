"""SQLite persistence with atomic host claims and ticket creation."""

import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger("sentrix.database")
DB_PATH = os.getenv("SENTRIX_DB_PATH", str(Path(__file__).with_name("sentrix.db")))
APPROVAL_TTL = timedelta(minutes=30)

_SEED_INVENTORY = [
    ("192.168.10.50", "00:1A:2B:3C:4D:50", "192.168.1.2", "cisco_ios",
     "SW-CORE-CISCO-01", "Gi0/1", "Workstation"),
    ("192.168.10.51", "00:1A:2B:3C:4D:51", "192.168.1.3", "arista_eos",
     "SW-DIST-ARISTA-01", "Et1", "Workstation"),
    ("192.168.10.52", "00:1A:2B:3C:4D:52", "192.168.1.2", "cisco_ios",
     "SW-CORE-CISCO-01", "Gi0/2", "Workstation"),
    ("192.168.10.53", "00:1A:2B:3C:4D:53", "192.168.1.3", "arista_eos",
     "SW-DIST-ARISTA-01", "Et2", "Workstation"),
    ("192.168.10.100", "00:1A:2B:3C:4D:99", "192.168.1.2", "cisco_ios",
     "SW-CORE-CISCO-01", "Gi0/10", "Production File Server"),
    ("192.168.10.54", "00:1A:2B:3C:4D:54", "192.168.1.3", "arista_eos",
     "SW-DIST-ARISTA-01", "Et3", "Dev Workstation"),
]

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS network_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT NOT NULL UNIQUE,
    host_mac TEXT NOT NULL,
    switch_ip TEXT NOT NULL,
    switch_vendor TEXT NOT NULL,
    switch_hostname TEXT NOT NULL,
    port_interface TEXT NOT NULL,
    port_role TEXT NOT NULL DEFAULT 'Workstation',
    current_vlan INTEGER NOT NULL DEFAULT 10,
    port_status TEXT NOT NULL DEFAULT 'SECURE',
    span_status TEXT NOT NULL DEFAULT 'DISABLED',
    last_updated TEXT NOT NULL,
    previous_vlan INTEGER,
    previous_description TEXT
);
CREATE TABLE IF NOT EXISTS incident_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    attacker_ip TEXT NOT NULL,
    attacker_mac TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    signature TEXT NOT NULL,
    severity INTEGER NOT NULL,
    switch_hostname TEXT NOT NULL,
    vendor TEXT NOT NULL,
    isolated_port TEXT NOT NULL,
    assigned_vlan INTEGER NOT NULL,
    span_destination TEXT NOT NULL DEFAULT '',
    execution_time_ms REAL NOT NULL DEFAULT 0,
    executed_cli TEXT NOT NULL DEFAULT '[]',
    ticket_status TEXT NOT NULL DEFAULT 'CONTAINED'
);
CREATE TABLE IF NOT EXISTS operation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    completed_at TEXT NOT NULL,
    action TEXT NOT NULL,
    host_ip TEXT NOT NULL,
    result TEXT NOT NULL,
    message TEXT NOT NULL,
    execution_time_ms REAL NOT NULL DEFAULT 0,
    steps_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS switch_operation_locks (
    switch_ip TEXT PRIMARY KEY,
    host_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    claimed_at TEXT NOT NULL
);
"""


def _resolved_db_path() -> str:
    path = Path(DB_PATH).expanduser()
    if not path.is_absolute():
        path = Path(__file__).parent / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_resolved_db_path(), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn: sqlite3.Connection) -> None:
    inventory_columns = _columns(conn, "network_inventory")
    for name, kind in (
        ("previous_vlan", "INTEGER"),
        ("previous_description", "TEXT"),
        ("approval_requested_at", "TEXT"),
    ):
        if name not in inventory_columns:
            conn.execute(f"ALTER TABLE network_inventory ADD COLUMN {name} {kind}")

    ticket_columns = _columns(conn, "incident_tickets")
    if "execution_time_ms" not in ticket_columns:
        conn.execute(
            "ALTER TABLE incident_tickets ADD COLUMN execution_time_ms REAL NOT NULL DEFAULT 0"
        )
        if "response_time_ms" in ticket_columns:
            conn.execute(
                "UPDATE incident_tickets SET execution_time_ms = response_time_ms"
            )
    if "span_destination" not in ticket_columns:
        conn.execute(
            "ALTER TABLE incident_tickets ADD COLUMN span_destination TEXT NOT NULL DEFAULT ''"
        )
    conn.execute(
        """UPDATE network_inventory SET port_status = 'ISOLATED'
           WHERE port_status LIKE 'ISOLATED (%'"""
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    conn = _connect()
    try:
        conn.executescript(_SCHEMA_SQL)
        _migrate(conn)
        count = conn.execute("SELECT COUNT(*) FROM network_inventory").fetchone()[0]
        if count == 0:
            now = _now()
            conn.executemany(
                """INSERT INTO network_inventory
                   (host_ip, host_mac, switch_ip, switch_vendor, switch_hostname,
                    port_interface, port_role, current_vlan, port_status, span_status, last_updated)
                   VALUES (?,?,?,?,?,?,?,10,'SECURE','DISABLED',?)""",
                [(*record, now) for record in _SEED_INVENTORY],
            )
        conn.execute("BEGIN IMMEDIATE")
        stale = conn.execute(
            """UPDATE network_inventory SET port_status = 'ERROR_REQUIRES_REVIEW',
               last_updated = ? WHERE port_status IN ('ISOLATING', 'RESTORING')""",
            (_now(),),
        ).rowcount
        if stale:
            LOGGER.error("recovered_incomplete_operations count=%s", stale)
        conn.execute(
            """DELETE FROM switch_operation_locks
               WHERE host_ip IN (
                   SELECT host_ip FROM network_inventory
                   WHERE port_status NOT IN ('ISOLATING', 'RESTORING')
               )"""
        )
        _expire_stale_approvals(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    LOGGER.info("database_ready path=%s", _resolved_db_path())


def get_inventory() -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM network_inventory ORDER BY id")]
    finally:
        conn.close()


def lookup_host(ip: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM network_inventory WHERE host_ip = ?", (ip,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def register_discovered_host(record: Dict[str, Any]) -> Dict[str, Any]:
    """Atomically register a validated discovery result, or return an identical row."""
    required = {
        "host_ip", "host_mac", "switch_ip", "switch_vendor", "switch_hostname",
        "port_interface", "current_vlan",
    }
    if not required.issubset(record):
        raise ValueError("Discovered host record is incomplete.")
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """INSERT OR IGNORE INTO network_inventory
               (host_ip, host_mac, switch_ip, switch_vendor, switch_hostname,
                port_interface, port_role, current_vlan, port_status, span_status, last_updated)
               VALUES (?, ?, ?, ?, ?, ?, 'Workstation', ?, 'SECURE', 'DISABLED', ?)""",
            (
                record["host_ip"], record["host_mac"], record["switch_ip"],
                record["switch_vendor"], record["switch_hostname"],
                record["port_interface"], record["current_vlan"], _now(),
            ),
        )
        row = conn.execute(
            "SELECT * FROM network_inventory WHERE host_ip = ?", (record["host_ip"],)
        ).fetchone()
        if row is None:
            raise RuntimeError("Discovered host registration failed.")
        stored = dict(row)
        for field in ("host_mac", "switch_ip", "switch_vendor", "port_interface"):
            if stored[field].lower() != str(record[field]).lower():
                raise ValueError("Discovered host conflicts with an existing inventory record.")
        port_owner = conn.execute(
            """SELECT host_ip FROM network_inventory
               WHERE switch_ip = ? AND port_interface = ? AND host_ip != ?""",
            (record["switch_ip"], record["port_interface"], record["host_ip"]),
        ).fetchone()
        if port_owner is not None:
            raise ValueError("Discovered port is already assigned to another inventory host.")
        conn.commit()
        return stored
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_pending_approval(host_ip: str, alert_payload: Dict[str, Any]) -> bool:
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _expire_stale_approvals(conn)
        updated = conn.execute(
            """UPDATE network_inventory
               SET port_status = 'PENDING_APPROVAL', previous_description = ?,
                   approval_requested_at = ?, last_updated = ?
               WHERE host_ip = ? AND port_status = 'SECURE'""",
            (json.dumps(alert_payload), _now(), _now(), host_ip),
        ).rowcount
        if updated:
            _insert_operation(
                conn, "approval_requested", host_ip, "PENDING_APPROVAL",
                "Critical asset alert is awaiting human approval.", 0.0, [],
            )
        conn.commit()
        return updated == 1
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def resolve_pending_approval(
    host_ip: str, approved: bool, approver: str = "MOCK_OPERATOR"
) -> Optional[Dict[str, Any]]:
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _expire_stale_approvals(conn)
        _expire_stale_approvals(conn)
        row = conn.execute(
            """SELECT previous_description, approval_requested_at, last_updated
               FROM network_inventory
               WHERE host_ip = ? AND port_status = 'PENDING_APPROVAL'""",
            (host_ip,),
        ).fetchone()
        if row is None:
            conn.rollback()
            return None
        try:
            payload = json.loads(row["previous_description"] or "")
        except json.JSONDecodeError as exc:
            raise RuntimeError("Pending approval payload is invalid; manual review is required.") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Pending approval payload is invalid; manual review is required.")
        conn.execute(
            """UPDATE network_inventory SET port_status = 'SECURE',
               previous_description = NULL, approval_requested_at = NULL,
               last_updated = ? WHERE host_ip = ?""",
            (_now(), host_ip),
        )
        if not approved:
            _insert_operation(
                conn, "approval_rejected", host_ip, "REJECTED",
                f"Critical asset alert was rejected by operator {approver}.", 0.0, [],
            )
        else:
            _insert_operation(
                conn, "approval_approved", host_ip, "APPROVED",
                f"Critical asset alert was approved by operator {approver}.", 0.0, [],
            )
        conn.commit()
        return payload
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_secure_hosts() -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        return [
            dict(row) for row in conn.execute(
                "SELECT * FROM network_inventory WHERE port_status = 'SECURE' ORDER BY id"
            )
        ]
    finally:
        conn.close()


def claim_host(host_ip: str, action: str) -> Optional[Dict[str, Any]]:
    """Atomically transition one host into an in-progress state."""
    transitions = {
        "isolate": ("SECURE", "ISOLATING"),
        "restore": ("ISOLATED", "RESTORING"),
    }
    if action not in transitions:
        raise ValueError("Unsupported host operation.")
    expected, pending = transitions[action]
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM network_inventory WHERE host_ip = ?", (host_ip,)
        ).fetchone()
        if row is None or row["port_status"] != expected:
            conn.rollback()
            return None
        if action == "restore" and row["previous_vlan"] is None:
            conn.rollback()
            return None
        switch_lock = conn.execute(
            "SELECT host_ip FROM switch_operation_locks WHERE switch_ip = ?",
            (row["switch_ip"],),
        ).fetchone()
        if switch_lock is not None:
            conn.rollback()
            return None
        conn.execute(
            """INSERT INTO switch_operation_locks
               (switch_ip, host_ip, action, claimed_at) VALUES (?, ?, ?, ?)""",
            (row["switch_ip"], host_ip, action, _now()),
        )
        conn.execute(
            "UPDATE network_inventory SET port_status = ?, last_updated = ? WHERE host_ip = ?",
            (pending, _now(), host_ip),
        )
        result = dict(row)
        result["port_status"] = pending
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _insert_operation(
    conn: sqlite3.Connection,
    action: str,
    host_ip: str,
    result: str,
    message: str,
    execution_time_ms: float,
    steps: List[Dict[str, Any]],
) -> None:
    conn.execute(
        """INSERT INTO operation_log
           (completed_at, action, host_ip, result, message, execution_time_ms, steps_json)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (_now(), action, host_ip, result, message, execution_time_ms, json.dumps(steps)),
    )


def _expire_stale_approvals(conn: sqlite3.Connection) -> int:
    rows = conn.execute(
        """SELECT host_ip, COALESCE(approval_requested_at, last_updated) AS requested_at
           FROM network_inventory WHERE port_status = 'PENDING_APPROVAL'"""
    ).fetchall()
    now = datetime.now(timezone.utc)
    expired_hosts = []
    for row in rows:
        try:
            requested_at = (
                datetime.fromisoformat(row["requested_at"])
                if row["requested_at"] else None
            )
            if requested_at is not None and requested_at.tzinfo is None:
                requested_at = requested_at.replace(tzinfo=timezone.utc)
            expired = requested_at is None or now - requested_at > APPROVAL_TTL
        except (TypeError, ValueError):
            expired = True
        if expired:
            expired_hosts.append(row["host_ip"])
    for host_ip in expired_hosts:
        conn.execute(
            """UPDATE network_inventory SET port_status = 'SECURE',
               previous_description = NULL, approval_requested_at = NULL,
               last_updated = ? WHERE host_ip = ? AND port_status = 'PENDING_APPROVAL'""",
            (_now(), host_ip),
        )
        _insert_operation(
            conn, "approval_expired", host_ip, "EXPIRED",
            "Critical asset approval expired without operator action.", 0.0, [],
        )
    return len(expired_hosts)


def fail_operation(
    host_ip: str,
    action: str,
    safe_state: str,
    message: str,
    execution_time_ms: float,
    steps: List[Dict[str, Any]],
    previous_vlan: Optional[int] = None,
    previous_description: Optional[str] = None,
) -> None:
    if safe_state not in {"SECURE", "ISOLATED", "ERROR_REQUIRES_REVIEW"}:
        raise ValueError("Invalid operation recovery state.")
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """UPDATE network_inventory
               SET port_status = ?, previous_vlan = COALESCE(?, previous_vlan),
                   previous_description = COALESCE(?, previous_description), last_updated = ?
               WHERE host_ip = ?""",
            (safe_state, previous_vlan, previous_description, _now(), host_ip),
        )
        _insert_operation(
            conn, action, host_ip, "FAILED", message, execution_time_ms, steps
        )
        conn.execute(
            "DELETE FROM switch_operation_locks WHERE host_ip = ?", (host_ip,)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def finalize_isolation(
    host_ip: str,
    ticket_data: Dict[str, Any],
    assigned_vlan: int,
    previous_vlan: int,
    previous_description: str,
    span_destination: str,
    execution_time_ms: float,
    executed_cli: str,
    steps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT port_status FROM network_inventory WHERE host_ip = ?", (host_ip,)
        ).fetchone()
        if row is None or row["port_status"] != "ISOLATING":
            raise RuntimeError("Host operation claim was lost before finalization.")
        conn.execute(
            """UPDATE network_inventory SET current_vlan = ?, port_status = 'ISOLATED',
               span_status = ?, previous_vlan = ?, previous_description = ?, last_updated = ?
               WHERE host_ip = ?""",
            (
                assigned_vlan,
                f"ACTIVE -> {span_destination}" if span_destination else "DISABLED",
                previous_vlan,
                previous_description,
                _now(),
                host_ip,
            ),
        )
        last_number = conn.execute(
            """SELECT MAX(CAST(SUBSTR(ticket_id, 6) AS INTEGER))
               FROM incident_tickets WHERE ticket_id GLOB 'SNTX-[0-9]*'"""
        ).fetchone()[0]
        ticket_id = f"SNTX-{(last_number or 1000) + 1}"
        values = (
            ticket_id, _now(), ticket_data["attacker_ip"], ticket_data["attacker_mac"],
            ticket_data["target_ip"], ticket_data["signature"], ticket_data["severity"],
            ticket_data["switch_hostname"], ticket_data["vendor"], ticket_data["isolated_port"],
            assigned_vlan, span_destination, execution_time_ms, executed_cli, "CONTAINED",
        )
        conn.execute(
            """INSERT INTO incident_tickets
               (ticket_id, timestamp, attacker_ip, attacker_mac, target_ip, signature,
                severity, switch_hostname, vendor, isolated_port, assigned_vlan,
                span_destination, execution_time_ms, executed_cli, ticket_status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            values,
        )
        _insert_operation(
            conn, "isolate", host_ip, "SUCCESS", "Host isolation verified.",
            execution_time_ms, steps,
        )
        conn.execute(
            "DELETE FROM switch_operation_locks WHERE host_ip = ?", (host_ip,)
        )
        ticket = conn.execute(
            "SELECT * FROM incident_tickets WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()
        conn.commit()
        return dict(ticket)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def finalize_restoration(
    host_ip: str,
    previous_vlan: int,
    execution_time_ms: float,
    message: str,
    steps: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT * FROM network_inventory WHERE host_ip = ? AND port_status = 'RESTORING'""",
            (host_ip,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Host operation claim was lost before finalization.")
        conn.execute(
            """UPDATE network_inventory SET current_vlan = ?, port_status = 'SECURE',
               span_status = 'DISABLED', previous_vlan = NULL, previous_description = NULL,
               last_updated = ? WHERE host_ip = ?""",
            (previous_vlan, _now(), host_ip),
        )
        ticket_row = conn.execute(
            """SELECT * FROM incident_tickets WHERE attacker_ip = ?
               AND ticket_status = 'CONTAINED' ORDER BY id DESC LIMIT 1""",
            (host_ip,),
        ).fetchone()
        ticket = dict(ticket_row) if ticket_row else None
        if ticket_row:
            conn.execute(
                "UPDATE incident_tickets SET ticket_status = 'RESOLVED' WHERE ticket_id = ?",
                (ticket_row["ticket_id"],),
            )
        _insert_operation(
            conn, "restore", host_ip, "SUCCESS", message, execution_time_ms, steps
        )
        conn.execute(
            "DELETE FROM switch_operation_locks WHERE host_ip = ?", (host_ip,)
        )
        conn.commit()
        if ticket:
            ticket["ticket_status"] = "RESOLVED"
        return ticket
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_tickets() -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM incident_tickets ORDER BY id DESC")
        tickets = []
        for row in rows:
            ticket = dict(row)
            if "execution_time_ms" not in ticket:
                ticket["execution_time_ms"] = ticket.get("response_time_ms", 0)
            tickets.append(ticket)
        return tickets
    finally:
        conn.close()


def get_last_operation() -> Optional[Dict[str, Any]]:
    conn = _connect()
    try:
        row = conn.execute(
            """SELECT action, host_ip, result, message, completed_at
               FROM operation_log ORDER BY id DESC LIMIT 1"""
        ).fetchone()
        if row is None:
            return None
        operation = dict(row)
        operation["completed_at"] = operation.pop("completed_at")
        return operation
    finally:
        conn.close()


def count_isolated() -> int:
    conn = _connect()
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM network_inventory WHERE port_status = 'ISOLATED'"
        ).fetchone()[0]
    finally:
        conn.close()


def count_pending_approvals() -> int:
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _expire_stale_approvals(conn)
        count = conn.execute(
            "SELECT COUNT(*) FROM network_inventory WHERE port_status = 'PENDING_APPROVAL'"
        ).fetchone()[0]
        conn.commit()
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def count_active_span() -> int:
    conn = _connect()
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM network_inventory WHERE span_status != 'DISABLED'"
        ).fetchone()[0]
    finally:
        conn.close()


def count_switches() -> int:
    conn = _connect()
    try:
        return conn.execute(
            "SELECT COUNT(DISTINCT switch_hostname) FROM network_inventory"
        ).fetchone()[0]
    finally:
        conn.close()


def average_execution_time() -> float:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT AVG(execution_time_ms) FROM incident_tickets"
        ).fetchone()
        return round(row[0], 2) if row and row[0] else 0.0
    finally:
        conn.close()


def total_alerts() -> int:
    conn = _connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM incident_tickets").fetchone()[0]
    finally:
        conn.close()
