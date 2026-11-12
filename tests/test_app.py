import json
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import containment
import database as db
import main
from main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRIX_MODE", "MOCK")
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setitem(containment._TELEGRAM_RUNTIME_CONFIG, "token", None)
    monkeypatch.setitem(containment._TELEGRAM_RUNTIME_CONFIG, "chat_id", None)
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    with TestClient(app) as test_client:
        yield test_client


def test_mock_alert_and_restore_are_persisted_atomically(client):
    response = client.post(
        "/api/webhook/alert",
        json={
            "attacker_ip": "192.168.10.50",
            "target_ip": "192.168.10.100",
            "signature": "Authorized unit test alert",
            "severity": 2,
        },
    )
    assert response.status_code == 200
    ticket = response.json()
    assert ticket["ticket_id"] == "SNTX-1001"
    assert ticket["assigned_vlan"] == 999
    assert ticket["execution_time_ms"] >= 0
    executed_cli = json.loads(ticket["executed_cli"])
    vlan_change = executed_cli.index("switchport access vlan 999")
    assert executed_cli[vlan_change + 1:vlan_change + 3] == ["shutdown", "no shutdown"]
    assert db.lookup_host("192.168.10.50")["port_status"] == "ISOLATED"
    assert db.lookup_host("192.168.10.50")["previous_vlan"] == 10

    state = client.get("/api/state").json()
    assert state["metrics"]["currently_isolated"] == 1
    assert state["metrics"]["average_execution_time_ms"] >= 0
    assert "avg_mttr_ms" not in state["metrics"]
    assert state["last_operation"]["result"] == "SUCCESS"

    restored = client.post("/api/ports/192.168.10.50/restore")
    assert restored.status_code == 200
    assert restored.json()["resolved_ticket"] == "SNTX-1001"
    host = db.lookup_host("192.168.10.50")
    assert host["port_status"] == "SECURE"
    assert host["current_vlan"] == 10
    assert host["previous_vlan"] is None
    assert client.get("/api/state").json()["tickets"][0]["ticket_status"] == "RESOLVED"


def test_mock_simulation_is_available_and_mode_is_not_http_switchable(client):
    response = client.post("/api/simulate/attack", json={"attacker_ip": "192.168.10.54"})
    assert response.status_code == 200
    assert response.json()["signature"].startswith("SENTRIX lab test alert:")
    assert client.post("/api/mode/toggle").status_code == 404


def test_invalid_alerts_have_stable_validation_error(client):
    response = client.post(
        "/api/webhook/alert",
        json={
            "attacker_ip": "not-an-ip",
            "target_ip": "192.168.10.1",
            "signature": "bad",
            "severity": 9,
        },
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request payload."}


def test_host_must_be_in_inventory(client):
    response = client.post(
        "/api/webhook/alert",
        json={
            "attacker_ip": "192.168.10.250",
            "target_ip": "192.168.10.100",
            "signature": "test",
            "severity": 1,
            "auto_discover": False,
        },
    )
    assert response.status_code == 404
    assert db.total_alerts() == 0


def test_mock_auto_discovery_registers_host_and_returns_discovery_trace(client):
    response = client.post(
        "/api/webhook/alert",
        json={
            "attacker_ip": "192.168.10.77",
            "target_ip": "192.168.10.100",
            "signature": "unknown host discovery test",
            "severity": 2,
        },
    )
    assert response.status_code == 200
    host = db.lookup_host("192.168.10.77")
    assert host["host_mac"] == "00:1A:2B:99:88:4D"
    assert host["port_interface"] == "Gi0/77"
    assert host["port_status"] == "ISOLATED"
    assert "shutdown" in response.json()["executed_cli"]

    manual = client.post("/api/discover/192.168.10.78")
    assert manual.status_code == 200
    assert "show ip arp 192.168.10.78" in manual.json()["discovery_cli"]
    assert "show cdp neighbors" in manual.json()["discovery_cli"]
    assert db.lookup_host("192.168.10.78")["port_status"] == "SECURE"


def test_critical_server_alert_requires_approval_and_can_be_rejected_or_approved(client):
    pending = client.post(
        "/api/simulate/attack",
        json={"attacker_ip": "192.168.10.100", "containment_mode": "vlan"},
    )
    assert pending.status_code == 202
    assert pending.json()["status"] == "PENDING_APPROVAL"
    assert db.lookup_host("192.168.10.100")["port_status"] == "PENDING_APPROVAL"
    assert client.get("/api/state").json()["metrics"]["pending_approvals"] == 1

    rejected = client.post("/api/approvals/192.168.10.100/reject")
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert db.lookup_host("192.168.10.100")["port_status"] == "SECURE"
    assert db.get_last_operation()["action"] == "approval_rejected"

    pending_again = client.post(
        "/api/simulate/attack",
        json={"attacker_ip": "192.168.10.100", "containment_mode": "vlan"},
    )
    assert pending_again.status_code == 202
    approved = client.post("/api/approvals/192.168.10.100/approve")
    assert approved.status_code == 200
    assert approved.json()["attacker_ip"] == "192.168.10.100"
    assert db.lookup_host("192.168.10.100")["port_status"] == "ISOLATED"


def _create_chatops_demo_alert(client):
    response = client.post("/api/chatops/test")
    assert response.status_code == 202
    pending = response.json()
    assert pending["status"] == "PENDING_APPROVAL"
    return pending["alert_id"]


def test_chatops_vlan_approval_creates_ticket_with_channel_and_audit(client):
    alert_id = _create_chatops_demo_alert(client)
    pending = client.get("/api/state").json()["pending_approvals"]
    assert pending[0]["alert_id"] == alert_id
    assert pending[0]["asset_name"] == "Production File Server"
    assert pending[0]["discovered_port"] == "Gi0/10"

    response = client.post(
        "/api/chatops/action",
        json={
            "alert_id": alert_id,
            "action": "approve_vlan",
            "channel": "Mobile Simulator",
        },
    )

    assert response.status_code == 200
    ticket = response.json()
    assert ticket["containment_mode"] == "vlan"
    assert ticket["approval_channel"] == "Mobile Simulator"
    assert ticket["approved_action"] == "vlan_isolation"
    assert ticket["approval_response_ms"] >= ticket["execution_time_ms"]
    assert "switchport access vlan 999" in ticket["executed_cli"]
    operation = db.get_last_operation()
    assert operation["approval_channel"] == "Mobile Simulator"
    assert operation["approved_action"] == "vlan_isolation"
    assert operation["executed_cli"] == ticket["executed_cli"]


def test_chatops_acl_approval_uses_surgical_acl_and_audits(client):
    alert_id = _create_chatops_demo_alert(client)

    response = client.post(
        "/api/chatops/action",
        json={
            "alert_id": alert_id,
            "action": "approve_acl",
            "channel": "Mobile Simulator",
        },
    )

    assert response.status_code == 200
    ticket = response.json()
    assert ticket["containment_mode"] == "acl"
    assert ticket["approval_channel"] == "Mobile Simulator"
    assert ticket["approved_action"] == "surgical_acl"
    assert "ip access-group SENTRIX_ACL_192_168_10_100 in" in ticket["executed_cli"]
    assert db.lookup_host("192.168.10.100")["current_vlan"] == 10


def test_chatops_rejection_is_audited_without_creating_containment_ticket(client):
    alert_id = _create_chatops_demo_alert(client)

    response = client.post(
        "/api/chatops/action",
        json={
            "alert_id": alert_id,
            "action": "reject",
            "channel": "Mobile Simulator",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"
    assert db.lookup_host("192.168.10.100")["port_status"] == "SECURE"
    assert db.total_alerts() == 0
    operation = db.get_last_operation()
    assert operation["approval_channel"] == "Mobile Simulator"
    assert operation["approved_action"] == "rejected"
    assert operation["approval_response_ms"] >= 0


def test_chatops_vlan_approval_respects_trunk_guard(client, monkeypatch):
    alert_id = _create_chatops_demo_alert(client)

    def trunk_hunt(ip, record):
        return {
            "target_ip": ip,
            "resolved_mac": record["host_mac"].lower(),
            "switch_ip": record["switch_ip"],
            "switch_hostname": record["switch_hostname"],
            "port": record["port_interface"],
            "port_type": "trunk",
            "trunk_guard_override": True,
            "warning": "⚠️ Trunk Port Detected — Auto-Switched to Surgical ACL to Prevent Uplink Outage",
            "hunt_time_ms": 1.0,
            "trace": [],
            "hunt_cli": ["show ip arp 192.168.10.100"],
        }

    monkeypatch.setattr(containment, "hunt_ip_port", trunk_hunt)
    response = client.post(
        "/api/chatops/action",
        json={
            "alert_id": alert_id,
            "action": "approve_vlan",
            "channel": "Mobile Simulator",
        },
    )

    assert response.status_code == 200
    ticket = response.json()
    assert ticket["containment_mode"] == "acl"
    assert ticket["approved_action"] == "surgical_acl"
    assert "ip access-group SENTRIX_ACL_192_168_10_100 in" in ticket["executed_cli"]
    assert "shutdown" not in ticket["executed_cli"]
    assert "Trunk Port Detected" in ticket["trunk_guard_warning"]


def test_chatops_config_is_masked_and_runtime_update_is_not_returned(client):
    before = client.get("/api/chatops/config").json()
    assert "telegram_bot_token" not in before

    updated = client.post(
        "/api/chatops/config",
        json={"telegram_bot_token": "123456:secret-token"},
    )
    assert updated.status_code == 200
    assert updated.json()["configured"] is False
    status = client.get("/api/chatops/config").json()
    assert status["token_configured"] is True
    assert status["chat_id_configured"] is False
    assert "secret-token" not in json.dumps(status)


def test_critical_alert_schedules_telegram_notification_with_trace(client, monkeypatch):
    sent = []
    monkeypatch.setattr(
        main.containment,
        "send_telegram_approval",
        lambda payload: sent.append(payload),
    )

    response = client.post(
        "/api/webhook/alert",
        json={
            "attacker_ip": "192.168.10.100",
            "target_ip": "192.168.10.50",
            "signature": "critical notification test",
            "severity": 5,
        },
    )

    assert response.status_code == 202
    assert len(sent) == 1
    assert sent[0]["approval_id"] == response.json()["alert_id"]
    assert sent[0]["asset_name"] == "Production File Server"
    assert sent[0]["approval_hunt"]["switch_hostname"] == "SW-CORE-CISCO-01"
    assert sent[0]["approval_hunt"]["port"] == "Gi0/10"
    assert sent[0]["severity"] == 5


def test_telegram_notification_sends_all_three_callback_actions(monkeypatch):
    monkeypatch.setitem(
        containment._TELEGRAM_RUNTIME_CONFIG, "token", "123456:secret-token"
    )
    monkeypatch.setitem(
        containment._TELEGRAM_RUNTIME_CONFIG, "chat_id", "987654321"
    )
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["payload"] = kwargs["json"]
        return FakeResponse()

    monkeypatch.setattr(containment.httpx, "post", fake_post)
    sent = containment.send_telegram_approval({
        "approval_id": "a" * 32,
        "attacker_ip": "192.168.10.100",
        "asset_name": "Production File Server",
        "severity": 4,
        "approval_hunt": {
            "switch_hostname": "SW-CORE-CISCO-01",
            "port": "Gi0/10",
            "port_type": "access",
        },
    })

    assert sent is True
    assert "secret-token" in captured["url"]
    assert captured["payload"]["chat_id"] == "987654321"
    buttons = captured["payload"]["reply_markup"]["inline_keyboard"]
    assert buttons[0][0]["callback_data"] == f"approve_vlan:{'a' * 32}"
    assert buttons[0][1]["callback_data"] == f"approve_acl:{'a' * 32}"
    assert buttons[1][0]["callback_data"] == f"reject:{'a' * 32}"


def test_mock_acl_containment_and_restore_leave_vlan_unchanged(client):
    response = client.post(
        "/api/webhook/alert",
        json={
            "attacker_ip": "192.168.10.50",
            "target_ip": "192.168.10.100",
            "signature": "surgical ACL test",
            "severity": 2,
            "containment_mode": "acl",
        },
    )
    assert response.status_code == 200
    ticket = response.json()
    commands = json.loads(ticket["executed_cli"])
    assert commands[:4] == [
        "ip access-list extended SENTRIX_ACL_192_168_10_50",
        "deny ip host 192.168.10.50 host 192.168.10.100",
        "permit ip any any",
        "exit",
    ]
    assert f"ip access-group SENTRIX_ACL_192_168_10_50 in" in commands
    host = db.lookup_host("192.168.10.50")
    assert host["current_vlan"] == 10
    assert host["previous_description"] == "MODE:acl"

    restored = client.post("/api/ports/192.168.10.50/restore")
    assert restored.status_code == 200
    host = db.lookup_host("192.168.10.50")
    assert host["port_status"] == "SECURE"
    assert host["current_vlan"] == 10
    assert host["previous_description"] is None


def test_ip_hunt_traces_uplink_hop_and_manual_trace_is_read_only(client):
    response = client.post("/api/hunt/192.168.10.52")

    assert response.status_code == 200
    trace = response.json()
    assert trace["resolved_mac"] == "00:1a:2b:3c:4d:52"
    assert trace["switch_hostname"] == "SW-CORE-CISCO-01"
    assert trace["port"] == "Gi0/2"
    assert trace["port_type"] == "access"
    assert trace["trunk_guard_override"] is False
    assert "show ip arp 192.168.10.52" in trace["hunt_cli"]
    assert "show interfaces Gi0/1 switchport" in trace["hunt_cli"]
    assert "show cdp neighbors Gi0/1 detail" in trace["hunt_cli"]
    assert "show mac address-table address 001a.2b3c.4d52" in trace["hunt_cli"]
    assert "show mac address-table interface Gi0/2" in trace["hunt_cli"]
    assert db.lookup_host("192.168.10.52")["port_status"] == "SECURE"

    trunk_trace = client.post("/api/hunt/192.168.10.29").json()
    assert trunk_trace["port_type"] == "trunk"
    assert trunk_trace["trunk_guard_override"] is True
    assert "show interfaces Gi0/29 switchport" in trunk_trace["hunt_cli"]


def test_multi_mac_alert_automatically_uses_surgical_acl_and_audits_hunt(client):
    response = client.post(
        "/api/webhook/alert",
        json={
            "attacker_ip": "192.168.10.51",
            "target_ip": "192.168.10.100",
            "signature": "multi-MAC trunk guard test",
            "severity": 2,
            "containment_mode": "vlan",
        },
    )

    assert response.status_code == 200
    ticket = response.json()
    commands = json.loads(ticket["executed_cli"])
    assert ticket["containment_mode"] == "acl"
    assert ticket["port_type"] == "multi-mac"
    assert ticket["trunk_guard_warning"] == (
        "⚠️ Trunk Port Detected — Auto-Switched to Surgical ACL to Prevent Uplink Outage"
    )
    assert ticket["hunt_time_ms"] >= 0
    trace = json.loads(ticket["hunt_trace_json"])
    assert trace["trunk_guard_override"] is True
    assert "show mac address-table interface Et1" in trace["hunt_cli"]
    assert "ip access-group SENTRIX_ACL_192_168_10_51 in" in commands
    assert "shutdown" not in commands
    assert db.lookup_host("192.168.10.51")["current_vlan"] == 10
    audit = db.get_last_operation()
    assert audit["result"] == "SUCCESS"
    conn = db._connect()
    try:
        audit_steps = json.loads(conn.execute(
            "SELECT steps_json FROM operation_log ORDER BY id DESC LIMIT 1"
        ).fetchone()["steps_json"])
    finally:
        conn.close()
    assert audit_steps[0]["step"] == "ip_to_port_hunt"
    assert "show ip arp 192.168.10.51" in audit_steps[0]["commands"]


def test_concurrent_host_claim_allows_only_one_operation(client):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: db.claim_host("192.168.10.50", "isolate"), range(2)))
    assert sum(result is not None for result in results) == 1
    assert db.lookup_host("192.168.10.50")["port_status"] == "ISOLATING"


def test_switch_lock_serializes_different_hosts_and_releases_after_failure(client):
    claim = db.claim_host("192.168.10.50", "isolate")
    assert claim is not None
    assert db.claim_host("192.168.10.52", "isolate") is None

    db.fail_operation(
        "192.168.10.50", "isolate", "SECURE",
        "test release", 0.0, [],
    )
    second_claim = db.claim_host("192.168.10.52", "isolate")
    assert second_claim is not None
    db.fail_operation(
        "192.168.10.52", "isolate", "SECURE",
        "test cleanup", 0.0, [],
    )


def test_pending_approval_expires_and_is_audited(client):
    assert db.mark_pending_approval(
        "192.168.10.50",
        {"attacker_ip": "192.168.10.50", "target_ip": "192.168.10.100"},
    )
    conn = db._connect()
    try:
        conn.execute(
            """UPDATE network_inventory SET approval_requested_at = ?
               WHERE host_ip = ?""",
            ("2000-01-01T00:00:00+00:00", "192.168.10.50"),
        )
    finally:
        conn.close()

    assert db.count_pending_approvals() == 0
    host = db.lookup_host("192.168.10.50")
    assert host["port_status"] == "SECURE"
    assert host["previous_description"] is None
    assert db.get_last_operation()["action"] == "approval_expired"


def test_existing_demo_database_migrates_without_losing_ticket_timing(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(database_path)
    conn.executescript(
        """
        CREATE TABLE network_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT, host_ip TEXT NOT NULL UNIQUE,
            host_mac TEXT NOT NULL, switch_ip TEXT NOT NULL, switch_vendor TEXT NOT NULL,
            switch_hostname TEXT NOT NULL, port_interface TEXT NOT NULL,
            port_role TEXT NOT NULL DEFAULT 'Workstation', current_vlan INTEGER NOT NULL DEFAULT 10,
            port_status TEXT NOT NULL DEFAULT 'SECURE', span_status TEXT NOT NULL DEFAULT 'DISABLED',
            last_updated TEXT NOT NULL
        );
        INSERT INTO network_inventory VALUES (
            1, '192.168.10.50', '00:1A:2B:3C:4D:50', '192.168.1.2', 'cisco_ios',
            'SW-CORE-CISCO-01', 'Gi0/1', 'Workstation', 10, 'ISOLATED (VLAN 999)', 'DISABLED', 'old-time'
        );
        CREATE TABLE incident_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL, attacker_ip TEXT NOT NULL, attacker_mac TEXT NOT NULL,
            target_ip TEXT NOT NULL, signature TEXT NOT NULL, severity INTEGER NOT NULL,
            switch_hostname TEXT NOT NULL, vendor TEXT NOT NULL, isolated_port TEXT NOT NULL,
            assigned_vlan INTEGER NOT NULL DEFAULT 99, span_destination TEXT NOT NULL DEFAULT 'Gi0/24',
            response_time_ms REAL NOT NULL DEFAULT 0, executed_cli TEXT NOT NULL DEFAULT '[]',
            ticket_status TEXT NOT NULL DEFAULT 'CONTAINED'
        );
        INSERT INTO incident_tickets VALUES (
            1, 'SNTX-1001', 'old-time', '192.168.10.50', '00:1A:2B:3C:4D:50',
            '192.168.10.100', 'legacy demo', 2, 'SW-CORE-CISCO-01', 'cisco_ios',
            'Gi0/1', 99, 'Gi0/24', 17.5, '[]', 'CONTAINED'
        );
        CREATE TABLE operation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, completed_at TEXT NOT NULL,
            action TEXT NOT NULL, host_ip TEXT NOT NULL, result TEXT NOT NULL,
            message TEXT NOT NULL, execution_time_ms REAL NOT NULL DEFAULT 0,
            steps_json TEXT NOT NULL DEFAULT '[]'
        );
        """
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(db, "DB_PATH", str(database_path))

    db.init_db()

    host = db.lookup_host("192.168.10.50")
    ticket = db.get_tickets()[0]
    assert host["previous_vlan"] is None
    assert host["port_status"] == "ISOLATED"
    assert ticket["ticket_id"] == "SNTX-1001"
    assert ticket["execution_time_ms"] == 17.5
    assert ticket["span_destination"] == "Gi0/24"
    assert ticket["hunt_trace_json"] == "[]"
    assert ticket["hunt_time_ms"] == 0
    conn = db._connect()
    try:
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(operation_log)")
        }
    finally:
        conn.close()
    assert {
        "approval_channel", "approved_action",
        "approval_response_ms", "executed_cli",
    }.issubset(columns)


def test_ticket_numbers_are_unique_across_concurrent_transactions(client):
    claims = [
        db.claim_host("192.168.10.50", "isolate"),
        db.claim_host("192.168.10.51", "isolate"),
    ]

    def finalize(claim):
        return db.finalize_isolation(
            host_ip=claim["host_ip"],
            ticket_data={
                "attacker_ip": claim["host_ip"],
                "attacker_mac": claim["host_mac"],
                "target_ip": "192.168.10.100",
                "signature": "concurrency test",
                "severity": 2,
                "switch_hostname": claim["switch_hostname"],
                "vendor": claim["switch_vendor"],
                "isolated_port": claim["port_interface"],
            },
            assigned_vlan=999,
            previous_vlan=10,
            previous_description="",
            span_destination="",
            execution_time_ms=1.0,
            executed_cli="[]",
            steps=[],
        )["ticket_id"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        ticket_ids = list(pool.map(finalize, claims))
    assert sorted(ticket_ids) == ["SNTX-1001", "SNTX-1002"]


def test_failed_device_verification_does_not_create_success_ticket(client, monkeypatch):
    monkeypatch.setattr(
        containment,
        "isolate_host",
        lambda host: {
            "success": False,
            "rollback_ok": True,
            "cli_output": "Isolation: switch did not verify requested VLAN.",
            "execution_time_ms": 3.0,
            "steps": [{"step": "configure_and_verify_interface", "success": False}],
            "original_vlan": 10,
            "original_description": "WORKSTATION",
        },
    )
    response = client.post(
        "/api/webhook/alert",
        json={
            "attacker_ip": "192.168.10.50",
            "target_ip": "192.168.10.100",
            "signature": "verification failure test",
            "severity": 2,
        },
    )
    assert response.status_code == 502
    assert db.total_alerts() == 0
    assert db.lookup_host("192.168.10.50")["port_status"] == "SECURE"
    assert db.get_last_operation()["result"] == "FAILED"


def test_live_requires_startup_settings_and_request_confirmation(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRIX_MODE", "LIVE")
    monkeypatch.setenv("SENTRIX_LAB_CONFIG", str(tmp_path / "absent.json"))
    monkeypatch.setenv("SENTRIX_LAB_USERNAME", "lab-user")
    monkeypatch.setenv("SENTRIX_LAB_PASSWORD", "test-only-password")
    monkeypatch.setenv("SENTRIX_LIVE_CHANGE_TOKEN", "a" * 40)
    monkeypatch.setenv("SENTRIX_APPROVAL_TOKEN", "d" * 40)
    with pytest.raises(containment.ConfigurationError, match="local SENTRIX_LAB_CONFIG"):
        containment.validate_startup()

    lab_config = {
        "devices": [{
            "host_ip": "192.168.10.50",
            "switch_ip": "192.168.1.2",
            "vendor": "cisco_ios",
            "port_interface": "Gi0/1",
            "isolation_vlan": 999,
            "restore_vlan": 10,
        }]
    }
    config_path = tmp_path / "lab.json"
    config_path.write_text(json.dumps(lab_config), encoding="utf-8")
    monkeypatch.setenv("SENTRIX_LAB_CONFIG", str(config_path))
    containment.validate_startup()
    with pytest.raises(containment.AuthorizationError, match="valid live-change token"):
        containment.authorize_live_change(None, containment.CONFIRMATION_VALUE)
    with pytest.raises(containment.AuthorizationError, match="Explicit lab-change confirmation"):
        containment.authorize_live_change("a" * 40, None)


def test_live_http_mutations_require_token_and_allowlisted_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRIX_MODE", "LIVE")
    monkeypatch.setenv("SENTRIX_DB_PATH", str(tmp_path / "live.db"))
    monkeypatch.setenv("SENTRIX_LAB_USERNAME", "lab-user")
    monkeypatch.setenv("SENTRIX_LAB_PASSWORD", "test-only-password")
    token = "c" * 40
    monkeypatch.setenv("SENTRIX_LIVE_CHANGE_TOKEN", token)
    monkeypatch.setenv("SENTRIX_APPROVAL_TOKEN", "e" * 40)
    config = tmp_path / "lab.json"
    config.write_text(json.dumps({
        "devices": [{
            "host_ip": "192.168.10.50",
            "switch_ip": "192.168.1.2",
            "vendor": "cisco_ios",
            "port_interface": "Gi0/1",
            "isolation_vlan": 999,
            "restore_vlan": 10,
        }]
    }), encoding="utf-8")
    monkeypatch.setenv("SENTRIX_LAB_CONFIG", str(config))
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "live.db"))
    monkeypatch.setitem(
        sys.modules, "netmiko",
        SimpleNamespace(ConnectHandler=lambda **kwargs: pytest.fail("LIVE request reached Netmiko")),
    )
    with TestClient(app) as live_client:
        body = {
            "attacker_ip": "192.168.10.51",
            "target_ip": "192.168.10.100",
            "signature": "live authorization test",
            "severity": 2,
        }
        no_token = live_client.post("/api/webhook/alert", json=body)
        assert no_token.status_code == 403
        denied_host = live_client.post(
            "/api/webhook/alert",
            json=body,
            headers={
                "X-SENTRIX-LIVE-TOKEN": token,
                "X-CONFIRM-LIVE-CHANGE": containment.CONFIRMATION_VALUE,
            },
        )
        assert denied_host.status_code == 403
        assert db.lookup_host("192.168.10.51")["port_status"] == "SECURE"
        assert live_client.post(
            "/api/simulate/attack", json={"attacker_ip": "192.168.10.50"}
        ).status_code == 403
        no_restore_token = live_client.post("/api/ports/192.168.10.50/restore")
        assert no_restore_token.status_code == 403


def test_live_approval_requires_separate_token_and_proxy_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRIX_MODE", "LIVE")
    monkeypatch.setenv("SENTRIX_LAB_USERNAME", "lab-user")
    monkeypatch.setenv("SENTRIX_LAB_PASSWORD", "test-only-password")
    live_token = "f" * 40
    approval_token = "g" * 40
    monkeypatch.setenv("SENTRIX_LIVE_CHANGE_TOKEN", live_token)
    monkeypatch.setenv("SENTRIX_APPROVAL_TOKEN", approval_token)
    config = tmp_path / "approval-lab.json"
    config.write_text(json.dumps({
        "devices": [{
            "host_ip": "192.168.10.100",
            "switch_ip": "192.168.1.2",
            "vendor": "cisco_ios",
            "port_interface": "Gi0/10",
            "isolation_vlan": 999,
            "restore_vlan": 10,
        }]
    }), encoding="utf-8")
    monkeypatch.setenv("SENTRIX_LAB_CONFIG", str(config))
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "approval.db"))
    monkeypatch.setattr(
        containment,
        "isolate_host",
        lambda host: {
            "success": True,
            "honeypot_vlan": 999,
            "original_vlan": 10,
            "original_description": "FILE-SERVER",
            "sandbox_port": "",
            "execution_time_ms": 1.0,
            "executed_cli": "[]",
            "steps": [],
        },
    )
    monkeypatch.setattr(
        containment,
        "hunt_ip_port",
        lambda ip, record: {
            "target_ip": ip,
            "resolved_mac": record["host_mac"].lower(),
            "switch_ip": record["switch_ip"],
            "switch_hostname": record["switch_hostname"],
            "port": record["port_interface"],
            "port_type": "access",
            "trunk_guard_override": False,
            "warning": "",
            "hunt_time_ms": 1.0,
            "trace": [],
            "hunt_cli": [],
            "root_switch_ip": record["switch_ip"],
        },
    )
    live_headers = {
        "X-SENTRIX-LIVE-TOKEN": live_token,
        "X-CONFIRM-LIVE-CHANGE": containment.CONFIRMATION_VALUE,
    }

    with TestClient(app) as live_client:
        pending = live_client.post(
            "/api/webhook/alert",
            headers=live_headers,
            json={
                "attacker_ip": "192.168.10.100",
                "target_ip": "192.168.10.50",
                "signature": "approval security test",
                "severity": 3,
            },
        )
        assert pending.status_code == 202
        denied = live_client.post(
            "/api/approvals/192.168.10.100/approve",
            headers=live_headers,
        )
        assert denied.status_code == 403
        assert db.lookup_host("192.168.10.100")["port_status"] == "PENDING_APPROVAL"

        approved = live_client.post(
            "/api/approvals/192.168.10.100/approve",
            headers={
                **live_headers,
                "X-SENTRIX-APPROVAL-TOKEN": approval_token,
                "X-Authenticated-User": "analyst@example.test",
            },
        )
        assert approved.status_code == 200
        assert db.lookup_host("192.168.10.100")["port_status"] == "ISOLATED"
        conn = db._connect()
        try:
            row = conn.execute(
                """SELECT message FROM operation_log
                   WHERE action = 'approval_approved' ORDER BY id DESC LIMIT 1"""
            ).fetchone()
        finally:
            conn.close()
        assert "analyst@example.test" in row["message"]


def test_live_rejects_non_lab_and_unsafe_configuration(tmp_path, monkeypatch):
    config_path = tmp_path / "lab.json"
    monkeypatch.setenv("SENTRIX_LAB_CONFIG", str(config_path))
    config = {
        "devices": [{
            "host_ip": "8.8.8.8",
            "switch_ip": "192.168.1.2",
            "vendor": "cisco_ios",
            "port_interface": "Gi0/1",
            "isolation_vlan": 999,
            "restore_vlan": 10,
        }]
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(containment.ConfigurationError, match="private or loopback"):
        containment.load_lab_devices()

    config["devices"][0]["host_ip"] = "192.168.10.50"
    config["devices"][0]["port_interface"] = "Gi0/1; reload"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(containment.ConfigurationError, match="Invalid port_interface"):
        containment.load_lab_devices()


def test_live_ip_hunt_checks_all_macs_on_the_final_access_port(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRIX_MODE", "LIVE")
    monkeypatch.setenv("SENTRIX_LAB_USERNAME", "lab-user")
    monkeypatch.setenv("SENTRIX_LAB_PASSWORD", "test-only-password")
    config = tmp_path / "hunt-lab.json"
    config.write_text(json.dumps({
        "devices": [{
            "host_ip": "192.168.10.50",
            "switch_ip": "192.168.1.2",
            "vendor": "cisco_ios",
            "port_interface": "Gi0/1",
            "isolation_vlan": 999,
            "restore_vlan": 10,
        }]
    }), encoding="utf-8")
    monkeypatch.setenv("SENTRIX_LAB_CONFIG", str(config))
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "hunt-live.db"))
    db.init_db()

    class HuntConnection:
        def __init__(self):
            self.commands = []

        def send_command(self, command, **kwargs):
            self.commands.append(command)
            if command == "show ip arp 192.168.10.50":
                return "Internet 192.168.10.50 0 001a.2b3c.4d50 ARPA Vlan10"
            if command == "show mac address-table address 001a.2b3c.4d50":
                return "10 001a.2b3c.4d50 DYNAMIC Gi0/1"
            if command == "show interfaces Gi0/1 switchport":
                return "Administrative Mode: static access\nOperational Mode: static access"
            if command == "show mac address-table interface Gi0/1":
                return (
                    "10 001a.2b3c.4d50 DYNAMIC Gi0/1\n"
                    "10 00aa.bbcc.ddee DYNAMIC Gi0/1"
                )
            raise AssertionError(f"Unexpected hunt command: {command}")

        def disconnect(self):
            pass

    connection = HuntConnection()
    monkeypatch.setitem(
        sys.modules, "netmiko",
        SimpleNamespace(ConnectHandler=lambda **kwargs: connection),
    )
    trace = containment.hunt_ip_port(
        "192.168.10.50", db.lookup_host("192.168.10.50")
    )

    assert trace["port_type"] == "multi-mac"
    assert trace["trunk_guard_override"] is True
    assert trace["hunt_time_ms"] >= 0
    assert "show mac address-table interface Gi0/1" in connection.commands


class FakeCiscoConnection:
    def __init__(self, with_span=False):
        self.vlan = 10
        self.description = "WORKSTATION"
        self.with_span = with_span
        self.config_calls = []
        self.saved = False
        self.disconnected = False

    def send_command(self, command, **kwargs):
        if command in {"show monitor session all", "show monitor session"}:
            return "Session 12\n" if self.with_span else "No active monitor sessions configured."
        if command.startswith("show running-config interface"):
            return (
                "interface GigabitEthernet0/1\n"
                f" description {self.description}\n"
                " switchport mode access\n"
                f" switchport access vlan {self.vlan}\n"
            )
        if command.startswith("show running-config | include ^monitor session"):
            if self.with_span:
                return (
                    "monitor session 12 source interface Gi0/1 both\n"
                    "monitor session 12 destination interface Gi0/24\n"
                )
            return ""
        raise AssertionError(f"Unexpected read-only verification command: {command}")

    def send_config_set(self, commands, **kwargs):
        self.config_calls.append(list(commands))
        for command in commands:
            if command.startswith("switchport access vlan "):
                self.vlan = int(command.rsplit(" ", 1)[1])
            elif command.startswith("description "):
                self.description = command[len("description "):]
            elif command == "no description":
                self.description = ""
            elif command.startswith("monitor session "):
                self.with_span = True
            elif command.startswith("no monitor session "):
                self.with_span = False
        return "configuration accepted"

    def save_config(self):
        self.saved = True
        return "saved"

    def disconnect(self):
        self.disconnected = True


class PartialFailureConnection(FakeCiscoConnection):
    def __init__(self):
        super().__init__()
        self.fail_once = True

    def send_config_set(self, commands, **kwargs):
        if self.fail_once and "switchport access vlan 999" in commands:
            self.fail_once = False
            self.vlan = 999
            raise RuntimeError("simulated partial write")
        return super().send_config_set(commands, **kwargs)


class FakeAclCiscoConnection(FakeCiscoConnection):
    def __init__(self):
        super().__init__()
        self.acl_name = None
        self.acl_rules = []
        self.access_group = None
        self.in_acl = False
        self.vendor = "cisco_ios"

    def send_command(self, command, **kwargs):
        if command.startswith("show running-config interface"):
            output = super().send_command(command, **kwargs)
            if self.access_group:
                output += f" ip access-group {self.access_group} in\n"
            return output
        if command == "show running-config":
            if not self.acl_name:
                return ""
            header = (
                f"ip access-list extended {self.acl_name}\n"
                if self.vendor == "cisco_ios"
                else f"ip access-list {self.acl_name}\n"
            )
            return header + "".join(f" {rule}\n" for rule in self.acl_rules) + "!\n"
        return super().send_command(command, **kwargs)

    def send_config_set(self, commands, **kwargs):
        self.config_calls.append(list(commands))
        for command in commands:
            if command.startswith("ip access-list "):
                self.acl_name = command.rsplit(" ", 1)[1]
                self.acl_rules = []
                self.in_acl = True
            elif command == "exit":
                self.in_acl = False
            elif self.in_acl:
                self.acl_rules.append(command)
            elif command.startswith("ip access-group "):
                self.access_group = command.split()[2]
            elif command.startswith("no ip access-group "):
                self.access_group = None
            elif command.startswith("no ip access-list "):
                self.acl_name = None
                self.acl_rules = []
        return "configuration accepted"


def _configure_fake_live(
    tmp_path, monkeypatch, connection, span=False, vendor="cisco_ios",
    port_interface="Gi0/1", port_bounce=True, span_limit=2
):
    monkeypatch.setenv("SENTRIX_MODE", "LIVE")
    monkeypatch.setenv("SENTRIX_LAB_USERNAME", "lab-user")
    monkeypatch.setenv("SENTRIX_LAB_PASSWORD", "not-a-real-password")
    monkeypatch.setenv("SENTRIX_LIVE_CHANGE_TOKEN", "b" * 40)
    device = {
        "host_ip": "192.168.10.50",
        "switch_ip": "192.168.1.2",
        "vendor": vendor,
        "port_interface": port_interface,
        "isolation_vlan": 999,
        "restore_vlan": 10,
        "port_bounce": port_bounce,
    }
    if span:
        device.update({"span_session": 12, "span_destination": "Gi0/24"})
    config = tmp_path / "lab.json"
    config.write_text(json.dumps({
        "devices": [device],
        "max_span_sessions_per_switch": span_limit,
    }), encoding="utf-8")
    monkeypatch.setenv("SENTRIX_LAB_CONFIG", str(config))
    monkeypatch.setitem(
        sys.modules, "netmiko",
        SimpleNamespace(ConnectHandler=lambda **kwargs: connection),
    )
    if isinstance(connection, FakeAclCiscoConnection):
        connection.vendor = vendor
    return {
        "host_ip": "192.168.10.50",
        "switch_ip": "192.168.1.2",
        "switch_vendor": vendor,
        "port_interface": port_interface,
        "current_vlan": 10,
        "port_status": "SECURE",
    }


def test_netmiko_is_mocked_and_restore_uses_saved_interface_state(tmp_path, monkeypatch):
    connection = FakeCiscoConnection()
    host = _configure_fake_live(tmp_path, monkeypatch, connection)

    isolated = containment.isolate_host(host)
    assert isolated["success"] is True
    assert isolated["original_vlan"] == 10
    assert isolated["original_description"] == "WORKSTATION"
    assert connection.vlan == 999
    assert connection.description == containment.ISOLATION_DESCRIPTION
    assert connection.saved and connection.disconnected

    host.update({
        "current_vlan": 999,
        "port_status": "ISOLATED",
        "previous_vlan": isolated["original_vlan"],
        "previous_description": isolated["original_description"],
    })
    restored = containment.restore_host(host)
    assert restored["success"] is True
    assert connection.vlan == 10
    assert connection.description == "WORKSTATION"
    assert connection.saved and connection.disconnected


def test_port_bounce_can_be_disabled_for_live_vlan_isolation_and_restore(tmp_path, monkeypatch):
    connection = FakeCiscoConnection()
    host = _configure_fake_live(
        tmp_path, monkeypatch, connection, port_bounce=False
    )
    isolated = containment.isolate_host(host)
    assert isolated["success"] is True
    assert "shutdown" not in json.loads(isolated["executed_cli"])
    assert not any(
        step["step"] == "port_bounce_session_drop"
        for step in isolated["steps"]
    )

    host.update({
        "current_vlan": 999,
        "port_status": "ISOLATED",
        "previous_vlan": isolated["original_vlan"],
        "previous_description": isolated["original_description"],
    })
    restored = containment.restore_host(host)
    assert restored["success"] is True
    assert "shutdown" not in json.loads(restored["executed_cli"])
    assert not any(
        step["step"] == "port_bounce_session_drop"
        for step in restored["steps"]
    )


def test_existing_span_session_is_not_replaced(tmp_path, monkeypatch):
    connection = FakeCiscoConnection(with_span=True)
    host = _configure_fake_live(tmp_path, monkeypatch, connection, span=True)

    result = containment.isolate_host(host)
    assert result["success"] is False
    assert result["rollback_ok"] is True
    assert connection.vlan == 10
    assert connection.config_calls == []
    assert connection.disconnected


def test_configured_span_is_created_and_only_that_session_is_restored(tmp_path, monkeypatch):
    connection = FakeCiscoConnection()
    host = _configure_fake_live(tmp_path, monkeypatch, connection, span=True)

    isolated = containment.isolate_host(host)
    assert isolated["success"] is True
    assert connection.with_span is True
    assert any(
        "monitor session 12 source interface Gi0/1 both" in commands
        and "monitor session 12 destination interface Gi0/24" in commands
        for commands in connection.config_calls
    )

    host.update({
        "current_vlan": 999,
        "port_status": "ISOLATED",
        "previous_vlan": isolated["original_vlan"],
        "previous_description": isolated["original_description"],
    })
    restored = containment.restore_host(host)
    assert restored["success"] is True
    assert connection.with_span is False
    assert any("no monitor session 12" in commands for commands in connection.config_calls)


def test_span_session_limit_is_configurable_and_enforced(tmp_path, monkeypatch):
    device = {
        "host_ip": "192.168.10.50",
        "switch_ip": "192.168.1.2",
        "vendor": "cisco_ios",
        "port_interface": "Gi0/1",
        "isolation_vlan": 999,
        "restore_vlan": 10,
        "span_session": 12,
        "span_destination": "Gi0/24",
    }
    second_device = {
        **device,
        "host_ip": "192.168.10.52",
        "port_interface": "Gi0/2",
        "span_session": 13,
    }
    config = tmp_path / "limited-span.json"
    config.write_text(json.dumps({
        "devices": [device, second_device],
        "max_span_sessions_per_switch": 1,
    }), encoding="utf-8")
    monkeypatch.setenv("SENTRIX_LAB_CONFIG", str(config))
    with pytest.raises(containment.ConfigurationError, match="exceed"):
        containment.load_lab_devices()


def test_reconciliation_is_read_only_and_reports_vlan_drift(tmp_path, monkeypatch):
    connection = FakeCiscoConnection()
    host = _configure_fake_live(tmp_path, monkeypatch, connection)

    in_sync = containment.reconcile_host_state(host)
    assert in_sync["status"] == "IN_SYNC"
    assert in_sync["limitations"] == [
        "Secure-state interface description baseline is not stored."
    ]
    assert connection.config_calls == []

    connection.vlan = 20
    drift = containment.reconcile_host_state(host)
    assert drift["status"] == "DRIFT"
    assert drift["drift"] == ["access_vlan"]
    assert connection.config_calls == []


def test_partial_isolation_write_rolls_back_before_reporting_failure(tmp_path, monkeypatch):
    connection = PartialFailureConnection()
    host = _configure_fake_live(tmp_path, monkeypatch, connection)

    result = containment.isolate_host(host)
    assert result["success"] is False
    assert result["rollback_ok"] is True
    assert connection.vlan == 10
    assert connection.description == "WORKSTATION"
    assert connection.saved and connection.disconnected
    assert any(step["step"] == "rollback_and_verify" and step["success"] for step in result["steps"])


def test_live_acl_containment_and_restore_verify_only_sentrix_acl(tmp_path, monkeypatch):
    connection = FakeAclCiscoConnection()
    host = _configure_fake_live(tmp_path, monkeypatch, connection)

    isolated = containment.isolate_host(
        host, mode="acl", target_ip="192.168.10.100"
    )
    assert isolated["success"] is True
    assert isolated["original_vlan"] == 10
    assert isolated["original_description"] == "MODE:acl"
    assert connection.acl_name == "SENTRIX_ACL_192_168_10_50"
    assert connection.access_group == connection.acl_name
    assert connection.acl_rules == [
        "deny ip host 192.168.10.50 host 192.168.10.100",
        "permit ip any any",
    ]

    host.update({
        "current_vlan": 10,
        "port_status": "ISOLATED",
        "previous_vlan": 10,
        "previous_description": "MODE:acl",
    })
    restored = containment.restore_host(host)
    assert restored["success"] is True
    assert connection.acl_name is None
    assert connection.access_group is None


def test_live_arista_acl_uses_eos_named_acl_syntax_and_restores(tmp_path, monkeypatch):
    connection = FakeAclCiscoConnection()
    host = _configure_fake_live(
        tmp_path, monkeypatch, connection, vendor="arista_eos", port_interface="Et1"
    )

    isolated = containment.isolate_host(
        host, mode="acl", target_ip="192.168.10.100"
    )
    assert isolated["success"] is True
    assert connection.acl_name == "SENTRIX_ACL_192_168_10_50"
    assert connection.config_calls[0][0] == "ip access-list SENTRIX_ACL_192_168_10_50"

    host.update({
        "port_status": "ISOLATED",
        "previous_vlan": 10,
        "previous_description": "MODE:acl",
    })
    restored = containment.restore_host(host)
    assert restored["success"] is True
    assert "no ip access-list SENTRIX_ACL_192_168_10_50" in connection.config_calls[-1]
    assert connection.acl_name is None
