import json
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import containment
import database as db
from main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRIX_MODE", "MOCK")
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
