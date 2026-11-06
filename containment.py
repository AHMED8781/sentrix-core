"""Fail-closed MOCK/LIVE containment for explicitly configured lab switches."""

import hmac
import ipaddress
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger("sentrix.containment")
CONFIRMATION_VALUE = "I_CONFIRM_GNS3_LAB_CHANGE"
SUPPORTED_VENDORS = {"cisco_ios", "arista_eos"}
ISOLATION_DESCRIPTION = "SENTRIX_ISOLATED"


class ConfigurationError(ValueError):
    """Local configuration is missing, invalid, or inconsistent."""


class AuthorizationError(PermissionError):
    """A requested live change is not explicitly authorized."""


@dataclass(frozen=True)
class LabDevice:
    host_ip: str
    switch_ip: str
    vendor: str
    port_interface: str
    isolation_vlan: int
    restore_vlan: int
    port: int
    timeout: int
    span_session: Optional[int]
    span_destination: Optional[str]
    port_bounce: bool = True
    span_session_limit: int = 2


def get_mode() -> str:
    mode = os.getenv("SENTRIX_MODE", "MOCK").strip().upper()
    if mode not in {"MOCK", "LIVE"}:
        raise ConfigurationError("SENTRIX_MODE must be MOCK or LIVE.")
    return mode


def get_mock_mode() -> bool:
    return get_mode() == "MOCK"


def _validate_ip(value: Any, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"Invalid {label} in lab configuration.") from exc
    if not (address.is_private or address.is_loopback):
        raise ConfigurationError(f"{label} must be a private or loopback lab address.")
    return str(address)


def _validate_interface(vendor: str, value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(f"Invalid {label} in lab configuration.")
    patterns = {
        "cisco_ios": r"(?:Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Eth|Ethernet)\d+(?:/\d+){1,2}",
        "arista_eos": r"(?:Et|Ethernet)\d+(?:/\d+){0,2}",
    }
    if vendor not in patterns or not re.fullmatch(patterns[vendor], value):
        raise ConfigurationError(f"Invalid {label} for {vendor}.")
    return value


def _validate_vlan(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 2 <= value <= 4094:
        raise ConfigurationError(f"{label} must be an integer from 2 through 4094.")
    return value


def _parse_device(data: Any, span_session_limit: int = 2) -> LabDevice:
    if not isinstance(data, dict):
        raise ConfigurationError("Each lab device entry must be an object.")
    required = {
        "host_ip", "switch_ip", "vendor", "port_interface",
        "isolation_vlan", "restore_vlan",
    }
    if not required.issubset(data):
        raise ConfigurationError("A lab device entry is missing required fields.")
    vendor = data["vendor"]
    if vendor not in SUPPORTED_VENDORS:
        raise ConfigurationError("Only cisco_ios and arista_eos are configured for LIVE.")
    host_ip = _validate_ip(data["host_ip"], "host_ip")
    switch_ip = _validate_ip(data["switch_ip"], "switch_ip")
    source = _validate_interface(vendor, data["port_interface"], "port_interface")
    isolation_vlan = _validate_vlan(data["isolation_vlan"], "isolation_vlan")
    restore_vlan = _validate_vlan(data["restore_vlan"], "restore_vlan")
    if isolation_vlan == restore_vlan:
        raise ConfigurationError("isolation_vlan and restore_vlan must differ.")
    port = data.get("port", 22)
    timeout = data.get("timeout", 8)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigurationError("port must be an integer from 1 through 65535.")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 3 <= timeout <= 60:
        raise ConfigurationError("timeout must be an integer from 3 through 60.")
    session = data.get("span_session")
    destination = data.get("span_destination")
    if (session is None) != (destination is None):
        raise ConfigurationError("span_session and span_destination must be configured together.")
    if session is not None:
        if isinstance(session, bool) or not isinstance(session, int) or not 1 <= session <= 66:
            raise ConfigurationError("span_session must be an integer from 1 through 66.")
        destination = _validate_interface(vendor, destination, "span_destination")
        if destination == source:
            raise ConfigurationError("SPAN destination must differ from the isolated port.")
    port_bounce = data.get("port_bounce", True)
    if not isinstance(port_bounce, bool):
        raise ConfigurationError("port_bounce must be a boolean.")
    return LabDevice(
        host_ip=host_ip,
        switch_ip=switch_ip,
        vendor=vendor,
        port_interface=source,
        isolation_vlan=isolation_vlan,
        restore_vlan=restore_vlan,
        port=port,
        timeout=timeout,
        span_session=session,
        span_destination=destination,
        port_bounce=port_bounce,
        span_session_limit=span_session_limit,
    )


def load_lab_devices() -> Dict[str, LabDevice]:
    path = Path(os.getenv("SENTRIX_LAB_CONFIG", "lab-config.json"))
    if not path.is_file():
        raise ConfigurationError("LIVE requires a local SENTRIX_LAB_CONFIG file.")
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("Could not read the local lab configuration.") from exc
    if (
        not isinstance(content, dict)
        or not {"devices"}.issubset(content)
        or set(content) - {"devices", "max_span_sessions_per_switch"}
        or not isinstance(content["devices"], list)
    ):
        raise ConfigurationError(
            "Lab configuration must contain a devices list and optional SPAN session limit."
        )
    span_limit = content.get("max_span_sessions_per_switch", 2)
    if isinstance(span_limit, bool) or not isinstance(span_limit, int) or not 1 <= span_limit <= 2:
        raise ConfigurationError(
            "max_span_sessions_per_switch must be 1 or 2."
        )
    devices: Dict[str, LabDevice] = {}
    for entry in content["devices"]:
        device = _parse_device(entry, span_limit)
        if device.host_ip in devices:
            raise ConfigurationError("Duplicate host_ip in lab configuration.")
        devices[device.host_ip] = device
    if not devices:
        raise ConfigurationError("LIVE requires at least one explicitly allowed lab host.")
    span_sessions: Dict[str, set[int]] = {}
    for device in devices.values():
        if device.span_session is None:
            continue
        sessions = span_sessions.setdefault(device.switch_ip, set())
        if device.span_session in sessions:
            raise ConfigurationError(
                "Each configured SPAN session must be unique per switch."
            )
        sessions.add(device.span_session)
        if len(sessions) > device.span_session_limit:
            raise ConfigurationError(
                "Configured SPAN sessions exceed max_span_sessions_per_switch."
            )
    return devices


def validate_startup() -> None:
    mode = get_mode()
    if mode == "MOCK":
        LOGGER.info("engine_started mode=MOCK")
        return
    if not os.getenv("SENTRIX_LAB_USERNAME") or not os.getenv("SENTRIX_LAB_PASSWORD"):
        raise ConfigurationError("LIVE requires SENTRIX_LAB_USERNAME and SENTRIX_LAB_PASSWORD.")
    token = os.getenv("SENTRIX_LIVE_CHANGE_TOKEN", "")
    if len(token) < 32:
        raise ConfigurationError("LIVE requires a SENTRIX_LIVE_CHANGE_TOKEN of at least 32 characters.")
    approval_token = os.getenv("SENTRIX_APPROVAL_TOKEN", "")
    if len(approval_token) < 32:
        raise ConfigurationError("LIVE requires a SENTRIX_APPROVAL_TOKEN of at least 32 characters.")
    if hmac.compare_digest(token, approval_token):
        raise ConfigurationError(
            "The live-change and approval tokens must be different values."
        )
    load_lab_devices()
    LOGGER.warning("engine_started mode=LIVE; live changes require a token and explicit confirmation")


def authorize_live_change(token: Optional[str], confirmation: Optional[str]) -> None:
    if get_mock_mode():
        return
    expected = os.getenv("SENTRIX_LIVE_CHANGE_TOKEN", "")
    if not token or not hmac.compare_digest(token, expected):
        raise AuthorizationError("A valid live-change token is required.")
    if confirmation != CONFIRMATION_VALUE:
        raise AuthorizationError("Explicit lab-change confirmation is required.")


def authorize_approval(
    live_token: Optional[str],
    confirmation: Optional[str],
    approval_token: Optional[str],
    approver: Optional[str],
) -> str:
    authorize_live_change(live_token, confirmation)
    if get_mock_mode():
        return "MOCK_OPERATOR"
    expected = os.getenv("SENTRIX_APPROVAL_TOKEN", "")
    if not approval_token or not hmac.compare_digest(approval_token, expected):
        raise AuthorizationError("A valid approval-specific token is required.")
    if not approver or not re.fullmatch(r"[A-Za-z0-9._@-]{1,120}", approver):
        raise AuthorizationError(
            "A trusted authenticated approver identity is required."
        )
    return approver


def _device_for_host(inventory_record: Dict[str, Any]) -> LabDevice:
    devices = load_lab_devices()
    host_ip = inventory_record["host_ip"]
    device = devices.get(host_ip)
    if device is None:
        raise AuthorizationError("This host is not explicitly allowed by the local lab configuration.")
    expected = (
        device.switch_ip, device.vendor, device.port_interface,
    )
    actual = (
        inventory_record["switch_ip"], inventory_record["switch_vendor"],
        inventory_record["port_interface"],
    )
    if actual != expected:
        raise AuthorizationError("Inventory does not match the explicitly allowed lab device.")
    if inventory_record["current_vlan"] != device.restore_vlan and inventory_record["port_status"] == "SECURE":
        raise AuthorizationError("Inventory VLAN does not match the configured restore VLAN.")
    return device


def _normalize_mac(value: str) -> Optional[str]:
    match = re.search(r"(?i)(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{12}", value)
    if not match:
        return None
    digits = re.sub(r"[^0-9a-f]", "", match.group(0).lower())
    return ":".join(digits[index:index + 2] for index in range(0, 12, 2))


def discover_host_port(target_ip: str) -> Dict[str, Any]:
    """Resolve an endpoint through ARP/MAC tables without enrolling unapproved LIVE ports."""
    address = ipaddress.ip_address(target_ip)
    if address.version != 4 or not address.is_private:
        raise AuthorizationError("Host discovery is limited to private IPv4 lab addresses.")

    if get_mock_mode():
        last_octet = int(address.packed[-1])
        mac_suffix = f"{last_octet:02X}"
        host_mac = f"00:1A:2B:99:88:{mac_suffix}"
        port_interface = f"Gi0/{last_octet}"
        return {
            "host_ip": str(address),
            "host_mac": host_mac,
            "switch_ip": "192.168.1.2",
            "switch_vendor": "cisco_ios",
            "switch_hostname": "SW-CORE-CISCO-01",
            "port_interface": port_interface,
            "current_vlan": 10,
            "discovery_cli": (
                f"show ip arp {address}\n"
                f"Internet {address} 0 {host_mac.replace(':', '.')} ARPA Vlan10\n"
                "show cdp neighbors Gi0/24\n"
                "Device ID: SW-DIST-ARISTA-01; Local Interface: Gi0/24; Capability: S I; Port ID: Et48 (excluded trunk)\n"
                f"show mac address-table address {host_mac.replace(':', '.')}\n"
                f"10 {host_mac.replace(':', '.')} DYNAMIC {port_interface} (access endpoint)\n"
            ),
        }

    devices = load_lab_devices()
    allowed = devices.get(str(address))
    if allowed is None:
        raise AuthorizationError(
            "LIVE discovery is limited to hosts explicitly listed in the lab allowlist."
        )
    primary = next(iter(devices.values()))
    if allowed.switch_ip != primary.switch_ip or allowed.vendor != primary.vendor:
        raise AuthorizationError("The target is not mapped to the configured primary lab switch.")
    from netmiko import ConnectHandler

    connection = None
    try:
        connection = ConnectHandler(
            device_type=primary.vendor,
            host=primary.switch_ip,
            port=primary.port,
            username=os.environ["SENTRIX_LAB_USERNAME"],
            password=os.environ["SENTRIX_LAB_PASSWORD"],
            timeout=primary.timeout,
            conn_timeout=primary.timeout,
            auth_timeout=primary.timeout,
            banner_timeout=primary.timeout,
            fast_cli=False,
        )
        arp_output = connection.send_command(
            f"show ip arp {address}", read_timeout=primary.timeout
        )
        host_mac = _normalize_mac(arp_output)
        if host_mac is None or str(address) not in arp_output:
            raise AuthorizationError("The target has no unambiguous ARP entry on the primary switch.")
        mac_output = connection.send_command(
            f"show mac address-table address {host_mac.replace(':', '.')}",
            read_timeout=primary.timeout,
        )
        matching_lines = [
            line for line in mac_output.splitlines()
            if _normalize_mac(line) == host_mac
        ]
        interfaces = {
            line.split()[-1] for line in matching_lines if line.split()
        }
        if len(interfaces) != 1:
            raise AuthorizationError("The target MAC does not resolve to exactly one switch port.")
        port_interface = interfaces.pop()
        _validate_interface(primary.vendor, port_interface, "discovered interface")

        cdp_output = connection.send_command(
            f"show cdp neighbors {port_interface}", read_timeout=primary.timeout
        )
        if cdp_output.strip() and not re.search(
            r"(?i)(?:no cdp neighbors|total cdp entries displayed\s*:\s*0)",
            cdp_output,
        ):
            raise AuthorizationError("The discovered port has a CDP neighbor and may be an uplink.")

        # Discovery is observational; LIVE enrollment requires an exact local allowlist match.
        if (
            allowed.port_interface != port_interface
        ):
            raise AuthorizationError(
                "The discovered host and port are not explicitly present in the LIVE lab allowlist."
            )
        return {
            "host_ip": str(address),
            "host_mac": host_mac,
            "switch_ip": primary.switch_ip,
            "switch_vendor": primary.vendor,
            "switch_hostname": f"LAB-{primary.switch_ip.replace('.', '-')}",
            "port_interface": port_interface,
            "current_vlan": allowed.restore_vlan,
            "discovery_cli": (
                f"show ip arp {address}\n{arp_output}\n"
                f"show mac address-table address {host_mac.replace(':', '.')}\n{mac_output}\n"
                f"show cdp neighbors {port_interface}\n{cdp_output or 'No CDP neighbor found.'}"
            ),
        }
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception as exc:
                LOGGER.warning(
                    "host_discovery_disconnect_failed vendor=%s error_type=%s",
                    device.vendor, type(exc).__name__,
                )


def _span_commands(vendor: str, session: int, source: str, destination: str) -> List[str]:
    if vendor == "cisco_ios":
        return [
            f"monitor session {session} source interface {source} both",
            f"monitor session {session} destination interface {destination}",
        ]
    return [
        f"monitor session {session} source {source} both",
        f"monitor session {session} destination {destination}",
    ]


def _active_span_sessions(output: str) -> set[int]:
    if re.search(
        r"(?i)no (?:active )?(?:span|monitor) sessions?(?: configured| found| active)?",
        output,
    ) or re.search(r"(?i)no sessions configured", output):
        return set()
    if not output.strip():
        raise ConfigurationError(
            "The switch returned an empty SPAN session response; capacity is unknown."
        )
    session_ids = {
        int(match.group(1))
        for match in re.finditer(
            r"(?im)^\s*(?:monitor\s+)?session(?:\s+id)?\s*[:#]?\s*(\d+)\b",
            output,
        )
    }
    if not session_ids:
        raise ConfigurationError(
            "Could not safely determine active SPAN session usage on the switch."
        )
    return session_ids


def _vlan_interface_commands(
    device: LabDevice, vlan: int, description: Optional[str] = None
) -> List[str]:
    commands = [
        f"interface {device.port_interface}",
        f"switchport access vlan {vlan}",
    ]
    if device.port_bounce:
        commands.extend(["shutdown", "no shutdown"])
    if description is not None:
        commands.append(
            "no description" if not description else f"description {description}"
        )
    commands.append("exit")
    return commands


def _generated_commands(device: LabDevice) -> List[str]:
    commands = [
        f"interface {device.port_interface}",
        f"description {ISOLATION_DESCRIPTION}",
        f"switchport access vlan {device.isolation_vlan}",
    ]
    if device.port_bounce:
        commands.extend(["shutdown", "no shutdown"])
    commands.append("exit")
    if device.span_session is not None:
        commands.extend(_span_commands(
            device.vendor, device.span_session,
            device.port_interface, device.span_destination or "",
        ))
    return commands


def _mock_execute(commands: List[str], label: str) -> Tuple[bool, str]:
    time.sleep(random.uniform(0.02, 0.06))
    output = "\n".join(f"MOCK {label}: {command} [OK]" for command in commands)
    return True, output


def _error_message(exc: Exception, stage: str) -> str:
    if isinstance(exc, (ValueError, AuthorizationError)):
        return f"{stage}: {exc}"
    name = type(exc).__name__
    if name in {"AuthenticationException", "NetmikoAuthenticationException"}:
        return f"{stage}: SSH authentication failed; check the local lab credentials."
    if name in {"TimeoutError", "NetmikoTimeoutException", "SSHException", "OSError"}:
        return f"{stage}: SSH connection failed ({name}); check the configured address, port, and lab SSH service."
    return f"{stage}: device operation failed ({name}); inspect the switch and its supported CLI."


def _parse_interface_config(output: str) -> Tuple[int, str]:
    mode = re.search(r"(?im)^\s*switchport mode access\s*$", output)
    vlan_match = re.search(r"(?im)^\s*switchport access vlan\s+(\d+)\s*$", output)
    if not mode or not vlan_match:
        raise ValueError("Port must have an explicit access mode and access VLAN.")
    description_match = re.search(r"(?im)^\s*description\s+(.+?)\s*$", output)
    description = description_match.group(1) if description_match else ""
    if len(description) > 240 or not re.fullmatch(r"[A-Za-z0-9 _.,:/()#+@=-]*", description):
        raise ValueError("Existing interface description contains unsupported CLI characters.")
    return int(vlan_match.group(1)), description


def _session_config(vendor: str, session: int, source: str, destination: str) -> List[str]:
    output_source, output_destination = _span_commands(vendor, session, source, destination)
    return [output_source, output_destination]


def _acl_name(host_ip: str) -> str:
    return f"SENTRIX_ACL_{host_ip.replace('.', '_')}"


def _acl_definition_commands(vendor: str, acl_name: str, attacker_ip: str, target_ip: str) -> List[str]:
    header = (
        f"ip access-list extended {acl_name}"
        if vendor == "cisco_ios"
        else f"ip access-list {acl_name}"
    )
    return [
        header,
        f"deny ip host {attacker_ip} host {target_ip}",
        "permit ip any any",
        "exit",
    ]


def _acl_removal_commands(vendor: str, acl_name: str, interface: str) -> List[str]:
    command = (
        f"no ip access-list extended {acl_name}"
        if vendor == "cisco_ios"
        else f"no ip access-list {acl_name}"
    )
    return [
        f"interface {interface}",
        f"no ip access-group {acl_name} in",
        "exit",
        command,
    ]


def _acl_rules_from_config(output: str, vendor: str, acl_name: str) -> Optional[List[str]]:
    header = (
        rf"(?i)^\s*ip access-list extended {re.escape(acl_name)}\s*$"
        if vendor == "cisco_ios"
        else rf"(?i)^\s*ip access-list {re.escape(acl_name)}\s*$"
    )
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if not re.fullmatch(header, line):
            continue
        rules: List[str] = []
        for rule_line in lines[index + 1:]:
            if not rule_line.strip() or rule_line.strip() == "!":
                continue
            if not rule_line[0].isspace():
                break
            rule = rule_line.strip()
            rule = re.sub(r"^\d+\s+", "", rule)
            rules.append(rule)
        return rules
    return None


def _live_acl_isolate(
    device: LabDevice, expected_vlan: int, attacker_ip: str, target_ip: str
) -> Dict[str, Any]:
    from netmiko import ConnectHandler

    acl_name = _acl_name(attacker_ip)
    acl_definition = _acl_definition_commands(device.vendor, acl_name, attacker_ip, target_ip)
    commands = acl_definition + [
        f"interface {device.port_interface}",
        f"ip access-group {acl_name} in",
        "exit",
    ]
    steps: List[Dict[str, Any]] = []
    connection = None
    mutated = False
    before_vlan: Optional[int] = None
    before_description = ""
    start = time.perf_counter()
    try:
        connection = ConnectHandler(
            device_type=device.vendor,
            host=device.switch_ip,
            port=device.port,
            username=os.environ["SENTRIX_LAB_USERNAME"],
            password=os.environ["SENTRIX_LAB_PASSWORD"],
            timeout=device.timeout,
            conn_timeout=device.timeout,
            auth_timeout=device.timeout,
            banner_timeout=device.timeout,
            fast_cli=False,
        )
        interface_command = (
            f"show running-config interface {device.port_interface}"
            if device.vendor == "cisco_ios"
            else f"show running-config interfaces {device.port_interface}"
        )
        interface_output = connection.send_command(
            interface_command, read_timeout=device.timeout
        )
        before_vlan, before_description = _parse_interface_config(interface_output)
        if before_vlan != expected_vlan or before_vlan != device.restore_vlan:
            raise AuthorizationError("Switch access VLAN does not match the configured restore VLAN.")
        if re.search(r"(?im)^\s*ip access-group\s+\S+\s+in\s*$", interface_output):
            raise AuthorizationError("The interface already has an inbound ACL; it was not replaced.")
        acl_output = connection.send_command(
            "show running-config",
            read_timeout=device.timeout,
        )
        if re.search(rf"(?im)^\s*ip access-list(?: extended)?\s+{re.escape(acl_name)}\s*$", acl_output):
            raise AuthorizationError("The generated SENTRIX ACL name already exists; it was not changed.")
        steps.append({"step": "preflight_acl_interface", "success": True})

        mutated = True
        connection.send_config_set(commands, cmd_verify=True)
        interface_output = connection.send_command(
            interface_command, read_timeout=device.timeout
        )
        acl_output = connection.send_command(
            "show running-config",
            read_timeout=device.timeout,
        )
        expected_rules = [
            f"deny ip host {attacker_ip} host {target_ip}",
            "permit ip any any",
        ]
        if (
            not re.search(rf"(?im)^\s*ip access-group\s+{re.escape(acl_name)}\s+in\s*$", interface_output)
            or _acl_rules_from_config(acl_output, device.vendor, acl_name) != expected_rules
        ):
            raise ValueError("The interface ACL attachment or ACL rules did not verify.")
        steps.extend([
            {"step": "configure_and_verify_acl", "success": True},
        ])
        connection.save_config()
        steps.append({"step": "save_config", "success": True})
        return {
            "success": True,
            "rollback_ok": True,
            "executed_cli": json.dumps(commands, indent=2),
            "cli_output": "Surgical ACL attachment and rules verified.",
            "steps": steps,
            "original_vlan": before_vlan,
            "original_description": "MODE:acl",
            "honeypot_vlan": before_vlan,
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "sandbox_port": "",
        }
    except Exception as exc:
        message = _error_message(exc, "ACL containment")
        steps.append({"step": "acl_isolation", "success": False, "message": message})
        rollback_ok = not mutated
        if connection is not None and mutated:
            try:
                removal = _acl_removal_commands(
                    device.vendor, acl_name, device.port_interface
                )
                connection.send_config_set(removal, cmd_verify=True)
                interface_output = connection.send_command(
                    f"show running-config interface {device.port_interface}"
                    if device.vendor == "cisco_ios"
                    else f"show running-config interfaces {device.port_interface}",
                    read_timeout=device.timeout,
                )
                acl_output = connection.send_command(
                    "show running-config",
                    read_timeout=device.timeout,
                )
                rollback_ok = (
                    not re.search(
                        rf"(?im)^\s*ip access-group\s+{re.escape(acl_name)}\s+in\s*$",
                        interface_output,
                    )
                    and _acl_rules_from_config(acl_output, device.vendor, acl_name) is None
                )
                if rollback_ok:
                    connection.save_config()
                steps.append({"step": "rollback_and_verify", "success": rollback_ok})
            except Exception as rollback_exc:
                rollback_ok = False
                steps.append({
                    "step": "rollback_and_verify",
                    "success": False,
                    "message": _error_message(rollback_exc, "ACL rollback"),
                })
        return {
            "success": False,
            "rollback_ok": rollback_ok,
            "executed_cli": json.dumps(commands, indent=2),
            "cli_output": message,
            "steps": steps,
            "original_vlan": before_vlan,
            "original_description": "MODE:acl" if not rollback_ok else before_description,
            "honeypot_vlan": before_vlan or expected_vlan,
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "sandbox_port": "",
        }
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception as exc:
                LOGGER.warning("netmiko_disconnect_failed vendor=%s error_type=%s", device.vendor, type(exc).__name__)


def _live_isolate(device: LabDevice, expected_vlan: int) -> Dict[str, Any]:
    from netmiko import ConnectHandler

    commands = _generated_commands(device)
    steps: List[Dict[str, Any]] = []
    connection = None
    before_vlan: Optional[int] = None
    before_description = ""
    interface_changed = False
    span_attempted = False
    primary_error: Optional[str] = None
    rollback_ok = True
    start = time.perf_counter()
    try:
        connection = ConnectHandler(
            device_type=device.vendor,
            host=device.switch_ip,
            port=device.port,
            username=os.environ["SENTRIX_LAB_USERNAME"],
            password=os.environ["SENTRIX_LAB_PASSWORD"],
            timeout=device.timeout,
            conn_timeout=device.timeout,
            auth_timeout=device.timeout,
            banner_timeout=device.timeout,
            fast_cli=False,
        )
        interface_command = (
            f"show running-config interface {device.port_interface}"
            if device.vendor == "cisco_ios"
            else f"show running-config interfaces {device.port_interface}"
        )
        interface_output = connection.send_command(interface_command, read_timeout=device.timeout)
        before_vlan, before_description = _parse_interface_config(interface_output)
        if before_vlan != expected_vlan or before_vlan != device.restore_vlan:
            raise ValueError("Switch access VLAN does not match the configured restore VLAN.")
        steps.append({"step": "preflight_interface", "success": True})

        if device.span_session is not None:
            span_command = (
                "show monitor session all"
                if device.vendor == "cisco_ios"
                else "show monitor session"
            )
            span_usage = connection.send_command(
                span_command, read_timeout=device.timeout
            )
            active_sessions = _active_span_sessions(span_usage)
            if (
                len(active_sessions) >= device.span_session_limit
                or device.span_session in active_sessions
            ):
                raise ValueError(
                    "The switch has no safely available SPAN session capacity."
                )
            span_lines = connection.send_command(
                f"show running-config | include ^monitor session {device.span_session} ",
                read_timeout=device.timeout,
            )
            if span_lines.strip():
                raise ValueError("Configured SPAN session already exists; it was not modified.")
            steps.append({"step": "preflight_span_session", "success": True})

        interface_changed = True
        isolate_commands = [
            f"interface {device.port_interface}",
            f"description {ISOLATION_DESCRIPTION}",
            f"switchport access vlan {device.isolation_vlan}",
        ]
        if device.port_bounce:
            isolate_commands.extend(["shutdown", "no shutdown"])
        isolate_commands.append("exit")
        connection.send_config_set(isolate_commands, cmd_verify=True)
        verify_output = connection.send_command(interface_command, read_timeout=device.timeout)
        actual_vlan, actual_description = _parse_interface_config(verify_output)
        if actual_vlan != device.isolation_vlan or actual_description != ISOLATION_DESCRIPTION:
            raise ValueError("Isolated interface did not match the requested configuration.")
        steps.append({"step": "configure_and_verify_interface", "success": True})
        if device.port_bounce:
            steps.append({"step": "port_bounce_session_drop", "success": True})

        if device.span_session is not None:
            span_attempted = True
            connection.send_config_set(
                _span_commands(
                    device.vendor, device.span_session,
                    device.port_interface, device.span_destination or "",
                ),
                cmd_verify=True,
            )
            span_lines = connection.send_command(
                f"show running-config | include ^monitor session {device.span_session} ",
                read_timeout=device.timeout,
            )
            expected_lines = _session_config(
                device.vendor, device.span_session,
                device.port_interface, device.span_destination or "",
            )
            if not all(line.lower() in span_lines.lower() for line in expected_lines):
                raise ValueError("Configured SPAN session did not match the requested source and destination.")
            steps.append({"step": "configure_and_verify_span", "success": True})

        connection.save_config()
        steps.append({"step": "save_config", "success": True})
        return {
            "success": True,
            "rollback_ok": True,
            "executed_cli": json.dumps(commands, indent=2),
            "cli_output": "Live configuration and running state verified.",
            "steps": steps,
            "original_vlan": before_vlan,
            "original_description": before_description,
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "sandbox_port": device.span_destination or "",
        }
    except Exception as exc:
        primary_error = _error_message(exc, "Isolation")
        LOGGER.warning("live_isolation_step_failed vendor=%s stage=%s", device.vendor, type(exc).__name__)
        steps.append({"step": "isolation", "success": False, "message": primary_error})
        if connection is not None and (interface_changed or span_attempted):
            try:
                if span_attempted and device.span_session is not None:
                    session_output = connection.send_command(
                        f"show running-config | include ^monitor session {device.span_session} ",
                        read_timeout=device.timeout,
                    )
                    expected_lines = _session_config(
                        device.vendor, device.span_session,
                        device.port_interface, device.span_destination or "",
                    )
                    if session_output.strip():
                        if all(line.lower() in session_output.lower() for line in expected_lines):
                            connection.send_config_set(
                                [f"no monitor session {device.span_session}"], cmd_verify=True
                            )
                        else:
                            raise ValueError("A different SPAN session appeared during rollback; it was not removed.")
                if interface_changed and before_vlan is not None:
                    restore_commands = _vlan_interface_commands(
                        device, before_vlan, before_description
                    )
                    connection.send_config_set(restore_commands, cmd_verify=True)
                output = connection.send_command(
                    f"show running-config interface {device.port_interface}"
                    if device.vendor == "cisco_ios"
                    else f"show running-config interfaces {device.port_interface}",
                    read_timeout=device.timeout,
                )
                restored_vlan, restored_description = _parse_interface_config(output)
                rollback_ok = restored_vlan == before_vlan and restored_description == before_description
                if device.span_session is not None and span_attempted:
                    remaining = connection.send_command(
                        f"show running-config | include ^monitor session {device.span_session} ",
                        read_timeout=device.timeout,
                    )
                    rollback_ok = rollback_ok and not remaining.strip()
                if rollback_ok:
                    connection.save_config()
                steps.append({"step": "rollback_and_verify", "success": rollback_ok})
            except Exception as rollback_exc:
                rollback_ok = False
                steps.append({
                    "step": "rollback_and_verify",
                    "success": False,
                    "message": _error_message(rollback_exc, "Rollback"),
                })
        return {
            "success": False,
            "rollback_ok": rollback_ok,
            "executed_cli": json.dumps(commands, indent=2),
            "cli_output": primary_error or "Isolation failed.",
            "steps": steps,
            "original_vlan": before_vlan,
            "original_description": before_description,
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "sandbox_port": device.span_destination or "",
        }
    finally:
        if connection is not None:
            try:
                connection.disconnect()
                steps.append({"step": "disconnect", "success": True})
            except Exception as exc:
                LOGGER.warning("netmiko_disconnect_failed vendor=%s error_type=%s", device.vendor, type(exc).__name__)


def _mock_isolate(inventory_record: Dict[str, Any]) -> Dict[str, Any]:
    vlan = 999
    commands = [
        f"interface {inventory_record['port_interface']}",
        f"description {ISOLATION_DESCRIPTION}",
        f"switchport access vlan {vlan}",
        "shutdown",
        "no shutdown",
        "exit",
    ]
    start = time.perf_counter()
    _, output = _mock_execute(commands, "ISOLATE")
    return {
        "success": True,
        "rollback_ok": True,
        "executed_cli": json.dumps(commands, indent=2),
        "cli_output": output,
        "steps": [
            {"step": "mock_isolation", "success": True},
            {"step": "port_bounce_session_drop", "success": True},
        ],
        "original_vlan": inventory_record["current_vlan"],
        "original_description": "",
        "honeypot_vlan": vlan,
        "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
        "sandbox_port": "",
    }


def _mock_acl_isolate(
    inventory_record: Dict[str, Any], target_ip: str
) -> Dict[str, Any]:
    host_ip = str(ipaddress.ip_address(inventory_record["host_ip"]))
    target = ipaddress.ip_address(target_ip)
    if target.version != 4 or not target.is_private:
        raise ConfigurationError("ACL containment requires a private IPv4 target.")
    if ipaddress.ip_address(host_ip).version != 4:
        raise ConfigurationError("ACL containment requires a private IPv4 attacker.")
    acl_name = _acl_name(host_ip)
    commands = _acl_definition_commands(
        inventory_record["switch_vendor"], acl_name, host_ip, str(target)
    ) + [
        f"interface {inventory_record['port_interface']}",
        f"ip access-group {acl_name} in",
        "exit",
    ]
    start = time.perf_counter()
    _, output = _mock_execute(commands, "ACL ISOLATE")
    return {
        "success": True,
        "rollback_ok": True,
        "executed_cli": json.dumps(commands, indent=2),
        "cli_output": output,
        "steps": [{"step": "mock_acl_isolation", "success": True}],
        "original_vlan": inventory_record["current_vlan"],
        "original_description": "MODE:acl",
        "honeypot_vlan": inventory_record["current_vlan"],
        "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
        "sandbox_port": "",
    }


def isolate_host(
    inventory_record: Dict[str, Any], mode: str = "vlan", target_ip: str = ""
) -> Dict[str, Any]:
    if mode not in {"vlan", "acl"}:
        raise ConfigurationError("Containment mode must be vlan or acl.")
    if mode == "acl":
        if not target_ip:
            raise ConfigurationError("ACL containment requires a target IP.")
        target = ipaddress.ip_address(target_ip)
        attacker = ipaddress.ip_address(inventory_record["host_ip"])
        if target.version != 4 or attacker.version != 4 or not target.is_private:
            raise ConfigurationError("ACL containment is limited to private IPv4 lab addresses.")
        if get_mock_mode():
            return _mock_acl_isolate(inventory_record, str(target))

    start = time.perf_counter()
    if get_mock_mode():
        result = _mock_isolate(inventory_record)
    else:
        device = _device_for_host(inventory_record)
        if mode == "acl":
            result = _live_acl_isolate(
                device, inventory_record["current_vlan"],
                str(attacker), str(target),
            )
        else:
            result = _live_isolate(device, inventory_record["current_vlan"])
    result["execution_time_ms"] = round((time.perf_counter() - start) * 1000, 2)
    if not result.get("honeypot_vlan"):
        result["honeypot_vlan"] = (
            999 if get_mock_mode() else _device_for_host(inventory_record).isolation_vlan
        )
    return result


def _live_acl_restore(
    inventory_record: Dict[str, Any], device: LabDevice, original_vlan: int
) -> Dict[str, Any]:
    from netmiko import ConnectHandler

    host_ip = inventory_record["host_ip"]
    acl_name = _acl_name(host_ip)
    steps: List[Dict[str, Any]] = []
    connection = None
    mutated = False
    start = time.perf_counter()
    removal = _acl_removal_commands(device.vendor, acl_name, device.port_interface)
    try:
        connection = ConnectHandler(
            device_type=device.vendor,
            host=device.switch_ip,
            port=device.port,
            username=os.environ["SENTRIX_LAB_USERNAME"],
            password=os.environ["SENTRIX_LAB_PASSWORD"],
            timeout=device.timeout,
            conn_timeout=device.timeout,
            auth_timeout=device.timeout,
            banner_timeout=device.timeout,
            fast_cli=False,
        )
        interface_command = (
            f"show running-config interface {device.port_interface}"
            if device.vendor == "cisco_ios"
            else f"show running-config interfaces {device.port_interface}"
        )
        interface_output = connection.send_command(
            interface_command, read_timeout=device.timeout
        )
        current_vlan, _ = _parse_interface_config(interface_output)
        if current_vlan != original_vlan or current_vlan != device.restore_vlan:
            raise AuthorizationError("The interface VLAN changed since ACL containment.")
        if not re.search(
            rf"(?im)^\s*ip access-group\s+{re.escape(acl_name)}\s+in\s*$",
            interface_output,
        ):
            raise AuthorizationError("The interface no longer has SENTRIX's inbound ACL.")
        acl_output = connection.send_command(
            "show running-config",
            read_timeout=device.timeout,
        )
        rule = re.search(
            rf"(?im)^\s*deny ip host {re.escape(host_ip)} host (\d{{1,3}}(?:\.\d{{1,3}}){{3}})\s*$",
            acl_output,
        )
        if not rule or "permit ip any any" not in acl_output:
            raise AuthorizationError("The SENTRIX ACL does not match the saved containment state.")
        target_ip = rule.group(1)
        expected_rules = [
            f"deny ip host {host_ip} host {target_ip}",
            "permit ip any any",
        ]
        if _acl_rules_from_config(acl_output, device.vendor, acl_name) != expected_rules:
            raise AuthorizationError("The SENTRIX ACL contains unexpected rules; it was not removed.")
        definition = _acl_definition_commands(
            device.vendor, acl_name, host_ip, target_ip
        )
        steps.append({"step": "preflight_saved_acl", "success": True})
        mutated = True
        connection.send_config_set(removal, cmd_verify=True)
        interface_output = connection.send_command(
            interface_command, read_timeout=device.timeout
        )
        remaining_acl = connection.send_command(
            "show running-config",
            read_timeout=device.timeout,
        )
        if (
            re.search(
                rf"(?im)^\s*ip access-group\s+{re.escape(acl_name)}\s+in\s*$",
                interface_output,
            )
            or _acl_rules_from_config(remaining_acl, device.vendor, acl_name) is not None
        ):
            raise ValueError("The SENTRIX ACL remained after restoration.")
        steps.append({"step": "remove_and_verify_acl", "success": True})
        connection.save_config()
        steps.append({"step": "save_config", "success": True})
        return {
            "success": True,
            "rollback_ok": True,
            "executed_cli": json.dumps(removal, indent=2),
            "cli_output": "SENTRIX ACL removed and verified.",
            "steps": steps,
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "honeypot_vlan": device.isolation_vlan,
            "sandbox_port": "",
        }
    except Exception as exc:
        message = _error_message(exc, "ACL restoration")
        steps.append({"step": "acl_restore", "success": False, "message": message})
        rollback_ok = not mutated
        if connection is not None and mutated:
            try:
                reapply = definition + [
                    f"interface {device.port_interface}",
                    f"ip access-group {acl_name} in",
                    "exit",
                ]
                connection.send_config_set(reapply, cmd_verify=True)
                interface_output = connection.send_command(
                    f"show running-config interface {device.port_interface}"
                    if device.vendor == "cisco_ios"
                    else f"show running-config interfaces {device.port_interface}",
                    read_timeout=device.timeout,
                )
                acl_output = connection.send_command(
                    "show running-config",
                    read_timeout=device.timeout,
                )
                rollback_ok = (
                    bool(re.search(
                        rf"(?im)^\s*ip access-group\s+{re.escape(acl_name)}\s+in\s*$",
                        interface_output,
                    ))
                    and f"deny ip host {host_ip} host {target_ip}" in acl_output
                    and "permit ip any any" in acl_output
                    and _acl_rules_from_config(acl_output, device.vendor, acl_name) == expected_rules
                )
                if rollback_ok:
                    connection.save_config()
                steps.append({"step": "rollback_and_verify", "success": rollback_ok})
            except Exception as rollback_exc:
                rollback_ok = False
                steps.append({
                    "step": "rollback_and_verify",
                    "success": False,
                    "message": _error_message(rollback_exc, "ACL rollback"),
                })
        return {
            "success": False,
            "rollback_ok": rollback_ok,
            "executed_cli": json.dumps(removal, indent=2),
            "cli_output": message,
            "steps": steps,
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "honeypot_vlan": device.isolation_vlan,
            "sandbox_port": "",
        }
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception as exc:
                LOGGER.warning("netmiko_disconnect_failed vendor=%s error_type=%s", device.vendor, type(exc).__name__)


def _live_restore(inventory_record: Dict[str, Any], device: LabDevice) -> Dict[str, Any]:
    from netmiko import ConnectHandler

    original_vlan = inventory_record.get("previous_vlan")
    original_description = inventory_record.get("previous_description") or ""
    if original_vlan is None or original_vlan != device.restore_vlan:
        raise AuthorizationError("Saved restore state is missing or differs from lab configuration.")
    if original_description == "MODE:acl":
        return _live_acl_restore(inventory_record, device, original_vlan)
    commands = _vlan_interface_commands(device, original_vlan, original_description)
    if device.span_session is not None:
        commands.append(f"no monitor session {device.span_session}")
    steps: List[Dict[str, Any]] = []
    connection = None
    start = time.perf_counter()
    mutated = False
    try:
        connection = ConnectHandler(
            device_type=device.vendor,
            host=device.switch_ip,
            port=device.port,
            username=os.environ["SENTRIX_LAB_USERNAME"],
            password=os.environ["SENTRIX_LAB_PASSWORD"],
            timeout=device.timeout,
            conn_timeout=device.timeout,
            auth_timeout=device.timeout,
            banner_timeout=device.timeout,
            fast_cli=False,
        )
        interface_command = (
            f"show running-config interface {device.port_interface}"
            if device.vendor == "cisco_ios"
            else f"show running-config interfaces {device.port_interface}"
        )
        output = connection.send_command(interface_command, read_timeout=device.timeout)
        current_vlan, current_description = _parse_interface_config(output)
        if current_vlan != device.isolation_vlan or current_description != ISOLATION_DESCRIPTION:
            raise AuthorizationError("The interface no longer matches SENTRIX's saved isolation state.")
        if device.span_session is not None:
            current_span = connection.send_command(
                f"show running-config | include ^monitor session {device.span_session} ",
                read_timeout=device.timeout,
            )
            expected_span = _session_config(
                device.vendor, device.span_session,
                device.port_interface, device.span_destination or "",
            )
            if not all(line.lower() in current_span.lower() for line in expected_span):
                raise AuthorizationError("The SPAN session is not SENTRIX's configured session; it was not removed.")
        steps.append({"step": "preflight_saved_state", "success": True})
        mutated = True
        connection.send_config_set(commands, cmd_verify=True)
        output = connection.send_command(interface_command, read_timeout=device.timeout)
        restored_vlan, restored_description = _parse_interface_config(output)
        if restored_vlan != original_vlan or restored_description != original_description:
            raise ValueError("Restored interface did not match its saved pre-isolation state.")
        if device.span_session is not None:
            remaining = connection.send_command(
                f"show running-config | include ^monitor session {device.span_session} ",
                read_timeout=device.timeout,
            )
            if remaining.strip():
                raise ValueError("Configured SPAN session remains after restoration.")
        steps.append({"step": "restore_and_verify", "success": True})
        if device.port_bounce:
            steps.append({"step": "port_bounce_session_drop", "success": True})
        connection.save_config()
        steps.append({"step": "save_config", "success": True})
        return {
            "success": True,
            "rollback_ok": True,
            "executed_cli": json.dumps(commands, indent=2),
            "cli_output": "Saved interface state restored and verified.",
            "steps": steps,
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "honeypot_vlan": device.isolation_vlan,
            "sandbox_port": device.span_destination or "",
        }
    except Exception as exc:
        message = _error_message(exc, "Restoration")
        steps.append({"step": "restore", "success": False, "message": message})
        LOGGER.warning("live_restoration_failed vendor=%s error_type=%s", device.vendor, type(exc).__name__)
        rollback_ok = not mutated
        if connection is not None and mutated:
            try:
                containment_commands = _vlan_interface_commands(
                    device, device.isolation_vlan, ISOLATION_DESCRIPTION
                )
                if device.span_session is not None:
                    span_output = connection.send_command(
                        f"show running-config | include ^monitor session {device.span_session} ",
                        read_timeout=device.timeout,
                    )
                    expected_span = _session_config(
                        device.vendor, device.span_session,
                        device.port_interface, device.span_destination or "",
                    )
                    if span_output.strip():
                        if not all(line.lower() in span_output.lower() for line in expected_span):
                            raise ValueError("A different SPAN session now uses the configured session number.")
                    else:
                        containment_commands.extend(_span_commands(
                            device.vendor, device.span_session,
                            device.port_interface, device.span_destination or "",
                        ))
                connection.send_config_set(containment_commands, cmd_verify=True)
                output = connection.send_command(
                    f"show running-config interface {device.port_interface}"
                    if device.vendor == "cisco_ios"
                    else f"show running-config interfaces {device.port_interface}",
                    read_timeout=device.timeout,
                )
                restored_vlan, restored_description = _parse_interface_config(output)
                rollback_ok = (
                    restored_vlan == device.isolation_vlan
                    and restored_description == ISOLATION_DESCRIPTION
                )
                if device.span_session is not None:
                    span_output = connection.send_command(
                        f"show running-config | include ^monitor session {device.span_session} ",
                        read_timeout=device.timeout,
                    )
                    expected_span = _session_config(
                        device.vendor, device.span_session,
                        device.port_interface, device.span_destination or "",
                    )
                    rollback_ok = rollback_ok and all(
                        line.lower() in span_output.lower() for line in expected_span
                    )
                if rollback_ok:
                    connection.save_config()
                steps.append({"step": "rollback_and_verify", "success": rollback_ok})
            except Exception as rollback_exc:
                rollback_ok = False
                steps.append({
                    "step": "rollback_and_verify",
                    "success": False,
                    "message": _error_message(rollback_exc, "Rollback"),
                })
        return {
            "success": False,
            "rollback_ok": rollback_ok,
            "executed_cli": json.dumps(commands, indent=2),
            "cli_output": message,
            "steps": steps,
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "honeypot_vlan": device.isolation_vlan,
            "sandbox_port": device.span_destination or "",
        }
    finally:
        if connection is not None:
            try:
                connection.disconnect()
                steps.append({"step": "disconnect", "success": True})
            except Exception as exc:
                LOGGER.warning("netmiko_disconnect_failed vendor=%s error_type=%s", device.vendor, type(exc).__name__)


def restore_host(inventory_record: Dict[str, Any]) -> Dict[str, Any]:
    start = time.perf_counter()
    if get_mock_mode():
        vlan = inventory_record.get("previous_vlan")
        if vlan is None:
            return {
                "success": False, "rollback_ok": True,
                "executed_cli": "[]", "cli_output": "Saved restore VLAN is missing.",
                "steps": [{"step": "preflight_saved_state", "success": False}],
                "execution_time_ms": 0.0, "honeypot_vlan": 999, "sandbox_port": "",
            }
        if inventory_record.get("previous_description") == "MODE:acl":
            commands = _acl_removal_commands(
                inventory_record["switch_vendor"],
                _acl_name(inventory_record["host_ip"]),
                inventory_record["port_interface"],
            )
            step = {"step": "mock_acl_restore", "success": True}
        else:
            commands = [
                f"interface {inventory_record['port_interface']}",
                f"switchport access vlan {vlan}",
                "shutdown",
                "no shutdown",
                "exit",
            ]
            step = {"step": "mock_restore", "success": True}
        _, output = _mock_execute(commands, "RESTORE")
        result = {
            "success": True, "rollback_ok": True,
            "executed_cli": json.dumps(commands, indent=2), "cli_output": output,
            "steps": [step] + (
                [{"step": "port_bounce_session_drop", "success": True}]
                if inventory_record.get("previous_description") != "MODE:acl"
                else []
            ),
            "execution_time_ms": round((time.perf_counter() - start) * 1000, 2),
            "honeypot_vlan": 999, "sandbox_port": "",
        }
    else:
        device = _device_for_host(inventory_record)
        result = _live_restore(inventory_record, device)
    result["execution_time_ms"] = round((time.perf_counter() - start) * 1000, 2)
    return result


def reconcile_host_state(
    inventory_record: Dict[str, Any],
    expected_target_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Read switch state for an allowlisted host without changing device or DB state."""
    if get_mock_mode():
        raise ConfigurationError("State reconciliation is available only in LIVE mode.")
    status = inventory_record["port_status"]
    previous_description = inventory_record.get("previous_description") or ""
    acl_mode = status == "ISOLATED" and previous_description == "MODE:acl"
    if status not in {"SECURE", "PENDING_APPROVAL", "ISOLATED"}:
        raise AuthorizationError(
            "Reconciliation requires a secure, pending-approval, or isolated host."
        )
    device = _device_for_host(inventory_record)
    from netmiko import ConnectHandler

    connection = None
    try:
        connection = ConnectHandler(
            device_type=device.vendor,
            host=device.switch_ip,
            port=device.port,
            username=os.environ["SENTRIX_LAB_USERNAME"],
            password=os.environ["SENTRIX_LAB_PASSWORD"],
            timeout=device.timeout,
            conn_timeout=device.timeout,
            auth_timeout=device.timeout,
            banner_timeout=device.timeout,
            fast_cli=False,
        )
        interface_command = (
            f"show running-config interface {device.port_interface}"
            if device.vendor == "cisco_ios"
            else f"show running-config interfaces {device.port_interface}"
        )
        interface_output = connection.send_command(
            interface_command, read_timeout=device.timeout
        )
        actual_vlan, actual_description = _parse_interface_config(interface_output)
        expected_vlan = (
            device.isolation_vlan if status == "ISOLATED" and not acl_mode
            else inventory_record["current_vlan"]
        )
        expected_description = (
            ISOLATION_DESCRIPTION
            if status == "ISOLATED" and not acl_mode else None
        )
        drift = []
        if actual_vlan != expected_vlan:
            drift.append("access_vlan")
        if expected_description is not None and actual_description != expected_description:
            drift.append("interface_description")

        actual_acl = None
        actual_acl_rules = None
        if acl_mode:
            acl_name = _acl_name(inventory_record["host_ip"])
            acl_output = connection.send_command(
                "show running-config", read_timeout=device.timeout
            )
            group_match = re.search(
                r"(?im)^\s*ip access-group\s+(\S+)\s+in\s*$",
                interface_output,
            )
            actual_acl = group_match.group(1) if group_match else None
            actual_acl_rules = _acl_rules_from_config(
                acl_output, device.vendor, acl_name
            )
            expected_rules_match = (
                actual_acl == acl_name and actual_acl_rules is not None
                and len(actual_acl_rules) == 2
                and re.fullmatch(
                    rf"deny ip host {re.escape(inventory_record['host_ip'])} host "
                    r"(?:\d{1,3}\.){3}\d{1,3}",
                    actual_acl_rules[0],
                )
                and actual_acl_rules[1] == "permit ip any any"
            )
            if expected_target_ip:
                expected_rules_match = expected_rules_match and actual_acl_rules == [
                    f"deny ip host {inventory_record['host_ip']} host {expected_target_ip}",
                    "permit ip any any",
                ]
            if not expected_rules_match:
                drift.append("inbound_acl")

        actual_span_lines: List[str] = []
        expected_span_lines: List[str] = []
        if device.span_session is not None:
            span_output = connection.send_command(
                f"show running-config | include ^monitor session {device.span_session} ",
                read_timeout=device.timeout,
            )
            actual_span_lines = [
                line.strip() for line in span_output.splitlines() if line.strip()
            ]
            if status == "ISOLATED" and not acl_mode:
                expected_span_lines = _session_config(
                    device.vendor, device.span_session,
                    device.port_interface, device.span_destination or "",
                )
            if [line.lower() for line in actual_span_lines] != [
                line.lower() for line in expected_span_lines
            ]:
                drift.append("span_session")

        return {
            "host_ip": inventory_record["host_ip"],
            "status": "DRIFT" if drift else "IN_SYNC",
            "drift": drift,
            "expected": {
                "access_vlan": expected_vlan,
                "interface_description": expected_description,
                "inbound_acl": _acl_name(inventory_record["host_ip"]) if acl_mode else None,
                "span_session": expected_span_lines,
            },
            "actual": {
                "access_vlan": actual_vlan,
                "interface_description": actual_description,
                "inbound_acl": actual_acl,
                "acl_rules": actual_acl_rules,
                "span_session": actual_span_lines,
            },
            "limitations": (
                ["Secure-state interface description baseline is not stored."]
                if status in {"SECURE", "PENDING_APPROVAL"} else []
            ),
        }
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception as exc:
                LOGGER.warning(
                    "reconciliation_disconnect_failed vendor=%s error_type=%s",
                    device.vendor, type(exc).__name__,
                )
