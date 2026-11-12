"""Validated API schemas for alerts and dashboard responses."""

import re
from typing import List, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    ValidationInfo,
    field_validator,
)


class AlertWebhook(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attacker_ip: IPvAnyAddress
    target_ip: IPvAnyAddress
    signature: str = Field(min_length=1, max_length=240)
    severity: int = Field(default=1, ge=1, le=5)
    auto_discover: bool = True
    containment_mode: Literal["vlan", "acl"] = "vlan"

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("signature must contain printable text")
        return value


class SimulateAttackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attacker_ip: Optional[IPvAnyAddress] = None
    containment_mode: Literal["vlan", "acl"] = "vlan"


class ChatOpsAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=8, max_length=80)
    action: Literal["approve_vlan", "approve_acl", "reject"]
    channel: Literal["Mobile Simulator"] = "Mobile Simulator"


class ChatOpsConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    telegram_bot_token: Optional[str] = Field(default=None, max_length=512)
    telegram_chat_id: Optional[str] = Field(default=None, max_length=128)

    @field_validator("telegram_bot_token", "telegram_chat_id")
    @classmethod
    def validate_optional_config(
        cls, value: Optional[str], info: ValidationInfo
    ) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        if not value:
            return None
        if info.field_name == "telegram_bot_token" and not re.fullmatch(
            r"\d+:[A-Za-z0-9_-]+", value
        ):
            raise ValueError("telegram_bot_token has an invalid format.")
        if info.field_name == "telegram_chat_id" and not re.fullmatch(
            r"[1-9]\d{0,19}", value
        ):
            raise ValueError("telegram_chat_id must be a positive private-chat ID.")
        return value


class NetworkInventoryRecord(BaseModel):
    id: int
    host_ip: str
    host_mac: str
    switch_ip: str
    switch_vendor: str
    switch_hostname: str
    port_interface: str
    port_role: str
    current_vlan: int
    port_status: str
    span_status: str
    last_updated: str


class IncidentTicket(BaseModel):
    ticket_id: str
    timestamp: str
    attacker_ip: str
    attacker_mac: str
    target_ip: str
    signature: str
    severity: int
    switch_hostname: str
    vendor: str
    isolated_port: str
    assigned_vlan: int
    span_destination: str
    execution_time_ms: float
    executed_cli: str
    ticket_status: str
    resolved_mac: str = ""
    discovered_switch: str = ""
    discovered_port: str = ""
    port_type: str = ""
    hunt_trace_json: str = "{}"
    hunt_time_ms: float = 0.0
    trunk_guard_warning: str = ""
    containment_mode: Literal["vlan", "acl"] = "vlan"
    approval_channel: str = ""
    approved_action: str = ""
    approval_response_ms: float = 0.0


class DashboardMetrics(BaseModel):
    total_alerts: int
    currently_isolated: int
    average_execution_time_ms: float
    active_span_sessions: int
    monitored_switches: int
    engine_mode: str
    pending_approvals: int


class OperationResult(BaseModel):
    action: str
    host_ip: str
    result: str
    message: str
    completed_at: str
    approval_channel: str = ""
    approved_action: str = ""
    approval_response_ms: float = 0.0
    executed_cli: str = "[]"


class PendingChatOpsAlert(BaseModel):
    alert_id: str
    attacker_ip: str
    target_ip: str
    asset_name: str
    signature: str
    severity: int
    discovered_switch: str = ""
    discovered_port: str = ""
    port_type: str = ""
    requested_at: str = ""


class DashboardState(BaseModel):
    metrics: DashboardMetrics
    inventory: List[NetworkInventoryRecord]
    tickets: List[IncidentTicket]
    pending_approvals: List[PendingChatOpsAlert] = Field(default_factory=list)
    last_operation: Optional[OperationResult] = None
