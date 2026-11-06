"""Validated API schemas for alerts and dashboard responses."""

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


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


class DashboardState(BaseModel):
    metrics: DashboardMetrics
    inventory: List[NetworkInventoryRecord]
    tickets: List[IncidentTicket]
    last_operation: Optional[OperationResult] = None
