"""SENTRIX FastAPI application for the authorized GNS3 lab."""

import json
import logging
import random
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import IPvAnyAddress

import containment
import database as db
from models import (
    AlertWebhook,
    DashboardMetrics,
    DashboardState,
    SimulateAttackRequest,
)

LOGGER = logging.getLogger("sentrix.api")
STATIC_DIR = Path(__file__).parent / "static"

_SIM_SIGNATURES = [
    "SENTRIX lab test alert: workstation activity",
    "SENTRIX lab test alert: unusual connection pattern",
    "SENTRIX lab test alert: analyst validation event",
]
_SIM_TARGETS = ["192.168.10.100", "192.168.10.200", "10.0.0.10"]
CRITICAL_ROLES = {"Production File Server", "Core Server", "Database Server"}


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        event_data = getattr(record, "event_data", None)
        if event_data:
            entry.update(event_data)
        return json.dumps(entry, separators=(",", ":"), ensure_ascii=True)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    if not any(getattr(item.formatter, "__class__", None) is JsonLogFormatter for item in root.handlers):
        root.addHandler(handler)
    root.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    containment.validate_startup()
    db.init_db()
    LOGGER.info(
        "application_started",
        extra={"event_data": {"mode": containment.get_mode()}},
    )
    yield


app = FastAPI(
    title="SENTRIX Lab Containment",
    version="2.0.0",
    description="Inventory, alert handling, and explicitly authorized GNS3 lab containment.",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "Invalid request payload."})


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health():
    return {"status": "ok", "mode": containment.get_mode()}


def _authorize(token: Optional[str], confirmation: Optional[str]) -> None:
    try:
        containment.authorize_live_change(token, confirmation)
    except containment.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _authorize_approval(
    live_token: Optional[str],
    confirmation: Optional[str],
    approval_token: Optional[str],
    approver: Optional[str],
) -> str:
    try:
        return containment.authorize_approval(
            live_token, confirmation, approval_token, approver
        )
    except containment.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _record_failure(host_ip: str, action: str, result: dict, safe_state: str) -> None:
    db.fail_operation(
        host_ip=host_ip,
        action=action,
        safe_state=safe_state,
        message=result["cli_output"],
        execution_time_ms=result["execution_time_ms"],
        steps=result["steps"],
        previous_vlan=result.get("original_vlan"),
        previous_description=result.get("original_description"),
    )
    LOGGER.warning(
        "network_operation_finished",
        extra={
            "event_data": {
                "action": action,
                "host_ip": host_ip,
                "result": "FAILED",
                "execution_time_ms": result["execution_time_ms"],
                "steps": result["steps"],
            }
        },
    )


@app.post("/api/webhook/alert", response_model=None)
def receive_alert(
    alert: AlertWebhook,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
):
    return _handle_alert(alert, x_sentrix_live_token, x_confirm_live_change)


def _handle_alert(
    alert: AlertWebhook,
    x_sentrix_live_token: Optional[str],
    x_confirm_live_change: Optional[str],
    bypass_approval: bool = False,
):
    """Accept an alert and isolate only its exact inventory/allowlist host."""
    _authorize(x_sentrix_live_token, x_confirm_live_change)
    attacker_ip = str(alert.attacker_ip)
    target_ip = str(alert.target_ip)
    host = db.lookup_host(attacker_ip)
    if host is None:
        if not alert.auto_discover:
            raise HTTPException(status_code=404, detail="Attacker host is not in the inventory.")
        try:
            discovered = containment.discover_host_port(attacker_ip)
            host = db.register_discovered_host(discovered)
        except containment.AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except containment.ConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            LOGGER.exception("host_discovery_failed host_ip=%s", attacker_ip)
            raise HTTPException(status_code=502, detail="Host discovery failed.") from exc

    if host["port_role"] in CRITICAL_ROLES and not bypass_approval:
        payload = alert.model_dump(mode="json")
        if not db.mark_pending_approval(attacker_ip, payload):
            raise HTTPException(status_code=409, detail="Host is unavailable for approval.")
        return JSONResponse(
            status_code=202,
            content={
                "status": "PENDING_APPROVAL",
                "host_ip": attacker_ip,
                "approve_url": f"/api/approvals/{attacker_ip}/approve",
                "reject_url": f"/api/approvals/{attacker_ip}/reject",
            },
        )

    claimed = db.claim_host(attacker_ip, "isolate")
    if claimed is None:
        if bypass_approval:
            db.mark_pending_approval(attacker_ip, alert.model_dump(mode="json"))
        raise HTTPException(status_code=409, detail="Host is unavailable or already has an operation in progress.")
    try:
        if alert.containment_mode == "acl":
            result = containment.isolate_host(
                claimed, mode="acl", target_ip=target_ip
            )
        else:
            result = containment.isolate_host(claimed)
    except containment.ConfigurationError as exc:
        rejected = {
            "cli_output": str(exc), "execution_time_ms": 0.0, "steps": [],
            "rollback_ok": True,
        }
        _record_failure(attacker_ip, "isolate", rejected, "SECURE")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except containment.AuthorizationError as exc:
        rejected = {
            "cli_output": str(exc), "execution_time_ms": 0.0, "steps": [],
            "rollback_ok": True,
        }
        _record_failure(attacker_ip, "isolate", rejected, "SECURE")
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("containment_engine_error host_ip=%s", attacker_ip)
        failed = {
            "cli_output": "Containment engine failed unexpectedly.",
            "execution_time_ms": 0.0,
            "steps": [{"step": "engine", "success": False}],
            "rollback_ok": False,
        }
        _record_failure(attacker_ip, "isolate", failed, "ERROR_REQUIRES_REVIEW")
        raise HTTPException(status_code=500, detail=failed["cli_output"]) from exc

    if not result["success"]:
        safe_state = "SECURE" if result["rollback_ok"] else "ERROR_REQUIRES_REVIEW"
        _record_failure(attacker_ip, "isolate", result, safe_state)
        raise HTTPException(status_code=502, detail=result["cli_output"])

    assigned_vlan = result["honeypot_vlan"]
    ticket_data = {
        "attacker_ip": attacker_ip,
        "attacker_mac": claimed["host_mac"],
        "target_ip": target_ip,
        "signature": alert.signature,
        "severity": alert.severity,
        "switch_hostname": claimed["switch_hostname"],
        "vendor": claimed["switch_vendor"],
        "isolated_port": claimed["port_interface"],
    }
    try:
        ticket = db.finalize_isolation(
            host_ip=attacker_ip,
            ticket_data=ticket_data,
            assigned_vlan=assigned_vlan,
            previous_vlan=result["original_vlan"],
            previous_description=result["original_description"],
            span_destination=result["sandbox_port"],
            execution_time_ms=result["execution_time_ms"],
            executed_cli=result["executed_cli"],
            steps=result["steps"],
        )
    except Exception as exc:
        LOGGER.exception("isolation_persistence_failed host_ip=%s", attacker_ip)
        db.fail_operation(
            attacker_ip, "isolate", "ERROR_REQUIRES_REVIEW",
            "Device change was verified, but database finalization failed; manual review is required.",
            result["execution_time_ms"], result["steps"],
            result["original_vlan"], result["original_description"],
        )
        raise HTTPException(
            status_code=500,
            detail="Device change completed but could not be recorded; manual review is required.",
        ) from exc
    LOGGER.info(
        "network_operation_finished",
        extra={
            "event_data": {
                "action": "isolate",
                "host_ip": attacker_ip,
                "ticket_id": ticket["ticket_id"],
                "result": "SUCCESS",
                "execution_time_ms": result["execution_time_ms"],
                "steps": result["steps"],
            }
        },
    )
    return ticket


@app.post("/api/discover/{ip}")
def manually_discover_host(
    ip: IPvAnyAddress,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
):
    _authorize(x_sentrix_live_token, x_confirm_live_change)
    target_ip = str(ip)
    try:
        discovery = containment.discover_host_port(target_ip)
        host = db.register_discovered_host(discovery)
    except containment.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except containment.ConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("manual_host_discovery_failed host_ip=%s", target_ip)
        raise HTTPException(status_code=502, detail="Host discovery failed.") from exc
    return {"host": host, "discovery_cli": discovery["discovery_cli"]}


@app.post("/api/approvals/{ip}/approve", response_model=None)
def approve_host_alert(
    ip: IPvAnyAddress,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
    x_sentrix_approval_token: Optional[str] = Header(default=None, alias="X-SENTRIX-APPROVAL-TOKEN"),
    x_authenticated_user: Optional[str] = Header(default=None, alias="X-Authenticated-User"),
):
    approver = _authorize_approval(
        x_sentrix_live_token, x_confirm_live_change,
        x_sentrix_approval_token, x_authenticated_user,
    )
    host_ip = str(ip)
    payload = db.resolve_pending_approval(
        host_ip, approved=True, approver=approver
    )
    if payload is None:
        raise HTTPException(status_code=409, detail="No pending approval exists for this host.")
    alert = AlertWebhook.model_validate(payload)
    if str(alert.attacker_ip) != host_ip:
        raise HTTPException(status_code=409, detail="Approval payload does not match the host.")
    return _handle_alert(alert, x_sentrix_live_token, x_confirm_live_change, True)


@app.post("/api/approvals/{ip}/reject")
def reject_host_alert(
    ip: IPvAnyAddress,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
    x_sentrix_approval_token: Optional[str] = Header(default=None, alias="X-SENTRIX-APPROVAL-TOKEN"),
    x_authenticated_user: Optional[str] = Header(default=None, alias="X-Authenticated-User"),
):
    approver = _authorize_approval(
        x_sentrix_live_token, x_confirm_live_change,
        x_sentrix_approval_token, x_authenticated_user,
    )
    host_ip = str(ip)
    payload = db.resolve_pending_approval(
        host_ip, approved=False, approver=approver
    )
    if payload is None:
        raise HTTPException(status_code=409, detail="No pending approval exists for this host.")
    return {"status": "REJECTED", "host_ip": host_ip}


@app.post("/api/simulate/attack")
def simulate_attack(
    body: SimulateAttackRequest = SimulateAttackRequest(),
):
    """Generate a harmless local test alert; unavailable in LIVE mode."""
    if not containment.get_mock_mode():
        raise HTTPException(status_code=403, detail="Alert simulation is available only in MOCK mode.")
    if body.attacker_ip:
        host_ip = str(body.attacker_ip)
        host = db.lookup_host(host_ip)
        if host is None and not containment.get_mock_mode():
            raise HTTPException(status_code=404, detail="Host is not in the inventory.")
        if host is not None and host["port_status"] != "SECURE":
            raise HTTPException(status_code=409, detail="Host is not available for a test alert.")
    else:
        available = [
            item for item in db.get_secure_hosts()
            if item["port_role"] in {"Workstation", "Dev Workstation"}
        ]
        if not available:
            raise HTTPException(status_code=409, detail="No available workstation for a test alert.")
        host = random.choice(available)
        host_ip = host["host_ip"]
    alert = AlertWebhook(
        attacker_ip=host_ip,
        target_ip=random.choice(_SIM_TARGETS),
        signature=random.choice(_SIM_SIGNATURES),
        severity=2,
        auto_discover=True,
        containment_mode=body.containment_mode,
    )
    return receive_alert(alert, None, None)


@app.post("/api/ports/{ip}/restore")
def restore_port(
    ip: IPvAnyAddress,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
):
    """Restore a port to its saved pre-isolation state."""
    _authorize(x_sentrix_live_token, x_confirm_live_change)
    host_ip = str(ip)
    host = db.lookup_host(host_ip)
    if host is None:
        raise HTTPException(status_code=404, detail="Host is not in the inventory.")
    claimed = db.claim_host(host_ip, "restore")
    if claimed is None:
        raise HTTPException(status_code=409, detail="Host is not isolated or another operation is in progress.")
    try:
        result = containment.restore_host(claimed)
    except (containment.ConfigurationError, containment.AuthorizationError) as exc:
        safe_state = "ISOLATED"
        failed = {
            "cli_output": str(exc), "execution_time_ms": 0.0, "steps": [],
            "rollback_ok": True,
        }
        _record_failure(host_ip, "restore", failed, safe_state)
        status = 403 if isinstance(exc, containment.AuthorizationError) else 503
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("restoration_engine_error host_ip=%s", host_ip)
        failed = {
            "cli_output": "Restoration engine failed unexpectedly.",
            "execution_time_ms": 0.0,
            "steps": [{"step": "engine", "success": False}],
            "rollback_ok": False,
        }
        _record_failure(host_ip, "restore", failed, "ERROR_REQUIRES_REVIEW")
        raise HTTPException(status_code=500, detail=failed["cli_output"]) from exc

    if not result["success"]:
        safe_state = "ISOLATED" if result["rollback_ok"] else "ERROR_REQUIRES_REVIEW"
        _record_failure(host_ip, "restore", result, safe_state)
        raise HTTPException(status_code=502, detail=result["cli_output"])
    try:
        ticket = db.finalize_restoration(
            host_ip=host_ip,
            previous_vlan=claimed["previous_vlan"],
            execution_time_ms=result["execution_time_ms"],
            message="Saved pre-isolation state restored and verified.",
            steps=result["steps"],
        )
    except Exception as exc:
        LOGGER.exception("restoration_persistence_failed host_ip=%s", host_ip)
        db.fail_operation(
            host_ip, "restore", "ERROR_REQUIRES_REVIEW",
            "Device restoration was verified, but database finalization failed; manual review is required.",
            result["execution_time_ms"], result["steps"],
        )
        raise HTTPException(
            status_code=500,
            detail="Device restoration completed but could not be recorded; manual review is required.",
        ) from exc
    LOGGER.info(
        "network_operation_finished",
        extra={
            "event_data": {
                "action": "restore",
                "host_ip": host_ip,
                "ticket_id": ticket["ticket_id"] if ticket else None,
                "result": "SUCCESS",
                "execution_time_ms": result["execution_time_ms"],
                "steps": result["steps"],
            }
        },
    )
    return {
        "message": "Host restored to its saved pre-isolation state.",
        "execution_time_ms": result["execution_time_ms"],
        "resolved_ticket": ticket["ticket_id"] if ticket else None,
    }


@app.get("/api/reconcile/{ip}")
def reconcile_port_state(
    ip: IPvAnyAddress,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
):
    _authorize(x_sentrix_live_token, x_confirm_live_change)
    host_ip = str(ip)
    host = db.lookup_host(host_ip)
    if host is None:
        raise HTTPException(status_code=404, detail="Host is not in the inventory.")
    latest_ticket = next(
        (ticket for ticket in db.get_tickets() if ticket["attacker_ip"] == host_ip),
        None,
    )
    expected_target = latest_ticket["target_ip"] if latest_ticket else None
    try:
        return containment.reconcile_host_state(host, expected_target)
    except containment.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except containment.ConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("state_reconciliation_failed host_ip=%s", host_ip)
        raise HTTPException(status_code=502, detail="Switch state reconciliation failed.") from exc


@app.get("/api/state", response_model=DashboardState)
def get_state():
    return DashboardState(
        metrics=DashboardMetrics(
            total_alerts=db.total_alerts(),
            currently_isolated=db.count_isolated(),
            average_execution_time_ms=db.average_execution_time(),
            active_span_sessions=db.count_active_span(),
            monitored_switches=db.count_switches(),
            engine_mode=containment.get_mode(),
            pending_approvals=db.count_pending_approvals(),
        ),
        inventory=db.get_inventory(),
        tickets=db.get_tickets(),
        last_operation=db.get_last_operation(),
    )
