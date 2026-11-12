"""SENTRIX FastAPI application for the authorized GNS3 lab."""

import asyncio
import json
import logging
import random
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import IPvAnyAddress

import containment
import database as db
from models import (
    AlertWebhook,
    ChatOpsAction,
    ChatOpsConfigUpdate,
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
    telegram_task = asyncio.create_task(_telegram_updates_worker())
    try:
        yield
    finally:
        telegram_task.cancel()
        try:
            await telegram_task
        except asyncio.CancelledError:
            pass


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


def _process_chatops_action(
    alert_id: str,
    action: str,
    channel: str,
    approver: str = "SENTRIX_CHATOPS_ADMIN",
):
    pending = db.get_pending_approval(alert_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="Pending ChatOps alert was not found.")
    host_ip = pending["host_ip"]
    approved = action != "reject"
    approved_action = {
        "approve_vlan": "vlan_isolation",
        "approve_acl": "surgical_acl",
        "reject": "rejected",
    }.get(action)
    if approved_action is None:
        raise HTTPException(status_code=422, detail="Unsupported ChatOps action.")
    payload = db.resolve_pending_approval(
        host_ip,
        approved=approved,
        approver=approver,
        approval_channel=channel,
        approved_action=approved_action,
        expected_approval_id=alert_id,
    )
    if payload is None:
        raise HTTPException(status_code=409, detail="ChatOps alert was already handled.")
    if not approved:
        return {
            "status": "REJECTED",
            "host_ip": host_ip,
            "alert_id": alert_id,
            "approval_channel": channel,
        }
    payload["containment_mode"] = (
        "acl" if action == "approve_acl" else "vlan"
    )
    alert_fields = {
        "attacker_ip", "target_ip", "signature", "severity",
        "auto_discover", "containment_mode",
    }
    alert = AlertWebhook.model_validate({
        key: value for key, value in payload.items() if key in alert_fields
    })
    return _handle_alert(
        alert,
        None,
        None,
        bypass_approval=True,
        approval_metadata=payload,
    )


async def _telegram_updates_worker() -> None:
    offset: Optional[int] = None
    active_token = ""
    async with httpx.AsyncClient(timeout=22.0) as client:
        while True:
            config = containment.get_telegram_config()
            if not config["token"] or not config["chat_id"]:
                await asyncio.sleep(2)
                continue
            if config["token"] != active_token:
                active_token = config["token"]
                offset = None
            params = {"timeout": 15}
            if offset is not None:
                params["offset"] = offset
            try:
                response = await client.get(
                    f"https://api.telegram.org/bot{config['token']}/getUpdates",
                    params=params,
                )
                response.raise_for_status()
                result = response.json()
                if not result.get("ok"):
                    LOGGER.error("telegram_poll_failed response_not_ok")
                    await asyncio.sleep(5)
                    continue
                for update in result.get("result", []):
                    offset = max(offset or 0, int(update["update_id"]) + 1)
                    callback = update.get("callback_query")
                    if not callback:
                        continue
                    callback_id = callback.get("id", "")
                    message = callback.get("message") or {}
                    chat_id = str((message.get("chat") or {}).get("id", ""))
                    sender_id = str((callback.get("from") or {}).get("id", ""))
                    if (
                        chat_id != config["chat_id"]
                        or sender_id != config["chat_id"]
                    ):
                        await _telegram_answer_callback(
                            client, config["token"], callback_id,
                            "Unauthorized chat.", alert=False,
                        )
                        continue
                    match = re.fullmatch(
                        r"(approve_vlan|approve_acl|reject):([0-9a-f]{32})",
                        str(callback.get("data", "")),
                    )
                    if not match:
                        await _telegram_answer_callback(
                            client, config["token"], callback_id,
                            "Invalid or expired action.", alert=True,
                        )
                        continue
                    action, alert_id = match.groups()
                    try:
                        await asyncio.to_thread(
                            _process_chatops_action,
                            alert_id,
                            action,
                            "Telegram ChatOps",
                            f"Telegram chat {config['chat_id']}",
                        )
                        result_text = "Action processed successfully."
                        show_alert = False
                    except HTTPException as exc:
                        result_text = exc.detail
                        show_alert = True
                    except Exception:
                        LOGGER.exception("telegram_chatops_action_failed alert_id=%s", alert_id)
                        result_text = "SENTRIX could not process this action."
                        show_alert = True
                    await _telegram_answer_callback(
                        client, config["token"], callback_id,
                        result_text, alert=show_alert,
                    )
            except asyncio.CancelledError:
                raise
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                LOGGER.error(
                    "telegram_poll_failed error_type=%s", type(exc).__name__
                )
                await asyncio.sleep(5)


async def _telegram_answer_callback(
    client: httpx.AsyncClient,
    token: str,
    callback_id: str,
    text: str,
    alert: bool,
) -> None:
    try:
        response = await client.post(
            f"https://api.telegram.org/bot{token}/answerCallbackQuery",
            json={
                "callback_query_id": callback_id,
                "text": text[:200],
                "show_alert": alert,
            },
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        LOGGER.error(
            "telegram_callback_answer_failed error_type=%s", type(exc).__name__
        )


def _record_failure(
    host_ip: str,
    action: str,
    result: dict,
    safe_state: str,
    approval_metadata: Optional[dict] = None,
) -> None:
    metadata = approval_metadata or {}
    db.fail_operation(
        host_ip=host_ip,
        action=action,
        safe_state=safe_state,
        message=result["cli_output"],
        execution_time_ms=result["execution_time_ms"],
        steps=result["steps"],
        previous_vlan=result.get("original_vlan"),
        previous_description=result.get("original_description"),
        approval_channel=metadata.get("approval_channel", ""),
        approved_action=metadata.get("approved_action", ""),
        approval_response_ms=metadata.get("approval_response_ms", 0.0),
        executed_cli=result.get("executed_cli", "[]"),
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
    background_tasks: BackgroundTasks,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
):
    return _handle_alert(
        alert, x_sentrix_live_token, x_confirm_live_change,
        background_tasks=background_tasks,
    )


def _handle_alert(
    alert: AlertWebhook,
    x_sentrix_live_token: Optional[str],
    x_confirm_live_change: Optional[str],
    bypass_approval: bool = False,
    approval_metadata: Optional[dict] = None,
    background_tasks: Optional[BackgroundTasks] = None,
):
    """Accept an alert and isolate only its exact inventory/allowlist host."""
    if not bypass_approval:
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
        try:
            approval_hunt = containment.hunt_ip_port(attacker_ip, host)
            if (
                approval_hunt["switch_ip"] != host["switch_ip"]
                or approval_hunt["port"] != host["port_interface"]
            ):
                raise containment.AuthorizationError(
                    "The traced endpoint does not match the critical asset inventory."
                )
        except containment.AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except containment.ConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            LOGGER.exception("critical_asset_hunt_failed host_ip=%s", attacker_ip)
            raise HTTPException(
                status_code=502, detail="Critical asset network trace failed."
            ) from exc
        payload.update({
            "approval_id": uuid.uuid4().hex,
            "asset_name": host["port_role"],
            "approval_hunt": approval_hunt,
        })
        if not db.mark_pending_approval(attacker_ip, payload):
            raise HTTPException(status_code=409, detail="Host is unavailable for approval.")
        if background_tasks is not None:
            background_tasks.add_task(containment.send_telegram_approval, payload)
        else:
            containment.send_telegram_approval(payload)
        return JSONResponse(
            status_code=202,
            content={
                "status": "PENDING_APPROVAL",
                "host_ip": attacker_ip,
                "alert_id": payload["approval_id"],
                "approve_url": f"/api/approvals/{attacker_ip}/approve",
                "reject_url": f"/api/approvals/{attacker_ip}/reject",
            },
        )

    claimed = db.claim_host(attacker_ip, "isolate")
    if claimed is None:
        if bypass_approval:
            retry_payload = alert.model_dump(mode="json")
            retry_payload.update(approval_metadata or {})
            retry_payload["containment_mode"] = alert.containment_mode
            db.mark_pending_approval(attacker_ip, retry_payload)
        raise HTTPException(status_code=409, detail="Host is unavailable or already has an operation in progress.")
    try:
        hunt = containment.hunt_ip_port(attacker_ip, claimed)
        if (
            hunt["switch_ip"] != claimed["switch_ip"]
            or hunt["port"] != claimed["port_interface"]
        ):
            raise containment.AuthorizationError(
                "The traced endpoint does not match the claimed inventory switch and port."
            )
    except containment.AuthorizationError as exc:
        rejected = {
            "cli_output": str(exc), "execution_time_ms": 0.0,
            "steps": [{"step": "ip_to_port_hunt", "success": False, "message": str(exc)}],
            "rollback_ok": True,
        }
        _record_failure(attacker_ip, "isolate", rejected, "SECURE", approval_metadata)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except containment.ConfigurationError as exc:
        rejected = {
            "cli_output": str(exc), "execution_time_ms": 0.0,
            "steps": [{"step": "ip_to_port_hunt", "success": False, "message": str(exc)}],
            "rollback_ok": True,
        }
        _record_failure(attacker_ip, "isolate", rejected, "SECURE", approval_metadata)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("ip_to_port_hunt_failed host_ip=%s", attacker_ip)
        rejected = {
            "cli_output": "IP-to-port trace failed; containment was not attempted.",
            "execution_time_ms": 0.0,
            "steps": [{"step": "ip_to_port_hunt", "success": False}],
            "rollback_ok": True,
        }
        _record_failure(attacker_ip, "isolate", rejected, "SECURE", approval_metadata)
        raise HTTPException(status_code=502, detail=rejected["cli_output"]) from exc

    hunt_audit = {
        "step": "ip_to_port_hunt",
        "success": True,
        "execution_time_ms": hunt["hunt_time_ms"],
        "commands": hunt["hunt_cli"],
        "trace": hunt["trace"],
        "trunk_guard_override": hunt["trunk_guard_override"],
    }
    containment_mode = (
        "acl" if hunt["trunk_guard_override"] else alert.containment_mode
    )
    if hunt["trunk_guard_override"]:
        if approval_metadata is not None:
            approval_metadata["approved_action"] = "surgical_acl"
        LOGGER.warning(
            "trunk_guard_override host_ip=%s switch=%s port=%s",
            attacker_ip, hunt["switch_hostname"], hunt["port"],
        )
    try:
        if containment_mode == "acl":
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
        rejected["steps"].insert(0, hunt_audit)
        _record_failure(attacker_ip, "isolate", rejected, "SECURE", approval_metadata)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except containment.AuthorizationError as exc:
        rejected = {
            "cli_output": str(exc), "execution_time_ms": 0.0, "steps": [],
            "rollback_ok": True,
        }
        rejected["steps"].insert(0, hunt_audit)
        _record_failure(attacker_ip, "isolate", rejected, "SECURE", approval_metadata)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("containment_engine_error host_ip=%s", attacker_ip)
        failed = {
            "cli_output": "Containment engine failed unexpectedly.",
            "execution_time_ms": 0.0,
            "steps": [{"step": "engine", "success": False}],
            "rollback_ok": False,
        }
        failed["steps"].insert(0, hunt_audit)
        _record_failure(
            attacker_ip, "isolate", failed, "ERROR_REQUIRES_REVIEW",
            approval_metadata,
        )
        raise HTTPException(status_code=500, detail=failed["cli_output"]) from exc

    result["steps"] = [hunt_audit] + result["steps"]
    if not result["success"]:
        safe_state = "SECURE" if result["rollback_ok"] else "ERROR_REQUIRES_REVIEW"
        _record_failure(attacker_ip, "isolate", result, safe_state, approval_metadata)
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
        "resolved_mac": hunt["resolved_mac"],
        "discovered_switch": hunt["switch_hostname"],
        "discovered_port": hunt["port"],
        "port_type": hunt["port_type"],
        "trunk_guard_warning": hunt["warning"],
    }
    approval_response_ms = float(
        (approval_metadata or {}).get("approval_response_ms", 0.0)
    )
    if approval_metadata is not None:
        approval_response_ms = round(
            approval_response_ms + result["execution_time_ms"], 2
        )
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
            hunt_trace=hunt,
            containment_mode=containment_mode,
            approval_channel=(approval_metadata or {}).get("approval_channel", ""),
            approved_action=(approval_metadata or {}).get("approved_action", ""),
            approval_response_ms=approval_response_ms,
        )
    except Exception as exc:
        LOGGER.exception("isolation_persistence_failed host_ip=%s", attacker_ip)
        db.fail_operation(
            attacker_ip, "isolate", "ERROR_REQUIRES_REVIEW",
            "Device change was verified, but database finalization failed; manual review is required.",
            result["execution_time_ms"], result["steps"],
            result["original_vlan"], result["original_description"],
            approval_channel=(approval_metadata or {}).get("approval_channel", ""),
            approved_action=(approval_metadata or {}).get("approved_action", ""),
            approval_response_ms=approval_response_ms,
            executed_cli=result.get("executed_cli", "[]"),
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


@app.post("/api/hunt/{ip}")
def manually_hunt_ip(
    ip: IPvAnyAddress,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
):
    _authorize(x_sentrix_live_token, x_confirm_live_change)
    target_ip = str(ip)
    try:
        return containment.hunt_ip_port(target_ip, db.lookup_host(target_ip))
    except containment.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except containment.ConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("manual_ip_hunt_failed host_ip=%s", target_ip)
        raise HTTPException(status_code=502, detail="IP-to-port trace failed.") from exc


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
    pending = next(
        (item for item in db.get_pending_approvals()
         if item["attacker_ip"] == host_ip),
        None,
    )
    if pending is None:
        raise HTTPException(status_code=409, detail="No pending approval exists for this host.")
    pending_payload = db.get_pending_approval(pending["alert_id"]) or {}
    action = (
        "approve_acl"
        if pending_payload.get("containment_mode") == "acl"
        else "approve_vlan"
    )
    return _process_chatops_action(
        pending["alert_id"], action, "Dashboard", approver
    )


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
    pending = next(
        (item for item in db.get_pending_approvals()
         if item["attacker_ip"] == host_ip),
        None,
    )
    if pending is None:
        raise HTTPException(status_code=409, detail="No pending approval exists for this host.")
    return _process_chatops_action(
        pending["alert_id"], "reject", "Dashboard", approver
    )


@app.get("/api/chatops/config")
def get_chatops_config():
    config = containment.get_telegram_config()
    return {
        "configured": bool(config["token"] and config["chat_id"]),
        "token_configured": bool(config["token"]),
        "chat_id_configured": bool(config["chat_id"]),
        "chat_id_hint": (
            f"...{config['chat_id'][-4:]}" if config["chat_id"] else ""
        ),
    }


@app.post("/api/chatops/config")
def set_chatops_config(
    body: ChatOpsConfigUpdate,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
):
    _authorize(x_sentrix_live_token, x_confirm_live_change)
    supplied = body.model_fields_set
    updated = containment.update_telegram_config(
        token=body.telegram_bot_token,
        chat_id=body.telegram_chat_id,
        update_token="telegram_bot_token" in supplied,
        update_chat_id="telegram_chat_id" in supplied,
    )
    return updated


@app.post("/api/chatops/action", response_model=None)
def chatops_action(
    body: ChatOpsAction,
    x_sentrix_live_token: Optional[str] = Header(default=None, alias="X-SENTRIX-LIVE-TOKEN"),
    x_confirm_live_change: Optional[str] = Header(default=None, alias="X-CONFIRM-LIVE-CHANGE"),
    x_sentrix_approval_token: Optional[str] = Header(default=None, alias="X-SENTRIX-APPROVAL-TOKEN"),
    x_authenticated_user: Optional[str] = Header(default=None, alias="X-Authenticated-User"),
):
    approver = _authorize_approval(
        x_sentrix_live_token,
        x_confirm_live_change,
        x_sentrix_approval_token,
        x_authenticated_user or "MOBILE_SIMULATOR_OPERATOR",
    )
    return _process_chatops_action(
        body.alert_id,
        body.action,
        body.channel,
        approver,
    )


@app.post("/api/chatops/test", response_model=None)
def trigger_chatops_test(background_tasks: BackgroundTasks):
    if not containment.get_mock_mode():
        raise HTTPException(
            status_code=403,
            detail="The simulated critical-asset alert is available only in MOCK mode.",
        )
    host_ip = "192.168.10.100"
    host = db.lookup_host(host_ip)
    if host is None or host["port_status"] != "SECURE":
        raise HTTPException(
            status_code=409,
            detail="The demo critical asset must be present and secure.",
        )
    alert = AlertWebhook(
        attacker_ip=host_ip,
        target_ip="192.168.10.50",
        signature="SENTRIX ChatOps mobile approval demo",
        severity=4,
        auto_discover=False,
        containment_mode="vlan",
    )
    return _handle_alert(
        alert, None, None, background_tasks=background_tasks
    )


@app.post("/api/simulate/attack")
def simulate_attack(
    background_tasks: BackgroundTasks,
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
    return _handle_alert(
        alert, None, None, background_tasks=background_tasks
    )


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
        pending_approvals=db.get_pending_approvals(),
        last_operation=db.get_last_operation(),
    )
