# SENTRIX

SENTRIX is a small FastAPI dashboard for inventory, test-alert handling, and explicitly authorized switch-port containment in an isolated GNS3 lab. SQLite is used for lab state and audit tickets.

## What is and is not supported

- **MOCK** is the default. It runs without a switch, credentials, or live configuration and never opens a Netmiko connection.
- Alert containment performs a read-only IP-to-port hunt (ARP, MAC table, switchport mode, and a bounded CDP/LLDP neighbor hop) before choosing an action. Trunk or multi-MAC endpoint ports are never placed into the quarantine VLAN; the workflow switches to its existing narrowly scoped ACL action and records the trace, exact show commands, per-step timing, and guard warning in the incident ticket. The dashboard also provides a manual trace action.
- **LIVE device types configured in code:** Netmiko `cisco_ios` and `arista_eos` only. Juniper and other device types are rejected.
- Cisco IOS and Arista EOS CLI command generation and handling have unit tests using a fake Netmiko connection. **No physical switch or GNS3 device image was available for this change, so neither vendor/image has been tested against a real CLI.** Treat LIVE as experimental until verified on the exact GNS3 images and versions in your lab.
- GNS3 appliance images vary. Interface show commands, SPAN syntax, Netmiko prompts, and save behavior must be validated on the actual image. If a command or verification does not match, SENTRIX fails closed and does not report containment as successful.
- LIVE IP-to-port hunting is limited to private IPv4 endpoints and switches explicitly present in the local lab allowlist. Neighbor hops are followed only when the discovered private switch IP is also configured; unresolved or mismatched traces block containment. Validate CDP/LLDP and switchport output on the exact lab images before using LIVE.
- The database inventory is seeded with demo records for MOCK. A seed row is **not** authorized for LIVE unless a matching device entry is explicitly added to the ignored local `lab-config.json`.
- MOCK alerts can discover and register simulated unknown hosts. LIVE discovery is read-only and restricted to a target already present in `lab-config.json`; the discovered switch and port must exactly match that allowlist before inventory registration. It does not enroll arbitrary LIVE endpoints.
- VLAN containment bounces the access port (`shutdown` / `no shutdown`) after VLAN reassignment by default. For sensitive ports, set `"port_bounce": false` on that LIVE device; this avoids the link flap but does not avoid the VLAN-change interruption. Surgical ACL mode installs a narrowly scoped extended ACL for the alert's source and target; it refuses to replace an existing inbound ACL and only removes the exact SENTRIX ACL during restore.
- Alerts for `Production File Server`, `Core Server`, and `Database Server` wait for explicit approval and expire after 30 minutes. LIVE approval/rejection additionally requires a separate approval token and an authenticated approver identity injected by a trusted reverse proxy.
- Critical-asset approvals are available through the floating on-screen ChatOps phone and (optionally) a Telegram bot. Configure `TELEGRAM_BOT_TOKEN` and the admin's positive private-chat `TELEGRAM_CHAT_ID` in the process environment, or update them for the current process with `POST /api/chatops/config`; the API never returns the bot token and runtime API changes are kept in memory, not written in plaintext to SQLite. With both values configured, pending alerts are sent asynchronously with VLAN, surgical ACL, and reject buttons. The built-in `getUpdates` poller accepts callback actions only when both the chat and clicking user's ID match the configured private-chat ID. Avoid running a webhook consumer for the same bot while polling.
- Use **Send demo critical alert** in the floating ChatOps drawer (or `POST /api/chatops/test`) to create a MOCK-only critical approval. `POST /api/chatops/action` accepts the same three action names for the on-screen simulator. In LIVE, simulator actions still require live-change authorization and the separate approval token; Telegram approvals require the configured administrator chat and remain subject to the normal host allowlist, IP-to-port re-trace, and Smart Trunk Guard. Approval channel, selected action, response-plus-execution time, and containment CLI are saved on tickets and in the operation audit log.
- SENTRIX serializes active operations per switch through SQLite, in addition to per-host claims. This protects cooperating SENTRIX instances using the same local database; it cannot lock out manual switch CLI changes or coordinate instances using different database files.
- The LIVE dashboard's **Check switch state** action performs read-only reconciliation against the allowlisted switch. It reports VLAN, SENTRIX description, ACL, and configured SPAN drift where a database baseline exists. Secure-state interface descriptions are not stored, so those cannot be checked; reconciliation is a point-in-time check and cannot prevent later manual changes.

## Run locally in MOCK

Requirements: Python 3.10+.

```powershell
cd C:\path\to\sentrix-core
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SENTRIX_MODE = "MOCK"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. MOCK is the default if `SENTRIX_MODE` is omitted. Use **Start guided demo** to step through simulated unknown-host discovery, a critical-server alert, human approval, and the final ticket/CLI trace. Approval is an explicit action on the Production File Server inventory card. **Restart** resets only the browser's walkthrough progress; it does not clear tickets, restore ports, or reset the database. The topology panel summarizes inventory and stored status, not live network telemetry. `/api/simulate/attack` is disabled in LIVE.

The local database defaults to `sentrix.db` beside `database.py`. Set `SENTRIX_DB_PATH` to an absolute path or a path relative to the project directory to use another SQLite file. The database, WAL files, and local configuration are ignored by Git.

## Publish a public MOCK demo on Render

The repository includes a Render Blueprint at `render.yaml`. Open the [Render deployment page](https://render.com/deploy?repo=https://github.com/AHMED8781/sentrix-core), sign in, review the Blueprint, and choose **Apply**. Render will build the app and provide a public `onrender.com` URL when deployment is ready.

This Blueprint pins `SENTRIX_MODE=MOCK`; do not change it to LIVE for a public service. The demo has no user authentication, so anyone with its URL can view the inventory and create simulated alerts. Its SQLite database is stored on the ephemeral filesystem and may be reset when Render restarts or redeploys the free service. Never add switch credentials, live-change tokens, approval tokens, or a real `lab-config.json` to this public deployment.
The public MOCK demo also exposes runtime ChatOps configuration without authentication. Do not configure a real Telegram bot or send sensitive operational details through a publicly reachable instance.

## Publish a public MOCK demo on Vercel Hobby

The application can be imported from GitHub as a FastAPI project on Vercel Hobby for personal, non-commercial demos. In Vercel, create a project from `AHMED8781/sentrix-core`, keep the repository root as the project root, and deploy with the Hobby plan. Vercel detects `main.py` and `requirements.txt`; `vercel.json` excludes local databases, secrets, and tests from the function bundle.

The Vercel deployment is deliberately MOCK-only: `LIVE` mode fails startup there, and the Telegram long-poll worker is disabled because serverless functions do not guarantee a persistent background process. SQLite uses `/tmp/sentrix.db` by default, which is temporary and can reset when the function restarts or scales to another instance. The in-dashboard ChatOps simulator remains available, but Telegram polling and durable ticket history are not guaranteed. Do not add real bot credentials or live-device secrets. Vercel Hobby has usage limits and is for personal, non-commercial use; check the current plan limits before sharing the demo widely.

## Prepare an isolated GNS3 lab

1. Use a disposable GNS3 project and switch images with console access and a recoverable startup configuration. Snapshot the project and confirm out-of-band recovery before enabling LIVE.
2. Create the required isolation VLAN and attach it only to the intended lab topology. If using SPAN, select a dedicated session number that is not already configured and a dedicated destination interface. SENTRIX does not choose or replace an existing session.
3. Make a private copy of `lab-config.example.json` named `lab-config.json`. The example is deliberately empty. Add only the exact host and switch mapping to be operated:

   ```json
   {
     "max_span_sessions_per_switch": 1,
     "devices": [
       {
         "host_ip": "192.168.10.50",
         "switch_ip": "192.168.1.2",
         "vendor": "cisco_ios",
         "port_interface": "Gi0/1",
         "isolation_vlan": 999,
         "restore_vlan": 10,
         "port": 22,
         "timeout": 8,
         "span_session": 12,
         "span_destination": "Gi0/24",
         "port_bounce": false
       }
     ]
   }
   ```

   Replace every example value. `switch_ip`, `vendor`, and `port_interface` must exactly match that host's inventory record. Update the local SQLite inventory record to the actual GNS3 host/switch mapping before LIVE; the demo inventory is not a real lab inventory. The switch IP and host IP must be private or loopback addresses. VLANs, ports, interface names, and the optional SPAN session/destination are validated before use. `max_span_sessions_per_switch` is optional and defaults to 2; lower it to match the actual switch image's supported capacity (for example `1`). SENTRIX also checks currently active sessions before configuring one and fails closed if the response is empty or cannot be parsed. The configured cap is a safety limit, not a discovery of hardware capability.

   Omit both `span_session` and `span_destination` to disable SPAN. If configured, SENTRIX checks that the session number is absent before creating it and checks its exact source/destination before removing it on restore.
4. Configure credentials and a separate, random live-change token in the process environment. Do not put credentials in the JSON file, source code, or Git:

   ```powershell
   $env:SENTRIX_LAB_USERNAME = "your-lab-account"
   $env:SENTRIX_LAB_PASSWORD = "<your local lab password>"
   $env:SENTRIX_LIVE_CHANGE_TOKEN = "<a random value of at least 32 characters>"
   $env:SENTRIX_APPROVAL_TOKEN = "<a different random value of at least 32 characters>"
   $env:SENTRIX_LAB_CONFIG = "lab-config.json"
   ```

   The `.env.example` is a reference only; SENTRIX does not load `.env` files.
5. Before LIVE, verify on the switch that the target interface is explicitly configured as an access port with the `restore_vlan`, that its current VLAN agrees with the database, and that the optional SPAN session is unused. Interface state that cannot be positively identified is rejected.
6. Bind the app to `127.0.0.1` and select LIVE at process start:

   ```powershell
   $env:SENTRIX_MODE = "LIVE"
   python -m uvicorn main:app --host 127.0.0.1 --port 8000
   ```

   Startup fails unless the local allowlist, credentials, and both tokens are present and valid. There is no HTTP mode-toggle endpoint. Each LIVE alert, discovery, restore, or reconciliation request must include `X-SENTRIX-LIVE-TOKEN` and `X-CONFIRM-LIVE-CHANGE: I_CONFIRM_GNS3_LAB_CHANGE`. LIVE approval/rejection also needs `X-SENTRIX-APPROVAL-TOKEN` and `X-Authenticated-User`. The latter is trustworthy only when an authenticated reverse proxy strips any client-supplied copy and sets it from the authenticated identity. Bind SENTRIX to loopback behind that proxy; do not expose the app directly to an untrusted network.

## Carefully exercise isolation and restore

1. First run the complete workflow in MOCK and confirm its ticket and return-to-saved-VLAN behavior.
2. In the GNS3 snapshot, select one disposable endpoint port and configure exactly one matching host in `lab-config.json`. Check the switch's running configuration and startup configuration before proceeding.
3. Start LIVE bound to loopback. Send one alert for that exact host to `POST /api/webhook/alert` with a valid test alert payload, the token header, and the explicit confirmation header. Example:

   ```powershell
   $headers = @{
     "X-SENTRIX-LIVE-TOKEN" = $env:SENTRIX_LIVE_CHANGE_TOKEN
     "X-CONFIRM-LIVE-CHANGE" = "I_CONFIRM_GNS3_LAB_CHANGE"
   }
   $body = @{
     attacker_ip = "192.168.10.50"
     target_ip = "192.168.10.100"
     signature = "Authorized GNS3 restore test"
     severity = 2
   } | ConvertTo-Json
   Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/webhook/alert -Headers $headers -ContentType "application/json" -Body $body
   ```

4. Verify the switch VLAN, SENTRIX description, optional SPAN session, saved configuration, dashboard status, and audit ticket directly. If any verification fails, stop and inspect the switch; the dashboard reports an error and may mark the host `ERROR_REQUIRES_REVIEW`.
5. Use **Restore** in the dashboard and confirm the target. Restore is permitted only when the interface still has SENTRIX's isolation description/VLAN and the optional SPAN session still exactly matches the configured source/destination. The original access VLAN and description are saved before isolation and used for restore; a fixed production VLAN is not assumed.
6. Verify the original interface configuration and SPAN state on the switch. Restore in the dashboard is only marked successful after device verification and SQLite finalization.
7. To return to MOCK, stop Uvicorn, set `$env:SENTRIX_MODE = "MOCK"`, and restart it. No endpoint can switch modes while running.

## API and operations

- `GET /api/state` returns metrics, inventory, ticket history, and the last operation.
- `POST /api/webhook/alert` validates and handles an inventory host; MOCK can auto-discover unknown private hosts, while LIVE discovery remains allowlist-bound. LIVE requires both confirmation headers.
- `POST /api/discover/{ip}` discovers and registers a host; in LIVE this is restricted to exact allowlist entries and requires both confirmation headers.
- `POST /api/approvals/{ip}/approve` and `/reject` resolve a critical-asset approval; approval immediately continues the saved alert workflow.
- `POST /api/ports/{ip}/restore` restores the saved state; LIVE requires both confirmation headers.
- `GET /api/reconcile/{ip}` performs a read-only LIVE state comparison and reports drift without attempting repair.
- `POST /api/simulate/attack` creates a harmless demo alert only in MOCK.
- `GET /api/health` reports the startup mode.

Concurrent operations claim the host and a per-switch operation lock transactionally in SQLite; only one request can change a given switch at a time. Locks are released atomically with operation finalization/failure and stale claims are cleared on restart after interrupted operations are marked `ERROR_REQUIRES_REVIEW`. Tickets are created in the same transaction as the verified inventory update and receive database-serialized IDs. Logs include operation, result, duration, and step outcomes, but not credentials.

Ticket history includes the generated CLI text. LIVE discovery is not a substitute for provisioning the exact host/switch/port mapping in the local allowlist, and neither ACL nor VLAN containment has been verified against production equipment. Read-only reconciliation can detect some manual state drift but is not continuous monitoring and cannot close the race between a check and a subsequent network operation.

The dashboard reports average **operation execution time**; this is not MTTR. SQLite remains the local persistence layer.

## Tests

```powershell
python -m pytest -q
```

Tests use temporary SQLite databases and fake Netmiko connections. They do not connect to a switch. Real GNS3 image compatibility remains a manual lab validation step as described above.
