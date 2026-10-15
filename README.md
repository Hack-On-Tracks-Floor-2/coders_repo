# VOID // SENTINEL — Person 3 Engineering Deliverables
**Persistence Engine, Webhook Alerting, Dashboard Bridge API, & Adversary Simulation CLI**

> **Author / Role:** Person 3 (Senior Backend Engineer)  
> **Team Context:** 3-Person Hackathon Team building **VOID // SENTINEL**, an autonomous cyber-deception and honeytoken defense platform.  
> **Ecosystem:**
> - **Person 1 (Core Backend):** FastAPI middleware running on `http://127.0.0.1:8000`. Detects intrusions, serves deceptive decoys, emits authoritative `SecurityEvent` payloads.
> - **Person 2 (Frontend Command Center):** React dashboard (`void.js`) running on `http://localhost:8080` (or `3000`). Displays real-time telemetry, tripwire canaries, KPI metrics, and manual blacklisting.
> - **Person 3 (Persistence, Alerting, Bridge & Simulation):** Thread-safe SQLite/Postgres persistence, asynchronous Discord/Slack webhooks with rate limiting and deduplication, Dashboard REST Bridge API (`http://127.0.0.1:8001`), and comprehensive attack simulation CLI (`simulate_attack.py`).

---

## 1. Architecture & Deliverables Summary

```
                       ┌──────────────────────────────────────────────┐
                       │          Person 1 Backend (Port 8000)        │
                       │   Detection Engine + Cyber-Deception Traps   │
                       └──────────────────────┬───────────────────────┘
                                              │ Emits SecurityEvent
                     ┌────────────────────────┴────────────────────────┐
                     │                                                 │
          [In-Process Subscriber]                           [Out-of-Process Polling]
       event_store.register_subscriber()                   python integration.py --poll
                     │                                                 │
                     └────────────────────────┬────────────────────────┘
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                                 │     integration.py      │
                                 └────────────┬────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
         ┌─────────────────────────┐                     ┌─────────────────────────┐
         │     persistence/        │                     │   webhook_notifier.py   │
         │      db_adapter.py      │                     │  Discord + Slack Queues │
         │   (SQLite WAL Mode)     │                     │  (Async Worker Thread)  │
         └────────────┬────────────┘                     └────────────┬────────────┘
                      │                                               │
                      │ Reads SQLite                                  ▼ Outbound Alerts
                      ▼                                     Discord / Slack Webhooks
         ┌─────────────────────────┐
         │      bridge_api.py      │ (Port 8001, CORS *)
         │   FastAPI Bridge API    │
         └────────────┬────────────┘
                      │ Transforms to Dashboard Schema
                      ▼
         ┌─────────────────────────┐
         │     Person 2 UI         │
         │   React (void.js)       │ (Port 8080 / 3000)
         └─────────────────────────┘
                      ▲
                      │ Simulated Workload & Canary Hits
         ┌────────────┴────────────┐
         │    simulate_attack.py   │
         │   Adversary Attack CLI  │
         └─────────────────────────┘
```

### Components Built & Hardened:
1. **Persistence (`persistence/db_adapter.py`, `db_adapter.py`):**
   - SQLite with Write-Ahead Logging (`WAL` mode), `busy_timeout=5000`, `synchronous=NORMAL`.
   - Thread-safe query execution via re-entrant mutex (`RLock`).
   - Idempotent writes via `INSERT OR IGNORE INTO security_events`.
   - Guaranteed **safe error suppression**: wraps all insertions in `try/except` and logs with traceback, never crashing Person 1's request path.
   - Auto-executes `database_schema.sql` on startup to ensure table and index readiness.
   - Comprehensive analytical aggregations: `query_events()`, `get_stats()`, `get_event_count()`, `purge_older_than(days)`, and quarantine blacklist management (`add_blacklisted_ip`, `is_ip_blacklisted`, `get_blacklisted_ips`, `remove_blacklisted_ip`).
   - Optional PostgreSQL support enabled automatically when `DATABASE_URL` is set.
2. **Alerting (`webhook_notifier.py`):**
   - Non-blocking background worker queue (`WebhookWorker`) consuming outbound alerts on a daemon thread (zero added latency to request path).
   - Severity filtering on both Discord and Slack (`min_severity`, default `MEDIUM`; deception canaries alert unconditionally).
   - Per-IP + attack-type cooldown deduplication (`ALERT_COOLDOWN_SECONDS=30` default) to prevent channel flooding during bursts.
   - Discord character limit protection: truncates embed fields (`title <= 256`, `value <= 1024`, `name <= 256`, `description <= 4096`, `footer <= 2048`).
   - Two-attempt retry with incremental backoff on transient network failures.
   - Demo-safe mock logging when webhook URLs are omitted.
3. **Integration Entrypoint (`integration.py`):**
   - Clean `wire_up(event_store)` API for direct in-process binding to Person 1.
   - Out-of-process polling mode (`python integration.py --poll`) that continuously polls Person 1's `GET /events`, deduplicates against existing records, and dispatches to persistence and alerts.
4. **Dashboard Bridge API (`bridge_api.py`):**
   - Standalone lightweight FastAPI server running on **port 8001** with `CORS: *`.
   - Real-time schema translator transforming backend `SecurityEvent` rows into Person 2's `void.js` data format.
   - Endpoints: `GET /api/events`, `GET /api/stats`, `POST /api/blacklist`, `GET /api/blacklist`, `DELETE /api/blacklist/{ip}`, `GET /health`.
5. **Adversary Simulation CLI (`simulate_attack.py`, alias `simulate_attacks.py`):**
   - Modular CLI supporting 9 attack modes (`--mode all|baseline|recon|sqli|traversal|cmdi|burst|brute|decoy`).
   - Uses `requests` with standard library `urllib` fallback.
   - Multi-threaded rapid burst (>8 req in <0.5s via `ThreadPoolExecutor`).
   - Safety guard: prevents running against public/remote IPs unless `--i-own-this` is supplied.
   - High-contrast ANSI colored output with automated `NO_COLOR` / non-TTY fallback.
   - Rich summary telemetry table matching client activity with backend `/stats`.

---

## 2. Quickstart & Installation (Windows PowerShell)

### Prerequisites
- Python 3.10+ (Tested on Python 3.12.10)
- Windows PowerShell

### Step 1: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 2: Environment Configuration
Copy the template configuration file:
```powershell
Copy-Item .env.example .env
```
Optionally configure your Discord and Slack webhook URLs inside `.env`:
```ini
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
ALERT_MIN_SEVERITY=MEDIUM
ALERT_COOLDOWN_SECONDS=30
VOID_DB_PATH=void_security_events.db
```
*(If left empty, all webhooks safely output formatted mock dispatches to logs.)*

### Step 3: Run Unit & Integration Tests
```powershell
python -m pytest -v
```
All 29 tests will execute, verifying persistence, WAL mode, deduplication, schema transformation, Discord/Slack formatters, rate-limiting, and error tolerance.

---

## 3. Running the Stack (Step-by-Step)

To run the complete system in separate PowerShell terminal windows:

### Terminal 1: Start Person 1's Backend (Port 8000)
```powershell
# From workspace root, start Person 1's FastAPI backend:
python -m uvicorn app.main:app --app-dir person2\void-backend --host 127.0.0.1 --port 8000

# OR to use the included standalone mock backend for testing:
python mock_person1_server.py
```

### Terminal 2: Start Person 3's Integration Ingestor
```powershell
# Run the out-of-process poller to sync Person 1's events into SQLite & Webhooks:
python integration.py --poll --target http://127.0.0.1:8000 --interval 2.5
```

### Terminal 3: Start Dashboard Bridge API (Port 8001)
```powershell
python -m uvicorn bridge_api:app --host 127.0.0.1 --port 8001
```

### Terminal 4: Launch Person 2's Dashboard (Port 8080)
```powershell
# From workspace root, serve Person 2's React dashboard:
python -m uvicorn void_server:app --app-dir person1 --host 0.0.0.0 --port 8080
# Open http://localhost:8080 in your browser
```

### Terminal 5: Fire Attack Simulation Suite
```powershell
python simulate_attack.py --mode all
```

---

## 4. One-Click Demo Launcher (`demo.ps1`)

For convenience during hackathon judging and live demonstrations, use the automated PowerShell runner:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo.ps1
```

This automated script:
1. Verifies if Person 1's backend is running on `http://127.0.0.1:8000` (auto-launches `mock_person1_server.py` if not).
2. Starts `bridge_api:app` on port 8001.
3. Starts `integration.py --poll` in the background.
4. Executes `python simulate_attack.py --mode all` with ANSI colored terminal telemetry.

---

## 5. Dashboard Bridge API & Schema Mapping Guide for Person 2

Person 2's React dashboard (`void.js`) currently uses client-side mock data. Person 3's Bridge API (`http://127.0.0.1:8001`) transforms all persistent security events into the exact JSON shape expected by Person 2's components.

### REST Endpoints Available on Port 8001:

| Method | Endpoint | Query Parameters | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/events` | `limit=50`, `severity=CRITICAL`, `decoy_only=true`, `client_ip=` | Returns live telemetry events formatted for the feed table. |
| `GET` | `/api/stats` | None | Returns telemetry KPI card numbers and aggregated analytics. |
| `POST` | `/api/blacklist` | Body: `{"ip": "1.2.3.4", "reason": "Attack burst"}` | Quarantines an attacker IP and updates blocklist metrics. |
| `GET` | `/api/blacklist` | None | Returns list of currently quarantined adversary IPs. |
| `DELETE`| `/api/blacklist/{ip}`| None | Removes an IP from quarantine. |
| `GET` | `/health` | None | Health check endpoint. |

### Schema Mapping Reference:

| Backend `SecurityEvent` Field | Dashboard `void.js` Field | Transformation / Mapping Rule |
| :--- | :--- | :--- |
| `event_id` | `id` | Direct mapping (e.g. `6019ed80-f521-4756-b034-a5042339b7a6`). |
| `timestamp` | `timestamp` | ISO-8601 UTC string formatted for `fmtTime()`. |
| `source_ip` | `client_ip` | Direct mapping. |
| `path` | `endpoint` | Direct mapping (e.g. `/.env`, `/admin/backup.sql`). |
| `evidence` | `payload` | List of sanitized evidence strings joined with newline `\n`. |
| `severity` | `severity` | **3-Tier Normalization:**<br>• `CRITICAL` &rarr; `CRITICAL`<br>• `HIGH` &rarr; `HIGH`<br>• `MEDIUM` &rarr; `HIGH`<br>• `LOW` / `NONE` &rarr; `INFO` |
| `attack_type` | `attack_type` | **Human Label Translation:**<br>• `DECOY_ACCESS` &rarr; `"Decoy Route Access"`<br>• `SQL_INJECTION` &rarr; `"SQL Injection Probe"`<br>• `PATH_TRAVERSAL` &rarr; `"Directory Traversal"`<br>• `COMMAND_INJECTION` &rarr; `"RCE Payload Injection"`<br>• `REQUEST_BURST` &rarr; `"Request Burst Anomaly"`<br>• `RECONNAISSANCE` &rarr; `"Admin Panel Recon"`<br>• `SUSPICIOUS_REQUEST` &rarr; `"Suspicious Request Pattern"`<br>• `NONE` &rarr; `"Normal Traffic"` |
| `action` | `action_taken` | **Action Label Translation:**<br>• `SYNTHETIC_RESPONSE` &rarr; `"Decoy Served & IP Logged"`<br>• `REQUEST_TEMPORARY_BLOCK` &rarr; `"Canary Token Fired • IP Blacklisted"`<br>• `RATE_LIMIT` &rarr; `"Throttle Applied • Flagged"`<br>• `REQUIRE_ANALYST_REVIEW` &rarr; `"Rate-Limited • Logged for Review"`<br>• `ALLOW` &rarr; `"Passthrough Logged"`<br>• `LOG_ONLY` &rarr; `"Clean — Telemetry Recorded"` |
| *(Derivation)* | `geo` | Returns `"LOCAL"` for loopback, `"INTERNAL"` for RFC1918, or `"UNKNOWN"`. |

### How Person 2 Connects `void.js` to Real Data:

In `void.js`, replace the `SAMPLE_EVENTS` seed and `setInterval` simulation with a single `fetch`:

```javascript
// Fetch real events from Person 3's Bridge API:
async function loadRealEvents() {
  try {
    const res = await fetch("http://localhost:8001/api/events?limit=50");
    const data = await res.json();
    setEvents(data);
  } catch (err) {
    console.error("Failed to fetch VOID events:", err);
  }
}

// Fetch KPI metrics:
async function loadRealStats() {
  try {
    const res = await fetch("http://localhost:8001/api/stats");
    const stats = await res.json();
    // stats.total_events, stats.decoy_hits, stats.unique_attacker_ips, stats.blocklist_size
  } catch (err) {
    console.error("Failed to fetch stats:", err);
  }
}

// Connect manual quarantine button:
async function handleBlacklist(ip) {
  await fetch("http://localhost:8001/api/blacklist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, reason: "Manual operator quarantine" }),
  });
  setBlacklisted(prev => new Set([...prev, ip]));
}
```

---

## 6. Attacker CLI (`simulate_attack.py`) Reference

Run realistic workloads against any target to demonstrate detection, tripwires, and persistence:

```powershell
python simulate_attack.py [OPTIONS]
```

### CLI Arguments:
- `--target URL`: Backend URL (Default: `http://127.0.0.1:8000`).
- `--mode MODE`:
  - `all` (Default): Runs all 8 phases sequentially followed by telemetry summary.
  - `baseline`: Sends legitimate, non-malicious business traffic (`/api/products`, `/api/profile`).
  - `decoy`: Hits configured honeypots (`/admin/backup.sql`, `/api/v1/internal/users/export`, `/api/debug/config`).
  - `recon`: Scans sensitive file signatures (`/.env`, `/.git/config`, `/wp-admin`, etc.).
  - `sqli`: Tests SQL injection strings (`' OR 1=1 --`, `UNION SELECT`, stacked queries).
  - `traversal`: Tests path traversal payloads (`../../etc/passwd`, Windows backslashes, URL-encoded).
  - `cmdi`: Tests command injection payloads (semicolons, pipes, subshells).
  - `burst`: Fires high-concurrency requests (>8 req in <0.5s) using `ThreadPoolExecutor`.
  - `brute`: Executes credential stuffing against token auth endpoint.
- `--delay SECONDS`: Delay between probes (Default: `0.25`).
- `--burst-count COUNT`: Number of concurrent requests in burst phase (Default: `10`).
- `--quiet`: Suppresses verbose per-request logs and outputs only the final telemetry table.
- `--i-own-this`: Safety override flag required to target external, non-private IP addresses.

---

## 7. Integration Checklists for Teammates

### Checklist for Person 1 (Backend Engineer):
- [x] **Contract Compliance:** Person 3 strictly uses the immutable `SecurityEvent` schema and requires no changes to Person 1's middleware or detector.
- [ ] **Option A (In-Process Integration):**
  In Person 1's startup file (e.g. `app/main.py`), add:
  ```python
  from integration import wire_up
  from app.event_logger import event_store

  # Registers Person 3's SQLite persister and Discord/Slack notifiers
  wire_up(event_store)
  ```
- [ ] **Option B (Zero-Change / Out-of-Process Integration):**
  Person 1 simply keeps running `uvicorn app.main:app --port 8000`. Person 3 runs `python integration.py --poll --interval 1.5`, which automatically consumes `GET /events` and handles all persistence and webhooks without touching Person 1's process.

### Checklist for Person 2 (Frontend Engineer):
- [ ] **Bridge Connection:** Start Person 3's bridge API with `uvicorn bridge_api:app --port 8001`.
- [ ] **Replace Mock Fetching:** Update `void.js` to query `http://localhost:8001/api/events` instead of relying on `SAMPLE_EVENTS`.
- [ ] **Wire Quarantine Button:** Point the blacklist handler in `IntrusionInspector` to `POST http://localhost:8001/api/blacklist`.
- [ ] **Verify CORS:** The bridge already serves `Access-Control-Allow-Origin: *` so no proxy configuration is needed.

---

## 8. Questions for Team

As required by the behavioral contract, no changes were made to the core `SecurityEvent` model. The following observations and enhancement suggestions are noted for team alignment:

1. **Geo-Location Data:**
   - *Observation:* Person 2's dashboard renders a `geo` tag (e.g. `RU-MOW`, `CN-SHA`) for every attack row, but `SecurityEvent` does not currently include a `geo` field.
   - *Current Bridge Solution:* Person 3's `bridge_api.py` tags `127.0.0.1` and loopbacks as `"LOCAL"`, private subnets as `"INTERNAL"`, and others as `"UNKNOWN"`.
   - *Question for Person 1 & 2:* Would you like Person 1 to add an optional `geo: Optional[str] = "UNKNOWN"` field to `SecurityEvent` using an offline MaxMind GeoLite2 lookup, or should Person 3 continue enriching it dynamically in `bridge_api.py`?

2. **Unified Decoy Route Inventory:**
   - *Observation:* Person 2's `void.js` displays a canary status panel tracking hits to `/.env`, `/admin/dump.sql`, `/api/v1/auth/tokens`, `/wp-login.php`, `/.git/config`. However, Person 1's default decoys in `decoys.py` are `/admin/backup.sql`, `/api/v1/internal/users/export`, and `/api/debug/config`.
   - *Current Bridge Solution:* Person 3's `bridge_api.py` captures all hits dynamically via the `decoy_triggered` boolean and endpoint prefix.
   - *Question for Team:* Can Person 1 ensure all 5 canary paths present in `void.js` (`/.env`, `/admin/dump.sql`, `/api/v1/auth/tokens`, `/wp-login.php`, `/.git/config`) are registered in Person 1's `decoy_registry` so all dashboard tripwires illuminate during demo attacks?
