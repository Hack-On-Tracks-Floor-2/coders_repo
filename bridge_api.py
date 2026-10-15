"""VOID // SENTINEL — Dashboard Bridge API (Port 8001).

Translates VOID's authoritative SecurityEvent database schema into the exact UI data shape
expected by the React Command Center Dashboard (void.js).

Features:
- CORS enabled for all origins (*)
- Enhanced multi-dimensional data source filtering ('demo' / 'live' / 'all')
- Search, sorting, pagination, and time range filtering
- Single event inspection endpoint (/api/events/{event_id})
- Correlated incident heuristic endpoint (/api/events/{event_id}/related)
- Chart analytics aggregations (/api/analytics)
- Safe demo dataset import, reset, and status endpoints (/api/dataset/*)
- Filtered dataset export to JSON or CSV (/api/export)
- Blacklist quarantine management endpoints (/api/blacklist)
"""

import csv
import io
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from persistence.db_adapter import EventPersistence

logger = logging.getLogger("void.bridge_api")

app = FastAPI(
    title="VOID // SENTINEL — Dashboard Bridge API",
    description="Bridge connecting persistent security events with the Cyber-Deception Command Center dashboard.",
    version="2.0.0",
)

# Enable CORS for all dashboard origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared persistence instance
db = EventPersistence()

# Mapping specifications
ATTACK_TYPE_LABELS = {
    "DECOY_ACCESS": "Decoy Route Access",
    "SQL_INJECTION": "SQL Injection Probe",
    "PATH_TRAVERSAL": "Directory Traversal",
    "COMMAND_INJECTION": "RCE Payload Injection",
    "REQUEST_BURST": "Request Burst Anomaly",
    "RECONNAISSANCE": "Admin Panel Recon",
    "SUSPICIOUS_REQUEST": "Suspicious Request Pattern",
    "NONE": "Normal Traffic",
}

ACTION_LABELS = {
    "SYNTHETIC_RESPONSE": "Decoy Served & IP Logged",
    "REQUEST_TEMPORARY_BLOCK": "Canary Token Fired • IP Blacklisted",
    "RATE_LIMIT": "Throttle Applied • Flagged",
    "REQUIRE_ANALYST_REVIEW": "Rate-Limited • Logged for Review",
    "ALLOW": "Passthrough Logged",
    "LOG_ONLY": "Clean — Telemetry Recorded",
}


def map_severity_to_dashboard(sev: str) -> str:
    """Map VOID severities to the dashboard's 3-tier severity schema: CRITICAL, HIGH, INFO."""
    normalized = str(sev).upper()
    if normalized == "CRITICAL":
        return "CRITICAL"
    if normalized in ("HIGH", "MEDIUM"):
        return "HIGH"
    # LOW, NONE or unknown map to INFO
    return "INFO"


def map_event_to_dashboard(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map stored SecurityEvent row into the React Dashboard schema with provenance."""
    # Build payload string from evidence or request details
    evidence = raw.get("evidence", [])
    if isinstance(evidence, list) and len(evidence) > 0:
        payload_str = "\n".join(str(e) for e in evidence)
    else:
        payload_str = f"{raw.get('method', 'GET')} {raw.get('path', '/')}\nReason: {raw.get('reason', '')}"

    raw_attack = str(raw.get("attack_type", "NONE"))
    attack_label = ATTACK_TYPE_LABELS.get(raw_attack, raw_attack.replace("_", " ").title())

    raw_action = str(raw.get("action", "ALLOW"))
    action_label = ACTION_LABELS.get(raw_action, raw_action.replace("_", " ").title())

    # Detect local/private IP for basic geo/network annotation (no fabricated location claims)
    client_ip = str(raw.get("source_ip", "UNKNOWN"))
    geo = "UNKNOWN"
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        geo = "LOCAL"
    elif client_ip.startswith(("10.", "192.168.", "172.16.")):
        geo = "INTERNAL"
    elif client_ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        geo = "RFC-5737"

    is_sim = bool(raw.get("is_simulated", False))

    return {
        "id": raw.get("event_id", ""),
        "timestamp": raw.get("timestamp", ""),
        "client_ip": client_ip,
        "attack_type": attack_label,
        "raw_attack_type": raw_attack,
        "endpoint": raw.get("path", "/"),
        "method": raw.get("method", "GET"),
        "payload": payload_str,
        "severity": map_severity_to_dashboard(str(raw.get("severity", "LOW"))),
        "raw_severity": str(raw.get("severity", "LOW")).upper(),
        "action_taken": action_label,
        "raw_action": raw_action,
        "geo": geo,
        "decoy_triggered": bool(raw.get("decoy_triggered", False)),
        "risk_score": int(raw.get("risk_score", 0)),
        "reason": raw.get("reason", ""),
        "rule_ids": raw.get("rule_ids", []),
        "evidence": raw.get("evidence", []),
        "request_id": raw.get("request_id", ""),
        "is_simulated": is_sim,
        "origin": "DEMO" if is_sim else "LIVE",
        "ground_truth_label": raw.get("ground_truth_label"),
        "scenario_id": raw.get("scenario_id"),
        "session_id": raw.get("session_id"),
        "user_agent": raw.get("user_agent"),
        "http_status": raw.get("http_status"),
        "response_time_ms": raw.get("response_time_ms"),
    }


def parse_data_source_flag(data_source: Optional[str]) -> Optional[bool]:
    """Parse data_source query param into is_simulated boolean flag."""
    if not data_source:
        return None
    val = data_source.strip().lower()
    if val in ("demo", "synthetic", "simulated"):
        return True
    if val in ("live", "production", "real"):
        return False
    return None


class BlacklistRequest(BaseModel):
    ip: str = Field(..., description="Adversary IP to blacklist")
    reason: Optional[str] = Field("Manually blacklisted via Dashboard Bridge", description="Reason for ban")


class DatasetImportRequest(BaseModel):
    reset: bool = Field(False, description="Reset previous demo events before importing")
    file_path: Optional[str] = Field(None, description="Optional custom dataset JSON file path")


@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for Dashboard Bridge."""
    return {
        "status": "healthy",
        "service": "VOID Dashboard Bridge",
        "port": 8001,
        "database_connected": True,
        "event_count": db.get_event_count(),
    }


@app.get("/api/events", tags=["Dashboard"])
async def get_dashboard_events(
    limit: int = Query(50, ge=1, le=1000, description="Max events to return"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, INFO"),
    decoy_only: Optional[bool] = Query(None, description="Filter only decoy canary events"),
    client_ip: Optional[str] = Query(None, description="Filter by client IP"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    data_source: Optional[str] = Query("all", description="Data view: 'demo', 'live', or 'all'"),
    attack_type: Optional[str] = Query(None, description="Filter by raw attack type (e.g. SQL_INJECTION)"),
    search: Optional[str] = Query(None, description="Search keyword in IP, path, reason, ground truth"),
    start_time: Optional[str] = Query(None, description="ISO-8601 start timestamp filter"),
    end_time: Optional[str] = Query(None, description="ISO-8601 end timestamp filter"),
    sort_by: str = Query("timestamp", description="Sort by timestamp, risk_score, severity, source_ip"),
    order: str = Query("desc", description="Sort direction: 'desc' or 'asc'"),
) -> List[Dict[str, Any]]:
    """Retrieve security events formatted for the React dashboard feed."""
    db_severity = None
    if severity:
        sev_upper = severity.upper()
        if sev_upper == "CRITICAL":
            db_severity = "CRITICAL"
        elif sev_upper in ("INFO", "CLEAN"):
            db_severity = "LOW"

    is_simulated = parse_data_source_flag(data_source)

    raw_events = db.query_events(
        limit=limit,
        severity=db_severity,
        decoy_only=decoy_only,
        source_ip=client_ip,
        offset=offset,
        is_simulated=is_simulated,
        attack_type=attack_type,
        search=search,
        start_time=start_time,
        end_time=end_time,
        sort_by=sort_by,
        order=order,
    )

    transformed = [map_event_to_dashboard(ev) for ev in raw_events]

    # Post-filter if dashboard requested HIGH (which covers both HIGH and MEDIUM)
    if severity and severity.upper() in ("HIGH", "WARNING"):
        transformed = [ev for ev in transformed if ev["severity"] == "HIGH"]

    return transformed


@app.get("/api/events/{event_id}", tags=["Dashboard"])
async def get_single_event(event_id: str) -> Dict[str, Any]:
    """Retrieve a single security event by event_id with full forensics."""
    raw = db.get_event_by_id(event_id)
    if not raw:
        raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found")
    return map_event_to_dashboard(raw)


@app.get("/api/events/{event_id}/related", tags=["Investigation"])
async def get_related_events(
    event_id: str,
    limit: int = Query(10, ge=1, le=50, description="Max related events to return"),
) -> Dict[str, Any]:
    """Correlate related events from the same source IP or session with heuristic campaign score."""
    result = db.get_related_events(event_id=event_id, limit=limit)
    if not result.get("target_event_id"):
        raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found")

    mapped_related = [map_event_to_dashboard(ev) for ev in result.get("related_events", [])]
    result["related_events"] = mapped_related
    return result


@app.get("/api/stats", tags=["Dashboard"])
async def get_dashboard_stats(
    data_source: Optional[str] = Query("all", description="Data view: 'demo', 'live', or 'all'"),
) -> Dict[str, Any]:
    """Return KPI metrics dynamically matching the dashboard cards and active data view."""
    is_simulated = parse_data_source_flag(data_source)
    stats = db.get_stats(is_simulated=is_simulated)
    return {
        "total_events": stats["total"],
        "total": stats["total"],
        "decoy_hits": stats["decoy_hits"],
        "unique_attacker_ips": stats["unique_ips"],
        "blocklist_size": stats["blocklist_size"],
        "aggregate_risk_score": stats["aggregate_system_risk"],
        "avg_risk_score": stats.get("avg_risk_score", 0.0),
        "max_risk_score": stats.get("max_risk_score", 0),
        "suspicious_count": stats.get("suspicious_count", 0),
        "critical_high_count": stats.get("critical_high_count", 0),
        "analyst_review_count": stats.get("analyst_review_count", 0),
        "simulated_count": stats.get("simulated_count", 0),
        "live_count": stats.get("live_count", 0),
        "severity_counts": stats["by_severity"],
        "attack_type_counts": stats["by_attack_type"],
        "top_ips": stats["top_ips"],
        "data_source": data_source or "all",
    }


@app.get("/api/analytics", tags=["Dashboard"])
async def get_dashboard_analytics(
    data_source: Optional[str] = Query("all", description="Data view: 'demo', 'live', or 'all'"),
) -> Dict[str, Any]:
    """Return visual analytics data for charts (time series, risk bins, top vectors, decoys)."""
    is_simulated = parse_data_source_flag(data_source)
    analytics = db.get_analytics(is_simulated=is_simulated)
    analytics["data_source"] = data_source or "all"
    return analytics


@app.post("/api/dataset/import", tags=["Demo Management"])
async def import_demo_dataset(req: Optional[DatasetImportRequest] = None) -> Dict[str, Any]:
    """Load or reload the synthetic demo dataset safely into the persistent store."""
    reset = req.reset if req else False
    custom_path = req.file_path if req else None

    # Locate sample_security_events.json
    candidates = []
    if custom_path:
        candidates.append(Path(custom_path))
    candidates.extend([
        Path("data/sample_security_events.json"),
        Path(__file__).parent / "data" / "sample_security_events.json",
        Path(__file__).parent.parent / "data" / "sample_security_events.json",
    ])

    target_file = None
    for p in candidates:
        if p.exists() and p.is_file():
            target_file = p.resolve()
            break

    if not target_file:
        raise HTTPException(
            status_code=404,
            detail="Synthetic dataset file 'data/sample_security_events.json' not found. Run 'python scripts/generate_sample_dataset.py' first.",
        )

    # Use importer logic
    try:
        from scripts.import_dataset import import_dataset
        summary = import_dataset(json_path=target_file, db=db, reset_demo=reset, dry_run=False)
        return {
            "status": "success",
            "message": f"Successfully imported {summary['imported']} demo events ({summary['skipped']} skipped)",
            "details": summary,
        }
    except Exception as e:
        logger.error("Failed to import dataset: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Dataset import error: {str(e)}")


@app.post("/api/dataset/reset", tags=["Demo Management"])
async def reset_demo_dataset() -> Dict[str, Any]:
    """Safely delete all synthetic demo events from storage, preserving live events."""
    deleted_count = db.delete_simulated_events()
    stats = db.get_stats()
    return {
        "status": "success",
        "deleted_count": deleted_count,
        "message": f"Purged {deleted_count} synthetic demo events. Live events preserved.",
        "remaining_events": stats["total"],
        "remaining_live": stats.get("live_count", 0),
    }


@app.get("/api/dataset/status", tags=["Demo Management"])
async def get_dataset_status() -> Dict[str, Any]:
    """Return status of synthetic dataset files and database record breakdown."""
    candidates = [
        Path("data/sample_security_events.json"),
        Path(__file__).parent / "data" / "sample_security_events.json",
    ]
    file_exists = any(p.exists() for p in candidates)
    stats = db.get_stats()
    return {
        "dataset_file_exists": file_exists,
        "simulated_events_in_db": stats.get("simulated_count", 0),
        "live_events_in_db": stats.get("live_count", 0),
        "total_events_in_db": stats.get("total", 0),
    }


@app.get("/api/export", tags=["Dashboard"])
async def export_events(
    format: str = Query("json", pattern="^(json|csv)$", description="Export format: json or csv"),
    data_source: Optional[str] = Query("demo", description="Data view: 'demo', 'live', or 'all'"),
    severity: Optional[str] = Query(None, description="Optional severity filter"),
    attack_type: Optional[str] = Query(None, description="Optional attack type filter"),
    limit: int = Query(1000, ge=1, le=5000, description="Max records to export"),
) -> Response:
    """Export filtered security events to downloadable JSON or CSV file."""
    is_simulated = parse_data_source_flag(data_source)
    raw_events = db.query_events(
        limit=limit,
        severity=severity,
        attack_type=attack_type,
        is_simulated=is_simulated,
        offset=0,
    )
    mapped = [map_event_to_dashboard(e) for e in raw_events]

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        headers = [
            "id", "timestamp", "client_ip", "method", "endpoint",
            "attack_type", "severity", "risk_score", "action_taken",
            "decoy_triggered", "origin", "ground_truth_label", "reason",
        ]
        writer.writerow(headers)
        for e in mapped:
            writer.writerow([
                e["id"], e["timestamp"], e["client_ip"], e["method"], e["endpoint"],
                e["attack_type"], e["severity"], e["risk_score"], e["action_taken"],
                1 if e["decoy_triggered"] else 0, e["origin"],
                e.get("ground_truth_label") or "", e.get("reason", ""),
            ])
        content = output.getvalue()
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=void_events_{data_source}.csv"},
        )

    # JSON export
    content = json.dumps(mapped, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=void_events_{data_source}.json"},
    )


@app.post("/api/blacklist", tags=["Defensive Control"])
async def blacklist_ip(req: BlacklistRequest) -> Dict[str, Any]:
    """Add an adversary IP to the quarantine blacklist."""
    clean_ip = req.ip.strip()
    if not clean_ip:
        raise HTTPException(status_code=400, detail="IP address cannot be empty")

    success = db.add_blacklisted_ip(clean_ip, reason=req.reason or "")
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add IP to blacklist")

    stats = db.get_stats()
    return {
        "status": "blacklisted",
        "ip": clean_ip,
        "blocklist_size": stats["blocklist_size"],
        "message": f"IP {clean_ip} quarantined successfully",
    }


@app.get("/api/blacklist", tags=["Defensive Control"])
async def list_blacklisted_ips() -> List[Dict[str, Any]]:
    """List all currently quarantined adversary IPs."""
    return db.get_blacklisted_ips()


@app.delete("/api/blacklist/{ip}", tags=["Defensive Control"])
async def remove_blacklisted_ip(ip: str) -> Dict[str, Any]:
    """Remove an IP from the quarantine blacklist."""
    removed = db.remove_blacklisted_ip(ip)
    stats = db.get_stats()
    return {
        "status": "removed" if removed else "not_found",
        "ip": ip,
        "blocklist_size": stats["blocklist_size"],
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("BRIDGE_PORT", 8001))
    print(f"\n[VOID // SENTINEL] Dashboard Bridge API running on http://127.0.0.1:{port}")
    uvicorn.run("bridge_api:app", host="127.0.0.1", port=port, reload=False)
