"""Lightweight mock server for Person 1 (port 8000) for testing and simulation demos."""

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="VOID Person 1 Mock Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

stats_data = {
    "total_events": 24,
    "severity_counts": {"CRITICAL": 6, "HIGH": 12, "MEDIUM": 4, "LOW": 2},
    "attack_type_counts": {
        "DECOY_ACCESS": 8,
        "SQL_INJECTION": 4,
        "PATH_TRAVERSAL": 4,
        "COMMAND_INJECTION": 2,
        "REQUEST_BURST": 2,
        "RECONNAISSANCE": 4,
    },
    "decoy_interactions": 8,
    "unique_ips": 3,
    "aggregate_system_risk": 82,
    "highest_risk_ip": "127.0.0.1",
    "active_recommendations_count": 3,
}

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0", "components": {"detector": "active", "decoys": "active"}}

@app.get("/api/products")
async def products(request: Request):
    q = request.query_params.get("q")
    category = request.query_params.get("category")
    burst = request.query_params.get("burst")
    if burst and int(burst) > 7:
        return Response(content="RATE_LIMIT", status_code=429)
    return [
        {"id": 1, "name": "VOID Sentinel Key", "price": 349.99},
        {"id": 2, "name": "Adaptive Perimeter Shield", "price": 1299.00},
    ]

@app.get("/api/profile")
async def profile():
    return {"id": "USR-PROD-7710", "username": "alex_secops", "role": "Senior Defense Analyst"}

# Decoy endpoints
@app.get("/admin/backup.sql")
@app.get("/api/v1/internal/users/export")
@app.get("/api/debug/config")
@app.get("/.env")
@app.get("/.git/config")
@app.get("/wp-admin")
@app.get("/wp-login.php")
@app.get("/phpinfo.php")
async def decoy_routes(request: Request):
    headers = {
        "x-void-interception": "DECOY_TRIGGERED",
        "x-synthetic-artifact": "SYNTHETIC_CANARY_v2",
    }
    return JSONResponse(
        content={"status": "synthetic_response", "trap_tripped": True, "path": request.url.path},
        headers=headers,
    )

@app.post("/api/v1/auth/tokens")
async def auth_login():
    headers = {
        "x-void-interception": "DECOY_TRIGGERED",
        "x-synthetic-artifact": "TOKEN_HONEYPOT",
    }
    return JSONResponse(
        content={"error": "Invalid credentials", "flagged": True},
        headers=headers,
    )

@app.get("/stats")
async def stats():
    return stats_data

@app.get("/events")
async def events():
    return [
        {
            "event_id": "6019ed80-f521-4756-b034-a5042339b7a6",
            "timestamp": "2026-10-15T06:13:11.431185+00:00",
            "path": "/admin/backup.sql",
            "method": "GET",
            "attack_type": "DECOY_ACCESS",
            "severity": "HIGH",
            "risk_score": 75,
            "decoy_triggered": True,
            "source_ip": "127.0.0.1",
            "reason": "Request matched configured decoy route",
            "action": "SYNTHETIC_RESPONSE",
            "rule_ids": ["DECOY-001"],
            "evidence": ["Requested /admin/backup.sql"],
            "request_id": "88556e99-b5df-442b-b60f-4901497423b1",
        }
    ]

if __name__ == "__main__":
    uvicorn.run("mock_person1_server:app", host="127.0.0.1", port=8000, log_level="warning")
