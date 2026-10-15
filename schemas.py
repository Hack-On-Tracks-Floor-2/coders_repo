"""Standalone Pydantic schemas and enums for Person 3.

No dependencies on internal backend middleware or detection engine.
Requires only: pydantic>=2.0.0
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid.uuid4())


def current_utc_timestamp() -> str:
    """Return current timestamp in ISO-8601 UTC format."""
    return datetime.now(timezone.utc).isoformat()


class SeverityLevel(str, Enum):
    """Normalized security severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(str, Enum):
    """Attack classification categories."""
    DECOY_ACCESS = "DECOY_ACCESS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    REQUEST_BURST = "REQUEST_BURST"
    RECONNAISSANCE = "RECONNAISSANCE"
    SUSPICIOUS_REQUEST = "SUSPICIOUS_REQUEST"
    NONE = "NONE"


class SecurityAction(str, Enum):
    """Action applied to intercepted traffic."""
    SYNTHETIC_RESPONSE = "SYNTHETIC_RESPONSE"
    ALLOW = "ALLOW"
    LOG_ONLY = "LOG_ONLY"
    RATE_LIMIT = "RATE_LIMIT"
    REQUEST_TEMPORARY_BLOCK = "REQUEST_TEMPORARY_BLOCK"
    REQUIRE_ANALYST_REVIEW = "REQUIRE_ANALYST_REVIEW"


class SecurityEvent(BaseModel):
    """The central unified security event emitted by VOID backend.
    
    Person 3: This is the exact object passed to your database persister
    and Discord/Slack notification callbacks.
    """
    event_id: str = Field(
        default_factory=generate_uuid,
        description="Globally unique identifier for the event (UUID v4)",
    )
    timestamp: str = Field(
        default_factory=current_utc_timestamp,
        description="ISO-8601 UTC timestamp of occurrence (e.g. 2026-10-15T06:13:11.431185+00:00)",
    )
    path: str = Field(..., description="Target URL path requested by client")
    method: str = Field(..., description="HTTP method used (GET, POST, etc.)")
    attack_type: AttackType = Field(..., description="Primary attack category")
    severity: SeverityLevel = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic threat score bounded between 0 and 100")
    decoy_triggered: bool = Field(..., description="Whether request struck a deception trap")
    source_ip: str = Field(..., description="Client source IP address")
    reason: str = Field(..., description="Human-readable explanation of why event was triggered")
    action: SecurityAction = Field(..., description="Action taken on the intercepted request")
    rule_ids: List[str] = Field(default_factory=list, description="IDs of rules triggered, e.g. ['DECOY-001']")
    evidence: List[str] = Field(default_factory=list, description="Sanitized evidence strings")
    request_id: str = Field(default_factory=generate_uuid, description="Correlation ID matching X-Request-ID")
    is_simulated: bool = Field(default=False, description="Flag indicating whether event originated from synthetic demo data")
    ground_truth_label: Optional[str] = Field(default=None, description="Known label of synthetic scenario (ground truth)")
    scenario_id: Optional[str] = Field(default=None, description="Synthetic scenario identifier")
    session_id: Optional[str] = Field(default=None, description="Correlated session identifier")
    user_agent: Optional[str] = Field(default=None, description="Observed client User-Agent")
    http_status: Optional[int] = Field(default=None, description="Observed HTTP status response code")
    response_time_ms: Optional[float] = Field(default=None, description="Observed response latency in milliseconds")

