"""Example and backward-compatibility wrapper for VOID Event Persistence.

Maintains backward-compatibility with existing kits:
    from db_adapter_example import SqliteEventPersistence
"""

import logging
from persistence.db_adapter import EventPersistence, SqliteEventPersistence

logger = logging.getLogger("void.db_adapter_example")

if __name__ == "__main__":
    import uuid
    from datetime import datetime, timezone
    from schemas import AttackType, SecurityAction, SecurityEvent, SeverityLevel

    logging.basicConfig(level=logging.INFO)
    persister = SqliteEventPersistence("void_security_events.db")
    sample_event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        path="/admin/backup.sql",
        method="GET",
        attack_type=AttackType.DECOY_ACCESS,
        severity=SeverityLevel.HIGH,
        risk_score=75,
        decoy_triggered=True,
        source_ip="192.168.1.100",
        reason="Decoy canary route hit",
        action=SecurityAction.SYNTHETIC_RESPONSE,
        rule_ids=["DECOY-001"],
        evidence=["Hit database backup decoy route"],
        request_id=str(uuid.uuid4()),
    )
    persister.save_event(sample_event)
    print(f"Total events in store: {persister.get_event_count()}")
    stats = persister.get_stats()
    print("Database statistics:", stats)
