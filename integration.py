"""VOID // SENTINEL — Integration Entrypoint (Person 3).

Provides dual-mode integration:
1. In-process: `wire_up(event_store)` binds persistence and webhooks directly to Person 1's event store.
2. Out-of-process: `python integration.py --poll` continuously polls Person 1's REST API (/events),
   deduplicates events, and pipes them into SQLite and Discord/Slack notifiers.
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, Optional, Set, Tuple
import urllib.error
import urllib.request

from persistence.db_adapter import EventPersistence
from webhook_notifier import WebhookManager

# Fallback schema imports
try:
    from app.schemas import AttackType, SecurityAction, SecurityEvent, SeverityLevel
except ImportError:
    from schemas import AttackType, SecurityAction, SecurityEvent, SeverityLevel

logger = logging.getLogger("void.integration")


def wire_up(
    event_store: Any = None,
    db: Optional[EventPersistence] = None,
    webhook_mgr: Optional[WebhookManager] = None,
) -> Tuple[EventPersistence, WebhookManager, Callable[[SecurityEvent], None]]:
    """Wire up database persistence and alert notifiers to an event store.

    Args:
        event_store: Instance of BaseEventStore (defaults to app.event_logger.event_store if available).
        db: Optional existing EventPersistence instance.
        webhook_mgr: Optional existing WebhookManager instance.

    Returns:
        Tuple of (persistence_instance, webhook_manager_instance, callback_function).
    """
    if db is None:
        db = EventPersistence()

    if webhook_mgr is None:
        webhook_mgr = WebhookManager()

    def on_security_event(event: SecurityEvent) -> None:
        """Callback invoked when Person 1 emits a new SecurityEvent."""
        try:
            # 1. Persist to SQLite/Postgres (idempotent, thread-safe, never raises)
            db.save_event(event)

            # 2. Dispatch to Discord & Slack asynchronously in background thread
            webhook_mgr.dispatch(event, sync=False)
        except Exception as exc:
            logger.error("Error in on_security_event callback: %s", exc, exc_info=True)

    if event_store is None:
        try:
            from app.event_logger import event_store as default_store
            event_store = default_store
        except ImportError:
            event_store = None

    if event_store is not None and hasattr(event_store, "register_subscriber"):
        event_store.register_subscriber(on_security_event)
        logger.info("Successfully registered on_security_event with Person 1's event_store!")
    else:
        logger.warning(
            "No in-process event_store available to register. "
            "Use 'python integration.py --poll' to ingest from Person 1's REST API."
        )

    return db, webhook_mgr, on_security_event


def poll_events(
    target_url: str = "http://127.0.0.1:8000",
    interval: float = 2.0,
    db: Optional[EventPersistence] = None,
    webhook_mgr: Optional[WebhookManager] = None,
    once: bool = False,
) -> int:
    """Continuously poll Person 1's GET /events REST API and feed into persistence & alerting.

    Args:
        target_url: Base URL of Person 1's FastAPI service.
        interval: Polling frequency in seconds.
        db: EventPersistence instance.
        webhook_mgr: WebhookManager instance.
        once: If True, execute single poll and return.

    Returns:
        Total number of newly processed events.
    """
    if db is None:
        db = EventPersistence()
    if webhook_mgr is None:
        webhook_mgr = WebhookManager()

    clean_target = target_url.rstrip("/")
    events_url = f"{clean_target}/events?limit=100&order=asc"

    # Pre-populate seen_event_ids from existing database to avoid re-alerting old records
    seen_ids: Set[str] = set()
    try:
        existing = db.query_events(limit=500)
        for ev in existing:
            seen_ids.add(ev["event_id"])
        logger.info("Loaded %d previously indexed event IDs from database.", len(seen_ids))
    except Exception as e:
        logger.warning("Could not pre-load existing event IDs: %s", e)

    total_ingested = 0
    logger.info("Starting out-of-process poller for %s (poll interval: %.1fs)...", events_url, interval)

    consecutive_errors = 0
    while True:
        try:
            req = urllib.request.Request(
                events_url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "VOID-Integration-Poller/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    new_batch = 0
                    for raw_ev in data:
                        eid = raw_ev.get("event_id")
                        if not eid or eid in seen_ids:
                            continue

                        # Mark as seen
                        seen_ids.add(eid)

                        # Construct SecurityEvent model
                        try:
                            sec_event = SecurityEvent(**raw_ev)
                        except Exception:
                            # Fallback dictionary if local validation differs
                            sec_event = raw_ev

                        db.save_event(sec_event)
                        webhook_mgr.dispatch(sec_event, sync=False)
                        new_batch += 1
                        total_ingested += 1

                    if new_batch > 0:
                        logger.info("Ingested %d new security events (total: %d)", new_batch, total_ingested)
                    consecutive_errors = 0

        except urllib.error.URLError as uerr:
            consecutive_errors += 1
            if consecutive_errors in (1, 5, 20):
                logger.warning(
                    "Target server %s not reachable (%s). Retrying in %.1fs...",
                    clean_target,
                    uerr.reason,
                    interval,
                )
        except Exception as exc:
            consecutive_errors += 1
            logger.error("Error during event poll cycle: %s", exc)

        if once:
            break

        time.sleep(interval)

    return total_ingested


def main() -> None:
    """CLI entrypoint for integration runner."""
    parser = argparse.ArgumentParser(
        description="VOID // SENTINEL — Person 3 Integration Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--poll",
        action="store_true",
        help="Run out-of-process polling mode against Person 1's GET /events",
    )
    parser.add_argument(
        "--target",
        default=os.getenv("VOID_BACKEND_URL", "http://127.0.0.1:8000"),
        help="Person 1 backend base URL",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds",
    )
    parser.add_argument(
        "--db",
        default=os.getenv("VOID_DB_PATH", "void_security_events.db"),
        help="SQLite database path",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll once and exit",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    db = EventPersistence(db_path=args.db)
    webhook_mgr = WebhookManager()

    if args.poll:
        logger.info("Starting out-of-process event polling mode against %s", args.target)
        try:
            poll_events(
                target_url=args.target,
                interval=args.interval,
                db=db,
                webhook_mgr=webhook_mgr,
                once=args.once,
            )
        except KeyboardInterrupt:
            logger.info("Poller stopped by user.")
    else:
        # Attempt in-process wire_up
        logger.info("Attempting in-process wire_up...")
        _, _, _ = wire_up(db=db, webhook_mgr=webhook_mgr)
        logger.info(
            "Integration initialized. To run out-of-process polling, execute:\n"
            "    python integration.py --poll --target %s",
            args.target,
        )


if __name__ == "__main__":
    main()
