"""Webhook Notification Dispatcher for VOID // SENTINEL (Person 3).

Provides resilient Discord and Slack alert dispatchers featuring:
- Asynchronous non-blocking queue worker
- Configurable severity thresholds (Discord & Slack)
- Per-IP + attack_type cooldown deduplication (e.g. 30s)
- Truncation to Discord/Slack API payload limits
- Automatic 2-attempt retry with backoff
- Environment variable configuration (.env support)
- Demo-safe mock logging when no webhook URLs are provided
"""

from collections import defaultdict
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import queue
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.request

# Load .env if python-dotenv is installed
try:
    from dotenv import load_dotenv

    # Search for .env in current and parent directories
    env_path = Path(".env")
    if not env_path.exists():
        env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        load_dotenv()
except ImportError:
    pass

# Handle schemas import
try:
    from app.schemas import AttackType, SecurityAction, SecurityEvent, SeverityLevel
except ImportError:
    from schemas import AttackType, SecurityAction, SecurityEvent, SeverityLevel

logger = logging.getLogger("void.webhook_notifier")


def truncate_str(text: Any, max_len: int) -> str:
    """Safely truncate text to max_len with ellipsis."""
    s = str(text) if text is not None else ""
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 3)] + "..."


class BaseNotifier:
    """Base class providing shared severity ranking and cooldown deduplication."""

    SEVERITY_RANK = {
        SeverityLevel.LOW: 1,
        "LOW": 1,
        SeverityLevel.MEDIUM: 2,
        "MEDIUM": 2,
        SeverityLevel.HIGH: 3,
        "HIGH": 3,
        SeverityLevel.CRITICAL: 4,
        "CRITICAL": 4,
    }

    def __init__(
        self,
        min_severity: Union[SeverityLevel, str] = SeverityLevel.MEDIUM,
        alert_on_all_decoys: bool = True,
        cooldown_seconds: float = 30.0,
    ) -> None:
        if isinstance(min_severity, str):
            try:
                self.min_severity = SeverityLevel(min_severity.upper())
            except ValueError:
                self.min_severity = SeverityLevel.MEDIUM
        else:
            self.min_severity = min_severity

        self.alert_on_all_decoys = alert_on_all_decoys
        self.cooldown_seconds = float(cooldown_seconds)
        self._cooldown_lock = threading.Lock()
        # Maps (source_ip, attack_type_str) -> timestamp of last dispatch
        self._last_alert_time: Dict[Tuple[str, str], float] = {}

    def should_alert(self, event: SecurityEvent) -> bool:
        """Check whether the event meets severity criteria."""
        if self.alert_on_all_decoys and event.decoy_triggered:
            return True

        event_sev = event.severity.value if hasattr(event.severity, "value") else str(event.severity)
        min_sev = self.min_severity.value if hasattr(self.min_severity, "value") else str(self.min_severity)

        return self.SEVERITY_RANK.get(event_sev, 0) >= self.SEVERITY_RANK.get(min_sev, 2)

    def check_and_update_cooldown(self, event: SecurityEvent) -> bool:
        """Return True if event is allowed past cooldown; False if suppressed.

        Enforces at most one alert per (source_ip, attack_type) within cooldown_seconds.
        """
        if self.cooldown_seconds <= 0:
            return True

        atk = event.attack_type.value if hasattr(event.attack_type, "value") else str(event.attack_type)
        key = (str(event.source_ip), str(atk))
        now = time.time()

        with self._cooldown_lock:
            last_time = self._last_alert_time.get(key, 0.0)
            if now - last_time < self.cooldown_seconds:
                logger.info(
                    "Cooldown active for (%s, %s): suppressed alert (%.1fs remaining)",
                    key[0],
                    key[1],
                    self.cooldown_seconds - (now - last_time),
                )
                return False
            self._last_alert_time[key] = now
            return True

    def reset_cooldown(self) -> None:
        """Reset internal cooldown cache (useful for testing)."""
        with self._cooldown_lock:
            self._last_alert_time.clear()


class DiscordNotifier(BaseNotifier):
    """Formats and posts Discord rich embed notifications with API limits protection."""

    COLOR_MAP = {
        SeverityLevel.CRITICAL: 15158332,  # Vivid Red (#E74C3C)
        "CRITICAL": 15158332,
        SeverityLevel.HIGH: 15105570,      # Orange (#E67E22)
        "HIGH": 15105570,
        SeverityLevel.MEDIUM: 15844367,    # Gold / Yellow (#F1C40F)
        "MEDIUM": 15844367,
        SeverityLevel.LOW: 3447003,        # Blue (#3498DB)
        "LOW": 3447003,
    }

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        min_severity: Union[SeverityLevel, str] = SeverityLevel.MEDIUM,
        alert_on_all_decoys: bool = True,
        cooldown_seconds: float = 30.0,
    ) -> None:
        super().__init__(
            min_severity=min_severity,
            alert_on_all_decoys=alert_on_all_decoys,
            cooldown_seconds=cooldown_seconds,
        )
        self.webhook_url = webhook_url or os.getenv("DISCORD_WEBHOOK_URL")

    def build_payload(self, event: SecurityEvent) -> Dict[str, Any]:
        """Build Discord rich embed JSON payload adhering to Discord character limits."""
        sev_val = event.severity.value if hasattr(event.severity, "value") else str(event.severity)
        atk_val = event.attack_type.value if hasattr(event.attack_type, "value") else str(event.attack_type)
        act_val = event.action.value if hasattr(event.action, "value") else str(event.action)

        color = self.COLOR_MAP.get(sev_val, 3447003)
        icon_flag = ":rotating_light:" if sev_val in ("HIGH", "CRITICAL") else ":warning:"

        # Discord field limit is 1024 chars for value, 256 for name
        fields = [
            {"name": "Attack Category", "value": f"`{truncate_str(atk_val, 50)}`", "inline": True},
            {"name": "Severity / Risk", "value": f"**{sev_val}** ({event.risk_score}/100)", "inline": True},
            {"name": "Source IP", "value": f"`{truncate_str(event.source_ip, 64)}`", "inline": True},
            {"name": "Target Path", "value": f"`{truncate_str(f'{event.method} {event.path}', 500)}`", "inline": False},
            {
                "name": "Deception Canary",
                "value": ":dart: **DECOY TRAP TRIGGERED**" if event.decoy_triggered else "No",
                "inline": True,
            },
            {"name": "Action Taken", "value": f"`{truncate_str(act_val, 64)}`", "inline": True},
            {"name": "Correlation ID", "value": f"`{truncate_str(event.request_id, 64)}`", "inline": True},
            {"name": "Trigger Reason", "value": truncate_str(event.reason, 1024), "inline": False},
        ]

        # Evidence: Only sanitized evidence strings, never raw secrets
        if event.evidence:
            evidence_lines = [f"• {truncate_str(e, 300)}" for e in event.evidence[:3]]
            evidence_str = truncate_str("\n".join(evidence_lines), 1024)
            fields.append({"name": "Evidence", "value": evidence_str, "inline": False})

        title_text = truncate_str(f"{icon_flag} VOID Security Alert: {atk_val}", 256)
        desc_text = truncate_str(f"Security incident intercepted at `{event.timestamp}`", 4096)
        footer_text = truncate_str(f"VOID Cyber Defense | Event ID: {event.event_id}", 2048)

        embed = {
            "title": title_text,
            "description": desc_text,
            "color": color,
            "fields": fields,
            "footer": {"text": footer_text},
        }

        return {"username": "VOID Cyber Defense Bot", "embeds": [embed]}

    def send_direct(self, event: SecurityEvent, check_cooldown: bool = True) -> bool:
        """Send notification directly with 2-attempt retry and backoff."""
        if not self.should_alert(event):
            return False

        if check_cooldown and not self.check_and_update_cooldown(event):
            return False

        payload = self.build_payload(event)

        if not self.webhook_url:
            logger.info("[MOCK DISCORD DISPATCH] %s", json.dumps(payload, indent=2))
            return True

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "VOID-Cyber-Defense-Notifier/1.0",
            },
        )

        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status in (200, 204):
                        return True
                    logger.warning("Discord webhook returned status %d on attempt %d", resp.status, attempt)
            except Exception as e:
                logger.warning("Discord webhook attempt %d/%d failed: %s", attempt, max_attempts, e)
                if attempt < max_attempts:
                    time.sleep(0.5)

        logger.error("Failed to post Discord webhook after %d attempts", max_attempts)
        return False

    def send(self, event: SecurityEvent, sync: bool = False) -> bool:
        """Send notification. Defaults to asynchronous background dispatch."""
        if sync:
            return self.send_direct(event)
        webhook_worker.enqueue(self, event)
        return True


class SlackNotifier(BaseNotifier):
    """Formats and posts Slack Block Kit notifications with severity filtering and limits."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        min_severity: Union[SeverityLevel, str] = SeverityLevel.MEDIUM,
        alert_on_all_decoys: bool = True,
        cooldown_seconds: float = 30.0,
    ) -> None:
        super().__init__(
            min_severity=min_severity,
            alert_on_all_decoys=alert_on_all_decoys,
            cooldown_seconds=cooldown_seconds,
        )
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")

    def build_payload(self, event: SecurityEvent) -> Dict[str, Any]:
        """Build Slack Block Kit notification payload."""
        sev_val = event.severity.value if hasattr(event.severity, "value") else str(event.severity)
        atk_val = event.attack_type.value if hasattr(event.attack_type, "value") else str(event.attack_type)

        header_text = truncate_str(f":rotating_light: *VOID Alert [{sev_val}]*: {atk_val}", 150)
        decoy_status = "Yes :dart:" if event.decoy_triggered else "No"

        blocks: List[Dict[str, Any]] = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": header_text},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Path:*\n`{truncate_str(f'{event.method} {event.path}', 500)}`"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{truncate_str(event.source_ip, 64)}`"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{event.risk_score} / 100"},
                    {"type": "mrkdwn", "text": f"*Decoy Triggered:*\n{decoy_status}"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Reason:* {truncate_str(event.reason, 300)} | *Event ID:* `{truncate_str(event.event_id, 36)}`",
                    }
                ],
            },
        ]

        if event.evidence:
            evidence_summary = truncate_str("\n".join([f"• {e}" for e in event.evidence[:3]]), 500)
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Evidence:*\n{evidence_summary}"},
            })

        return {"blocks": blocks}

    def send_direct(self, event: SecurityEvent, check_cooldown: bool = True) -> bool:
        """Send webhook to Slack directly with 2-attempt retry and backoff."""
        if not self.should_alert(event):
            return False

        if check_cooldown and not self.check_and_update_cooldown(event):
            return False

        payload = self.build_payload(event)

        if not self.webhook_url:
            logger.info("[MOCK SLACK DISPATCH] %s", json.dumps(payload, indent=2))
            return True

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
        )

        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        return True
                    logger.warning("Slack webhook returned status %d on attempt %d", resp.status, attempt)
            except Exception as e:
                logger.warning("Slack webhook attempt %d/%d failed: %s", attempt, max_attempts, e)
                if attempt < max_attempts:
                    time.sleep(0.5)

        logger.error("Failed to post Slack webhook after %d attempts", max_attempts)
        return False

    def send(self, event: SecurityEvent, sync: bool = False) -> bool:
        """Send notification. Defaults to asynchronous background dispatch."""
        if sync:
            return self.send_direct(event)
        webhook_worker.enqueue(self, event)
        return True


class WebhookWorker:
    """Background queue worker thread to guarantee webhooks never block request path."""

    def __init__(self) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._thread = threading.Thread(target=self._process_queue, daemon=True, name="VOID-WebhookWorker")
        self._thread.start()

    def enqueue(self, notifier: BaseNotifier, event: SecurityEvent) -> None:
        """Enqueue alert item for background delivery."""
        try:
            self._queue.put_nowait((notifier, event))
        except queue.Full:
            logger.warning("Webhook queue full! Dropping oldest alert.")
            try:
                self._queue.get_nowait()
                self._queue.put_nowait((notifier, event))
            except Exception:
                pass

    def _process_queue(self) -> None:
        while True:
            try:
                notifier, event = self._queue.get()
                if hasattr(notifier, "send_direct"):
                    notifier.send_direct(event)
                self._queue.task_done()
            except Exception as e:
                logger.error("Unexpected error in webhook worker thread: %s", e, exc_info=True)

    def drain(self, timeout: float = 5.0) -> None:
        """Block until all queued notifications are dispatched."""
        try:
            self._queue.join()
        except Exception:
            pass


# Global singleton worker for background non-blocking dispatch
webhook_worker = WebhookWorker()


class WebhookManager:
    """Unified manager holding both Discord and Slack dispatchers configured from env."""

    def __init__(
        self,
        discord_url: Optional[str] = None,
        slack_url: Optional[str] = None,
        min_severity: Optional[str] = None,
        cooldown_seconds: Optional[float] = None,
    ) -> None:
        min_sev_str = min_severity or os.getenv("ALERT_MIN_SEVERITY", "MEDIUM")
        cd_secs = cooldown_seconds if cooldown_seconds is not None else float(os.getenv("ALERT_COOLDOWN_SECONDS", "30"))

        self.discord = DiscordNotifier(
            webhook_url=discord_url or os.getenv("DISCORD_WEBHOOK_URL"),
            min_severity=min_sev_str,
            cooldown_seconds=cd_secs,
        )
        self.slack = SlackNotifier(
            webhook_url=slack_url or os.getenv("SLACK_WEBHOOK_URL"),
            min_severity=min_sev_str,
            cooldown_seconds=cd_secs,
        )

    def dispatch(self, event: SecurityEvent, sync: bool = False) -> None:
        """Dispatch event to both Discord and Slack notifiers asynchronously."""
        self.discord.send(event, sync=sync)
        self.slack.send(event, sync=sync)
