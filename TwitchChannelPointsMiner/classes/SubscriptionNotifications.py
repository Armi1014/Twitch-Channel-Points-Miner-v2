import hashlib
import logging
import threading
import time

from TwitchChannelPointsMiner.utils import _millify, dump_json, load_json

logger = logging.getLogger(__name__)

SUBSCRIPTION_NOTIFICATION_CACHE_VERSION = 1
SUBSCRIPTION_NOTIFICATION_TTL_SECONDS = 12 * 60 * 60
_CACHE_LOCK = threading.Lock()


def format_sub_plan(plan_code):
    plans = {
        "Prime": "Prime",
        "1000": "Tier 1",
        "2000": "Tier 2",
        "3000": "Tier 3",
    }
    if not plan_code:
        return "Unknown"
    return plans.get(str(plan_code), str(plan_code))


def format_channel_points(points) -> str:
    if isinstance(points, (int, float)):
        return f"{_millify(points)} points"
    return "Unknown"


def build_detail_message(title, details):
    return "\n".join([f"**{title}**", "", *details])


def build_subscription_message(
    *,
    msg_id: str,
    channel: str,
    points_label: str,
    subscriber: str = "Unknown",
    recipient: str = "Unknown",
    gifter: str = "Unknown",
    plan: str = "Unknown",
    months: str | None = None,
) -> str | None:
    if msg_id == "sub":
        return build_detail_message(
            "New Subscription",
            [
                f"**Channel:** `{channel}` (`{points_label}`)",
                f"**Subscriber:** **{subscriber}**",
                f"**Tier:** `{plan}`",
            ],
        )
    if msg_id == "resub":
        details = [
            f"**Channel:** `{channel}` (`{points_label}`)",
            f"**Subscriber:** **{subscriber}**",
            f"**Tier:** `{plan}`",
        ]
        if months:
            details.append(f"**Months:** `{months}`")
        return build_detail_message("Subscription Renewed", details)
    if msg_id in ["subgift", "anonsubgift"]:
        return build_detail_message(
            "Received Subgift",
            [
                f"**Channel:** `{channel}` (`{points_label}`)",
                f"**Recipient:** **{recipient}**",
                f"**From:** **{gifter}**",
                f"**Tier:** `{plan}`",
            ],
        )
    if msg_id in ["giftpaidupgrade", "anongiftpaidupgrade"]:
        return build_detail_message(
            "Gift Subscription Upgraded",
            [
                f"**Channel:** `{channel}` (`{points_label}`)",
                f"**Subscriber:** **{subscriber}**",
            ],
        )
    if msg_id == "primepaidupgrade":
        return build_detail_message(
            "Prime Subscription Upgraded",
            [
                f"**Channel:** `{channel}` (`{points_label}`)",
                f"**Subscriber:** **{subscriber}**",
            ],
        )
    return None


def _normalize_dedupe_part(value) -> str:
    return " ".join(str(value or "unknown").lower().split())


def build_subscription_dedupe_key(
    *,
    msg_id: str,
    channel: str,
    points_label: str | None = None,
    subscriber: str = "Unknown",
    recipient: str = "Unknown",
    gifter: str = "Unknown",
    plan: str = "Unknown",
    months: str | None = None,
) -> str:
    if msg_id in ["subgift", "anonsubgift"]:
        parts = ["subgift", channel, recipient, gifter, plan]
    elif msg_id == "resub":
        parts = ["resub", channel, subscriber, plan, months]
    elif msg_id == "sub":
        parts = ["sub", channel, subscriber, plan]
    elif msg_id in ["giftpaidupgrade", "anongiftpaidupgrade", "primepaidupgrade"]:
        parts = [msg_id, channel, subscriber]
    else:
        parts = [msg_id, channel, subscriber, recipient, gifter, plan, months]
    return "|".join(_normalize_dedupe_part(part) for part in parts)


def _dedupe_key(value: str) -> str:
    normalized = " ".join(str(value).lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def should_emit_subscription_notification(
    cache_path: str | None,
    message: str,
    now: float | None = None,
    dedupe_key: str | None = None,
) -> bool:
    if not cache_path:
        return True

    now = time.time() if now is None else now
    key = _dedupe_key(dedupe_key or message)
    with _CACHE_LOCK:
        payload = load_json(cache_path, {})
        raw_entries = payload.get("notifications") if isinstance(payload, dict) else []
        entries = []
        seen = set()
        if isinstance(raw_entries, list):
            for entry in raw_entries:
                if not isinstance(entry, dict):
                    continue
                entry_key = entry.get("key")
                seen_at = entry.get("seen_at")
                if not entry_key:
                    continue
                try:
                    seen_at = float(seen_at)
                except (TypeError, ValueError):
                    continue
                if now - seen_at > SUBSCRIPTION_NOTIFICATION_TTL_SECONDS:
                    continue
                entries.append({"key": str(entry_key), "seen_at": seen_at})
                seen.add(str(entry_key))

        if key in seen:
            logger.debug("Skipping duplicate subscription notification")
            return False

        entries.append({"key": key, "seen_at": now})
        dump_json(
            cache_path,
            {
                "schema_version": SUBSCRIPTION_NOTIFICATION_CACHE_VERSION,
                "notifications": entries[-200:],
            },
        )
        return True
