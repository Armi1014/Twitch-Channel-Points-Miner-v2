"""Server-reported eligibility for weekly visits and missed-stream recovery."""

from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite
import time


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, OverflowError):
        return None


def nonnegative_int(value):
    if isinstance(value, bool):
        return None
    try:
        result = int(value)
        return result if result >= 0 and str(result) == str(value) else None
    except (TypeError, ValueError, OverflowError):
        return None


@dataclass(frozen=True)
class WeeklyRewards:
    event_id: str
    ends_at: float
    days_visited: int
    accumulated_weeks: int
    reward_count: int
    visited_today: bool
    earned_this_week: bool

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or not isinstance(data.get("eventConfig"), dict):
            return None
        event = data["eventConfig"]
        ends_at = timestamp(event.get("endDate"))
        days = nonnegative_int(data.get("daysVisitedThisWeek"))
        weeks = nonnegative_int(data.get("accumulatedWeeks"))
        tiers = event.get("rewardTiers")
        visited = data.get("hasVisitedToday")
        earned = data.get("hasEarnedWeeklyRewardThisWeek")
        if (
            not isinstance(event.get("id"), str)
            or not event["id"]
            or ends_at is None
            or days is None
            or weeks is None
            or not isinstance(tiers, list)
            or not isinstance(visited, bool)
            or not isinstance(earned, bool)
        ):
            return None
        return cls(event["id"], ends_at, days, weeks, len(tiers), visited, earned)

    def needs_visit(self, now=None):
        now = time.time() if now is None else now
        return (
            self.ends_at > now
            and self.accumulated_weeks < self.reward_count
            and not self.visited_today
            and not self.earned_this_week
        )

    def progressed_from(self, previous, now=None):
        return (
            previous.needs_visit(now)
            and self.event_id == previous.event_id
            and (
                self.visited_today
                or self.earned_this_week
                or self.days_visited > previous.days_visited
                or self.accumulated_weeks > previous.accumulated_weeks
            )
        )


@dataclass(frozen=True)
class StreakRecovery:
    streak_days: int
    missed_broadcasts: frozenset[str]
    expires_at: float | None

    @classmethod
    def from_dict(cls, milestone):
        if not isinstance(milestone, dict):
            return None
        viewer = milestone.get("watchStreakMilestone")
        if not isinstance(viewer, dict):
            return None
        days = nonnegative_int(viewer.get("value"))
        missed = milestone.get("missedStreams")
        if (
            days is None
            or "missedStreams" not in milestone
            or "expiresAt" not in milestone
            or (missed is not None and not isinstance(missed, list))
        ):
            return None
        ids = set()
        for broadcast in missed or []:
            if not isinstance(broadcast, dict):
                return None
            identifiers = broadcast.get("broadcastIdentifiers")
            if not isinstance(identifiers, list):
                return None
            for identifier in identifiers:
                if not isinstance(identifier, dict) or not isinstance(
                    identifier.get("id"), str
                ):
                    return None
                if identifier["id"]:
                    ids.add(identifier["id"])
        return cls(days, frozenset(ids), timestamp(milestone.get("expiresAt")))

    def recoverable(self, now=None):
        now = time.time() if now is None else now
        return (
            self.streak_days >= 3
            and bool(self.missed_broadcasts)
            and self.expires_at is not None
            and self.expires_at > now
        )

    def recovered_from(self, previous, now=None):
        return (
            previous.recoverable(now)
            and not self.missed_broadcasts
            and self.streak_days >= previous.streak_days
        )


@dataclass(frozen=True)
class Replay:
    kind: str
    id: str
    broadcast_id: str | None
    duration: float
    url: str = ""
    slug: str = ""

    @classmethod
    def from_dict(cls, data, kind):
        if (
            kind not in {"clip", "vod"}
            or not isinstance(data, dict)
            or not isinstance(data.get("id"), str)
            or not data["id"]
        ):
            return None
        value = data.get("durationSeconds" if kind == "clip" else "lengthSeconds")
        if isinstance(value, bool):
            return None
        try:
            duration = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if not isfinite(duration) or duration < (5 if kind == "clip" else 300):
            return None
        broadcast = data.get("broadcastIdentifier")
        broadcast_id = broadcast.get("id") if isinstance(broadcast, dict) else None
        if broadcast_id is not None and not isinstance(broadcast_id, str):
            return None
        if kind == "clip":
            if (
                not isinstance(data.get("slug"), str)
                or not data["slug"]
                or not isinstance(data.get("url"), str)
                or not data["url"].startswith("https://")
            ):
                return None
            return cls(
                kind, data["id"], broadcast_id, duration, data["url"], data["slug"]
            )
        if not data["id"].isdigit():
            return None
        return cls(kind, data["id"], broadcast_id, duration)
