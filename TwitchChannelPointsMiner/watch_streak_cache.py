import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

from TwitchChannelPointsMiner.utils import dump_json

logger = logging.getLogger(__name__)

WATCH_STREAK_CACHE_VERSION = 2
MIN_OFFLINE_FOR_NEW_STREAK = 30 * 60  # 30 minutes
MAX_STREAK_ATTEMPTS_PER_BROADCAST = 2
STALE_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60  # drop ended sessions after a week


@dataclass
class WatchStreakSession:
    account_name: str
    streamer_login: str
    broadcast_id: str
    started_at: float
    attempts: int = 0
    claimed: bool = False
    last_attempt_at: float | None = None
    ended_at: float | None = None

    def key(self) -> str:
        return f"{self.account_name}:{self.streamer_login}:{self.broadcast_id}"

    def to_dict(self) -> Dict[str, object]:
        return {
            "account_name": self.account_name,
            "streamer_login": self.streamer_login,
            "broadcast_id": self.broadcast_id,
            "started_at": self.started_at,
            "attempts": self.attempts,
            "claimed": self.claimed,
            "last_attempt_at": self.last_attempt_at,
            "ended_at": self.ended_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "WatchStreakSession":
        return cls(
            account_name=str(data.get("account_name", "")),
            streamer_login=str(data.get("streamer_login", "")),
            broadcast_id=str(data.get("broadcast_id", "")),
            started_at=float(data.get("started_at", 0) or 0),
            attempts=int(data.get("attempts", 0) or 0),
            claimed=bool(data.get("claimed", False)),
            last_attempt_at=(
                float(data["last_attempt_at"])
                if data.get("last_attempt_at") not in [None, ""]
                else None
            ),
            ended_at=(
                float(data["ended_at"]) if data.get("ended_at") not in [None, ""] else None
            ),
        )


@dataclass
class StreamerPresence:
    last_broadcast_id: str | None = None
    previous_broadcast_id: str | None = None
    last_online_at: float | None = None
    last_offline_at: float | None = None
    seen_online: bool = False


class WatchStreakCache:
    def __init__(
        self,
        sessions: Dict[str, WatchStreakSession] | None = None,
        default_account_name: str | None = None,
    ):
        self._sessions: Dict[str, WatchStreakSession] = sessions or {}
        self.default_account_name = default_account_name
        self._lock = threading.Lock()
        self._dirty = False
        self._presence: Dict[str, StreamerPresence] = {}
        self.bootstrap_done: bool = False

    @classmethod
    def load_from_disk(
        cls, path: str, default_account_name: str | None = None
    ) -> "WatchStreakCache":
        raw_data: Dict[str, object] = {}
        if not os.path.isfile(path):
            logger.debug(
                "WatchStreakCache: cache not found at %s, starting empty",
                path,
            )
        else:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
            except Exception as exc:
                logger.warning(
                    "Failed to read watch streak cache from %s, starting empty: %s",
                    path,
                    exc,
                )
                raw_data = {}

        sessions: Dict[str, WatchStreakSession] = {}
        if isinstance(raw_data, dict) and isinstance(raw_data.get("sessions"), list):
            for raw_session in raw_data.get("sessions", []):
                if not isinstance(raw_session, dict):
                    continue
                try:
                    session = WatchStreakSession.from_dict(raw_session)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("Skipping invalid watch streak session: %s", exc)
                    continue
                if not session.account_name or not session.streamer_login or not session.broadcast_id:
                    continue
                sessions[session.key()] = session
        elif isinstance(raw_data, dict) and raw_data:
            # Backwards compatibility: old format was {<streamer_login>: {"last_streak_timestamp": ts}}
            logger.debug(
                "WatchStreakCache: detected legacy cache format with %d entries, starting fresh",
                len(raw_data),
            )

        cache = cls(sessions, default_account_name)
        cache._prune_stale_sessions(time.time())
        logger.debug(
            "WatchStreakCache: loaded %d sessions from %s",
            len(cache._sessions),
            path,
        )
        return cache

    def set_default_account(self, account_name: str) -> None:
        self.default_account_name = account_name

    def _resolve_account(self, account_name: str | None) -> str:
        account = account_name or self.default_account_name
        if not account:
            raise ValueError("account_name is required for watch streak tracking")
        return account

    def _presence_key(self, account_name: str, streamer_login: str) -> str:
        return f"{account_name}:{streamer_login}"

    def _session_key(self, account_name: str, streamer_login: str, broadcast_id: str) -> str:
        return f"{account_name}:{streamer_login}:{broadcast_id}"

    def latest_session_for_streamer(
        self, streamer_login: str, account_name: str | None = None
    ) -> Optional[WatchStreakSession]:
        account = self._resolve_account(account_name)
        with self._lock:
            sessions = [
                s
                for s in self._sessions.values()
                if s.account_name == account and s.streamer_login == streamer_login
            ]
        if not sessions:
            return None
        return max(sessions, key=lambda s: s.started_at)

    def get_session(
        self, streamer_login: str, broadcast_id: str, account_name: str | None = None
    ) -> Optional[WatchStreakSession]:
        account = self._resolve_account(account_name)
        key = self._session_key(account, streamer_login, broadcast_id)
        with self._lock:
            return self._sessions.get(key)

    def ensure_session(
        self,
        streamer_login: str,
        broadcast_id: str,
        started_at: float,
        account_name: str | None = None,
    ) -> WatchStreakSession:
        account = self._resolve_account(account_name)
        key = self._session_key(account, streamer_login, broadcast_id)
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                for other in self._sessions.values():
                    if (
                        other.account_name == account
                        and other.streamer_login == streamer_login
                        and other.ended_at is None
                        and other.broadcast_id != broadcast_id
                    ):
                        other.ended_at = started_at
                        self._dirty = True
                session = WatchStreakSession(
                    account_name=account,
                    streamer_login=streamer_login,
                    broadcast_id=broadcast_id,
                    started_at=started_at,
                )
                self._sessions[key] = session
                self._dirty = True
            return session

    def mark_attempt(
        self,
        streamer_login: str,
        broadcast_id: str,
        attempt_end_time: float,
        account_name: str | None = None,
        max_attempts: int = MAX_STREAK_ATTEMPTS_PER_BROADCAST,
    ) -> WatchStreakSession:
        account = self._resolve_account(account_name)
        session = self.ensure_session(
            streamer_login, broadcast_id, attempt_end_time, account_name=account
        )
        with self._lock:
            session.attempts += 1
            session.last_attempt_at = attempt_end_time
            if session.attempts >= max_attempts and session.ended_at is None:
                session.ended_at = attempt_end_time
            self._dirty = True
            return session

    def mark_claimed(
        self,
        streamer_login: str,
        broadcast_id: str | None = None,
        now: Optional[float] = None,
        account_name: str | None = None,
    ) -> WatchStreakSession:
        account = self._resolve_account(account_name)
        now = time.time() if now is None else now
        session: Optional[WatchStreakSession] = None
        if broadcast_id:
            session = self.get_session(streamer_login, broadcast_id, account_name=account)
        if session is None:
            session = self.latest_session_for_streamer(streamer_login, account_name=account)
        if session is None:
            session = self.ensure_session(
                streamer_login,
                broadcast_id or f"{streamer_login}:{int(now)}",
                now,
                account_name=account,
            )
        with self._lock:
            session.claimed = True
            session.ended_at = session.ended_at or now
            self._dirty = True
            return session

    def mark_ended(
        self,
        streamer_login: str,
        broadcast_id: str,
        ended_at: Optional[float] = None,
        account_name: str | None = None,
    ) -> Optional[WatchStreakSession]:
        account = self._resolve_account(account_name)
        ended_at = time.time() if ended_at is None else ended_at
        key = self._session_key(account, streamer_login, broadcast_id)
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                return None
            if session.ended_at is None:
                session.ended_at = ended_at
                self._dirty = True
            return session

    def end_other_sessions(
        self,
        streamer_login: str,
        broadcast_id: str,
        ended_at: Optional[float] = None,
        account_name: str | None = None,
    ) -> None:
        account = self._resolve_account(account_name)
        ended_at = time.time() if ended_at is None else ended_at
        with self._lock:
            for session in self._sessions.values():
                if (
                    session.account_name == account
                    and session.streamer_login == streamer_login
                    and session.broadcast_id != broadcast_id
                    and session.ended_at is None
                ):
                    session.ended_at = ended_at
                    self._dirty = True

    def pending_sessions(
        self,
        account_name: str | None = None,
        max_attempts: int = MAX_STREAK_ATTEMPTS_PER_BROADCAST,
    ) -> list[WatchStreakSession]:
        account = self._resolve_account(account_name)
        with self._lock:
            return [
                s
                for s in self._sessions.values()
                if s.account_name == account
                and s.ended_at is None
                and s.claimed is False
                and s.attempts < max_attempts
            ]

    def record_online(
        self,
        streamer_login: str,
        broadcast_id: str,
        online_at: float,
        account_name: str | None = None,
    ) -> None:
        account = self._resolve_account(account_name)
        key = self._presence_key(account, streamer_login)
        with self._lock:
            presence = self._presence.get(key)
            if presence is None:
                presence = StreamerPresence()
                self._presence[key] = presence
            broadcast_changed = presence.last_broadcast_id not in [None, broadcast_id]
            presence.previous_broadcast_id = presence.last_broadcast_id if broadcast_changed else None
            presence.last_broadcast_id = broadcast_id
            presence.last_online_at = online_at
            presence.seen_online = True

    def record_offline(
        self,
        streamer_login: str,
        offline_at: float,
        account_name: str | None = None,
    ) -> None:
        account = self._resolve_account(account_name)
        key = self._presence_key(account, streamer_login)
        with self._lock:
            presence = self._presence.get(key)
            if presence is None:
                presence = StreamerPresence()
                self._presence[key] = presence
            presence.last_offline_at = offline_at

    def mark_bootstrap_done(self) -> None:
        with self._lock:
            self.bootstrap_done = True

    def _offline_gap_from_presence(self, presence: StreamerPresence) -> Optional[float]:
        if (
            presence.last_online_at is None
            or presence.last_offline_at is None
            or presence.last_online_at < presence.last_offline_at
        ):
            return None
        return presence.last_online_at - presence.last_offline_at

    def should_create_session(
        self,
        streamer_login: str,
        account_name: str | None = None,
    ) -> bool:
        account = self._resolve_account(account_name)
        key = self._presence_key(account, streamer_login)
        with self._lock:
            presence = self._presence.get(key)
            bootstrap_done = self.bootstrap_done
            offline_gap = self._offline_gap_from_presence(presence) if presence else None
            seen_offline_online = (
                presence is not None
                and presence.last_offline_at is not None
                and presence.last_online_at is not None
                and presence.last_online_at >= presence.last_offline_at
            )
            broadcast_changed = (
                presence is not None
                and presence.previous_broadcast_id is not None
                and presence.last_broadcast_id is not None
                and presence.previous_broadcast_id != presence.last_broadcast_id
            )
            if (
                not broadcast_changed
                and presence is not None
                and presence.previous_broadcast_id is None
                and presence.last_broadcast_id is not None
                and seen_offline_online
            ):
                # We saw an offline->online transition but don't have a prior broadcast id;
                # treat this as a new broadcast to avoid skipping legitimate streak attempts.
                broadcast_changed = True
        if presence is None:
            return False
        if not bootstrap_done:
            return False

        if offline_gap is None:
            return False

        if broadcast_changed:
            return True

        return offline_gap >= MIN_OFFLINE_FOR_NEW_STREAK

    def _prune_stale_sessions(self, now: float, ttl_seconds: int = STALE_SESSION_TTL_SECONDS):
        with self._lock:
            stale_keys = [
                key
                for key, session in self._sessions.items()
                if session.ended_at is not None and (now - session.ended_at) > ttl_seconds
            ]
            for key in stale_keys:
                del self._sessions[key]
            if stale_keys:
                self._dirty = True

    def save_to_disk_if_dirty(self, path: str) -> None:
        with self._lock:
            if not self._dirty:
                return
            data = {
                "version": WATCH_STREAK_CACHE_VERSION,
                "sessions": [session.to_dict() for session in self._sessions.values()],
            }
            dump_json(path, data)
            self._dirty = False
        logger.debug("WatchStreakCache: saved %d sessions to %s", len(self._sessions), path)


def _self_check_watch_streak_cache():
    now = time.time()
    cache = WatchStreakCache(default_account_name="tester")
    session = cache.ensure_session("streamer", "broadcastA", now)
    assert session.attempts == 0
    cache.mark_attempt("streamer", "broadcastA", now + 10)
    assert cache.get_session("streamer", "broadcastA").attempts == 1
    cache.mark_claimed("streamer", "broadcastA", now + 20)
    claimed_session = cache.get_session("streamer", "broadcastA")
    assert claimed_session.claimed is True
    assert claimed_session.ended_at is not None
    cache.record_online("streamer", "broadcastA", now + 30)
    assert cache.should_create_session("streamer") is False, "Bootstrap gating should block new sessions"
    cache.record_offline("streamer", now + 60)
    cache.mark_bootstrap_done()
    cache.record_online(
        "streamer",
        "broadcastB",
        now + 60 + MIN_OFFLINE_FOR_NEW_STREAK + 5,
    )
    assert cache.should_create_session("streamer") is True, "Offline->online should allow new session after bootstrap"
    cache._prune_stale_sessions(now + STALE_SESSION_TTL_SECONDS + 10)
    print("Watch streak cache self-check passed.")


if __name__ == "__main__":
    _self_check_watch_streak_cache()
