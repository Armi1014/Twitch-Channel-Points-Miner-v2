# For documentation on Twitch GraphQL API see:
# https://www.apollographql.com/docs/
# https://github.com/mauricew/twitch-graphql-api
# Full list of available methods: https://azr.ivr.fi/schema/query.doc.html (a bit outdated)


import copy
import logging
import os
import random
import re
import string
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed

import requests
import validators
# import json

from pathlib import Path
from secrets import choice, token_hex
from typing import Dict, Any, Optional
# from urllib.parse import quote
# from base64 import urlsafe_b64decode
# from datetime import datetime

from dataclasses import dataclass
from datetime import timezone
from TwitchChannelPointsMiner.classes.entities.Campaign import Campaign
from TwitchChannelPointsMiner.classes.entities.CommunityGoal import CommunityGoal
from TwitchChannelPointsMiner.classes.entities.Drop import Drop
from TwitchChannelPointsMiner.classes.Exceptions import (
    StreamerDoesNotExistException,
    StreamerIsOfflineException,
)
from TwitchChannelPointsMiner.classes.Settings import (
    Events,
    FollowersOrder,
    Priority,
    Settings,
)
from TwitchChannelPointsMiner.classes.TwitchLogin import TwitchLogin
from TwitchChannelPointsMiner.constants import (
    CLIENT_ID,
    CLIENT_VERSION,
    URL,
    GQLOperations,
)
from TwitchChannelPointsMiner.watch_streak_cache import (
    MAX_STREAK_ATTEMPTS_PER_BROADCAST,
    MIN_OFFLINE_FOR_NEW_STREAK,
    WatchStreakSession,
)
from datetime import datetime
from TwitchChannelPointsMiner.utils import (
    _millify,
    create_chunks,
    internet_connection_available,
    interruptible_sleep,
)

logger = logging.getLogger(__name__)
JsonType = Dict[str, Any]
STREAMER_INIT_TIMEOUT_PER_STREAMER = 5  # seconds
STREAM_INFO_CACHE_TTL = 30  # seconds
GQL_ERROR_LOG_TTL = 60  # seconds
STREAK_MIN_SECONDS = 5 * 60  # Qualifying watch time before attempting a streak


@dataclass
class ActiveWatchStreakAttempt:
    session_key: str
    streamer: str
    broadcast_id: str
    started_at: float


class Twitch(object):
    __slots__ = [
        "cookies_file",
        "account_username",
        "user_agent",
        "twitch_login",
        "running",
        "device_id",
        # "integrity",
        # "integrity_expire",
        "client_session",
        "client_version",
        "twilight_build_id_pattern",
        "_stream_info_cache",
        "watch_streak_cache",
        "_last_gql_error_log",
        "_drop_progress_log",
        "watch_streak_max_parallel",
        "max_watch_amount",
        "_last_selection_was_streak",
        "_last_streak_selection",
        "max_streak_sessions",
        "streak_watch_seconds",
        "max_streak_attempts",
        "_active_streak_attempts",
        "_streak_outcomes_logged",
    ]

    def __init__(self, username, user_agent, password=None, watch_streak_max_parallel=None):
        cookies_path = os.path.join(Path().absolute(), "cookies")
        Path(cookies_path).mkdir(parents=True, exist_ok=True)
        self.cookies_file = os.path.join(cookies_path, f"{username}.pkl")
        self.account_username = username
        self.user_agent = user_agent
        self.device_id = "".join(
            choice(string.ascii_letters + string.digits) for _ in range(32)
        )
        self.twitch_login = TwitchLogin(
            CLIENT_ID, self.device_id, username, self.user_agent, password=password
        )
        self.running = True
        # self.integrity = None
        # self.integrity_expire = 0
        self.client_session = token_hex(16)
        self.client_version = CLIENT_VERSION
        self.twilight_build_id_pattern = re.compile(
            r'window\.__twilightBuildID\s*=\s*"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"'
        )
        self._stream_info_cache = {}
        self.watch_streak_cache = None
        self._last_gql_error_log = {}
        self._drop_progress_log: Dict[str, int] = {}
        self.watch_streak_max_parallel = (
            max(1, int(watch_streak_max_parallel))
            if watch_streak_max_parallel is not None
            else None
        )
        self.max_watch_amount = 2
        self._last_selection_was_streak = False
        self._last_streak_selection: set[str] = set()
        self.max_streak_sessions = min(2, self.watch_streak_max_parallel or 2)
        self.max_streak_attempts = MAX_STREAK_ATTEMPTS_PER_BROADCAST
        self.streak_watch_seconds = STREAK_MIN_SECONDS
        self._active_streak_attempts: Dict[str, ActiveWatchStreakAttempt] = {}
        # Track which sessions we've already logged a terminal outcome for
        self._streak_outcomes_logged: set[str] = set()

    def login(self):
        if not os.path.isfile(self.cookies_file):
            if self.twitch_login.login_flow():
                self.twitch_login.save_cookies(self.cookies_file)
        else:
            self.twitch_login.load_cookies(self.cookies_file)
            self.twitch_login.set_token(self.twitch_login.get_auth_token())

    # === STREAMER / STREAM / INFO === #
    def update_stream(self, streamer):
        if streamer.stream.update_required() is False:
            return True

        stream_info = self.get_stream_info(streamer)
        if stream_info is None:
            return False

        try:
            streamer.stream.update(
                broadcast_id=stream_info["stream"]["id"],
                title=stream_info["broadcastSettings"]["title"],
                game=stream_info["broadcastSettings"]["game"],
                tags=stream_info["stream"]["tags"],
                viewers_count=stream_info["stream"]["viewersCount"],
            )
        except (KeyError, TypeError):
            logger.debug("Invalid stream info for %s", streamer.username)
            return False

        event_properties = {
            "channel_id": streamer.channel_id,
            "broadcast_id": streamer.stream.broadcast_id,
            "player": "site",
            "user_id": self.twitch_login.get_user_id(),
            "live": True,
            "channel": streamer.username,
        }

        if (
            streamer.stream.game_name() is not None
            and streamer.stream.game_id() is not None
            and streamer.settings.claim_drops is True
        ):
            event_properties["game"] = streamer.stream.game_name()
            event_properties["game_id"] = streamer.stream.game_id()
            # Update also the campaigns_ids so we are sure to tracking the correct campaign
            streamer.stream.campaigns_ids = (
                self.__get_campaign_ids_from_streamer(streamer)
            )

        streamer.stream.payload = [
            {"event": "minute-watched", "properties": event_properties}
        ]
        return True

    def get_spade_url(self, streamer):
        try:
            # fixes AttributeError: 'NoneType' object has no attribute 'group'
            # headers = {"User-Agent": self.user_agent}
            from TwitchChannelPointsMiner.constants import USER_AGENTS

            headers = {"User-Agent": USER_AGENTS["Linux"]["FIREFOX"]}

            main_page_request = requests.get(
                streamer.streamer_url, headers=headers)
            response = main_page_request.text
            # logger.info(response)
            regex_settings = "(https://static.twitchcdn.net/config/settings.*?js|https://assets.twitch.tv/config/settings.*?.js)"
            settings_url = re.search(regex_settings, response).group(1)

            settings_request = requests.get(settings_url, headers=headers)
            response = settings_request.text
            regex_spade = '"spade_url":"(.*?)"'
            streamer.stream.spade_url = re.search(
                regex_spade, response).group(1)
        except requests.exceptions.RequestException as e:
            logger.error(
                f"Something went wrong during extraction of 'spade_url': {e}")

    def get_broadcast_id(self, streamer):
        json_data = copy.deepcopy(GQLOperations.WithIsStreamLiveQuery)
        json_data["variables"] = {"id": streamer.channel_id}
        response = self.post_gql_request(json_data)
        if self._log_gql_errors(json_data.get("operationName"), response):
            raise StreamerIsOfflineException
        stream = (
            response.get("data", {}).get("user", {}).get("stream")
            if isinstance(response, dict)
            else None
        )
        if stream is not None and stream.get("id") is not None:
            return stream.get("id")
        raise StreamerIsOfflineException

    def get_stream_info(self, streamer):
        cache_key = streamer.username
        now = time.time()
        cached_entry = self._get_cached_stream_info(cache_key, now)
        if cached_entry:
            return cached_entry

        json_data = copy.deepcopy(GQLOperations.VideoPlayerStreamInfoOverlayChannel)
        json_data["variables"] = {"channel": streamer.username}
        response = self.post_gql_request(json_data)
        if not response:
            return cached_entry

        self._log_gql_errors(json_data.get("operationName"), response)

        data = response.get("data") if isinstance(response, dict) else None
        if not isinstance(data, dict):
            logger.debug(
                "Stream info response missing data for %s", streamer.username
            )
            return cached_entry

        user = data.get("user")
        if user is None:
            self._invalidate_stream_info_cache(cache_key)
            raise StreamerIsOfflineException

        stream = user.get("stream") if isinstance(user, dict) else None
        if stream is None:
            self._invalidate_stream_info_cache(cache_key)
            raise StreamerIsOfflineException

        broadcast_settings = (
            stream.get("broadcastSettings") if isinstance(stream, dict) else None
        )
        if not isinstance(broadcast_settings, dict):
            broadcast_settings = {}

        if not isinstance(stream.get("tags"), list):
            stream["tags"] = []
        viewers_count = (
            stream.get("viewersCount") if stream.get("viewersCount") is not None else 0
        )
        stream_id = stream.get("id")
        if stream_id is None:
            self._invalidate_stream_info_cache(cache_key)
            raise StreamerIsOfflineException
        title = broadcast_settings.get("title") or ""
        game = broadcast_settings.get("game") or {}

        stream_info = {
            "stream": {
                "id": stream_id,
                "tags": stream.get("tags"),
                "viewersCount": viewers_count,
            },
            "broadcastSettings": {
                "title": title,
                "game": game,
            },
        }

        self._stream_info_cache[cache_key] = {
            "data": stream_info,
            "timestamp": now,
        }
        return stream_info

    def check_streamer_online(self, streamer):
        if time.time() < streamer.offline_at + 60:
            return

        if streamer.is_online is False:
            try:
                self.get_spade_url(streamer)
                updated = self.update_stream(streamer)
            except StreamerIsOfflineException:
                streamer.set_offline()
            else:
                if updated:
                    streamer.set_online()
        else:
            try:
                updated = self.update_stream(streamer)
            except StreamerIsOfflineException:
                streamer.set_offline()
            else:
                if updated is False:
                    # Transient error, keep current state
                    return

    def get_channel_id(self, streamer_username):
        json_data = copy.deepcopy(GQLOperations.GetIDFromLogin)
        json_data["variables"]["login"] = streamer_username
        json_response = self.post_gql_request(json_data)
        if self._log_gql_errors(json_data.get("operationName"), json_response):
            raise StreamerDoesNotExistException
        user = (
            json_response.get("data", {}).get("user")
            if isinstance(json_response, dict)
            else None
        )
        if not user or user.get("id") is None:
            raise StreamerDoesNotExistException
        return user["id"]

    def get_followers(
        self, limit: int = 100, order: FollowersOrder = FollowersOrder.ASC
    ):
        json_data = copy.deepcopy(GQLOperations.ChannelFollows)
        json_data["variables"] = {"limit": limit, "order": str(order)}
        has_next = True
        last_cursor = ""
        follows = []
        timeouts_in_a_row = 0
        while has_next is True:
            json_data["variables"]["cursor"] = last_cursor
            while True:
                json_response = self.post_gql_request(json_data)
                is_timeout = self._has_service_timeout(json_response)
                if self._log_gql_errors(json_data.get("operationName"), json_response):
                    if is_timeout:
                        timeouts_in_a_row += 1
                        logger.debug(
                            "[follows] ChannelFollows service timeout (attempt %d)",
                            timeouts_in_a_row,
                        )
                        if timeouts_in_a_row == 2:
                            logger.info(
                                "[follows] ChannelFollows got %d service timeouts, retrying...",
                                timeouts_in_a_row,
                            )
                        time.sleep(min(3, 0.5 * timeouts_in_a_row + 0.5))
                        continue
                    return follows
                break
            if timeouts_in_a_row > 1:
                logger.debug(
                    "[follows] ChannelFollows recovered after %d service timeouts",
                    timeouts_in_a_row,
                )
            timeouts_in_a_row = 0
            follows_response = (
                json_response.get("data", {})
                .get("user", {})
                .get("follows", {})
                if isinstance(json_response, dict)
                else {}
            )
            if not follows_response:
                return follows

            last_cursor = None
            for f in follows_response.get("edges", []):
                try:
                    follows.append(f["node"]["login"].lower())
                    last_cursor = f.get("cursor", last_cursor)
                except (KeyError, TypeError):
                    continue

            has_next = (
                follows_response.get("pageInfo", {}).get("hasNextPage", False)
                if isinstance(follows_response, dict)
                else False
            )
        return follows

    def update_raid(self, streamer, raid):
        if streamer.raid != raid:
            streamer.raid = raid
            json_data = copy.deepcopy(GQLOperations.JoinRaid)
            json_data["variables"] = {"input": {"raidID": raid.raid_id}}
            self.post_gql_request(json_data)

            logger.info(
                f"Joining raid from {streamer} to {raid.target_login}!",
                extra={"emoji": ":performing_arts:",
                       "event": Events.JOIN_RAID},
            )

    def viewer_is_mod(self, streamer):
        json_data = copy.deepcopy(GQLOperations.ModViewChannelQuery)
        json_data["variables"] = {"channelLogin": streamer.username}
        response = self.post_gql_request(json_data)
        if self._log_gql_errors(json_data.get("operationName"), response):
            streamer.viewer_is_mod = False
            return
        try:
            streamer.viewer_is_mod = (
                response.get("data", {})
                .get("user", {})
                .get("self", {})
                .get("isModerator", False)
            )
        except (ValueError, AttributeError):
            streamer.viewer_is_mod = False

    # === 'GLOBALS' METHODS === #
    # Create chunk of sleep of speed-up the break loop after CTRL+C
    def __chuncked_sleep(self, seconds, chunk_size=3):
        step = max(seconds / max(chunk_size, 1), 0.5)
        interruptible_sleep(lambda: self.running, seconds, step=step)

    def __check_connection_handler(self, chunk_size):
        # The success rate It's very hight usually. Why we have failed?
        # Check internet connection ...
        while internet_connection_available() is False:
            random_sleep = random.randint(1, 3)
            logger.warning(
                f"No internet connection available! Retry after {random_sleep}m"
            )
            self.__chuncked_sleep(random_sleep * 60, chunk_size=chunk_size)

    def _log_gql_errors(self, operation_name, response):
        if not isinstance(response, dict):
            return False
        errors = response.get("errors") or []
        if errors in [[], None]:
            return False
        messages = []
        has_service_timeout = False
        for error in errors:
            if isinstance(error, dict):
                message = error.get("message", str(error))
            else:
                message = str(error)
            messages.append(message)
            if isinstance(message, str) and "service timeout" in message.lower():
                has_service_timeout = True
        message = "; ".join(messages) if messages else "Unknown GQL error"
        if has_service_timeout and operation_name in [
            "VideoPlayerStreamInfoOverlayChannel",
            "ChannelFollows",
        ]:
            logger.debug(
                "GQL operation %s returned service timeout (suppressed): %s",
                operation_name,
                message,
            )
            return True
        now = time.time()
        key = (operation_name, message)
        last_logged = self._last_gql_error_log.get(key, 0)
        if now - last_logged >= GQL_ERROR_LOG_TTL:
            logger.warning(
                "GQL operation %s returned errors: %s", operation_name, message
            )
            self._last_gql_error_log[key] = now
        return True

    def _log_request_exception(self, operation_name, error_message):
        now = time.time()
        key = (operation_name, error_message)
        last_logged = self._last_gql_error_log.get(key, 0)
        if now - last_logged >= GQL_ERROR_LOG_TTL:
            logger.error(
                "Error with GQLOperations (%s): %s", operation_name, error_message
            )
            self._last_gql_error_log[key] = now

    def _has_service_timeout(self, response):
        if not isinstance(response, dict):
            return False
        errors = response.get("errors") or []
        for error in errors:
            message = error.get("message") if isinstance(error, dict) else str(error)
            if isinstance(message, str) and "service timeout" in message.lower():
                return True
        return False

    def _render_drop_progress_bar(self, percent: int) -> str:
        percent = max(0, min(100, percent))
        length = 20
        filled = int((percent * length) / 100)
        return f"[{'█' * filled}{'░' * (length - filled)}]"

    def _log_drop_progress(self, streamer, drop, drops_logging_enabled: bool):
        if not drops_logging_enabled:
            return
        drop_id = getattr(drop, "drop_instance_id", None) or getattr(drop, "id", None)
        if drop_id is None or drop.is_claimed or drop.minutes_required <= 0:
            return

        progress_ratio = drop.current_minutes_watched / drop.minutes_required
        progress_ratio = max(0.0, min(1.0, progress_ratio))
        percent = int(progress_ratio * 100)

        # Always emit an initial log for a new drop progress entry
        last_logged = self._drop_progress_log.get(drop_id)
        if last_logged is None:
            logger.info(
                "[DROPS] %s - \"%s\" %s/%s min (%d%%)",
                streamer.username,
                drop.name,
                drop.current_minutes_watched,
                drop.minutes_required,
                percent,
            )
            self._drop_progress_log[drop_id] = max(0, percent)
            if percent >= 100:
                self._drop_progress_log.pop(drop_id, None)
            return

        if percent >= 100:
            logger.info(
                f"[DROPS] {streamer.username} - \"{drop.name}\" {drop.minutes_required}/{drop.minutes_required} min (100%)"
            )
            self._drop_progress_log.pop(drop_id, None)
            return

        if percent < last_logged + 10 and percent != 100:
            return

        current_minutes = min(drop.current_minutes_watched, drop.minutes_required)
        logger.info(
            f"[DROPS] {streamer.username} - \"{drop.name}\" {current_minutes}/{drop.minutes_required} min ({percent}%)"
        )
        self._drop_progress_log[drop_id] = percent

    def _get_cached_stream_info(self, cache_key, now):
        cached_entry = self._stream_info_cache.get(cache_key)
        if cached_entry and (now - cached_entry["timestamp"]) <= STREAM_INFO_CACHE_TTL:
            return cached_entry["data"]
        return None

    def _invalidate_stream_info_cache(self, cache_key):
        self._stream_info_cache.pop(cache_key, None)

    def post_gql_request(self, json_data):
        try:
            response = requests.post(
                GQLOperations.url,
                json=json_data,
                headers={
                    "Authorization": f"OAuth {self.twitch_login.get_auth_token()}",
                    "Client-Id": CLIENT_ID,
                    # "Client-Integrity": self.post_integrity(),
                    "Client-Session-Id": self.client_session,
                    "Client-Version": self.update_client_version(),
                    "User-Agent": self.user_agent,
                    "X-Device-Id": self.device_id,
                },
            )
            logger.debug(
                f"Data: {json_data}, Status code: {response.status_code}, Content: {response.text}"
            )
            try:
                return response.json()
            except ValueError:
                operation_name = (
                    json_data.get("operationName")
                    if isinstance(json_data, dict)
                    else "UnknownOperation"
                )
                logger.warning(
                    "Invalid JSON response for %s (status %s)", operation_name, response.status_code
                )
                return {}
        except requests.exceptions.RequestException as e:
            operation_name = (
                json_data.get("operationName")
                if isinstance(json_data, dict)
                else "UnknownOperation"
            )
            self._log_request_exception(operation_name, str(e))
            return {}

    # Request for Integrity Token
    # Twitch needs Authorization, Client-Id, X-Device-Id to generate JWT which is used for authorize gql requests
    # Regenerate Integrity Token 5 minutes before expire
    """def post_integrity(self):
        if (
            self.integrity_expire - datetime.now().timestamp() * 1000 > 5 * 60 * 1000
            and self.integrity is not None
        ):
            return self.integrity
        try:
            response = requests.post(
                GQLOperations.integrity_url,
                json={},
                headers={
                    "Authorization": f"OAuth {self.twitch_login.get_auth_token()}",
                    "Client-Id": CLIENT_ID,
                    "Client-Session-Id": self.client_session,
                    "Client-Version": self.update_client_version(),
                    "User-Agent": self.user_agent,
                    "X-Device-Id": self.device_id,
                },
            )
            logger.debug(
                f"Data: [], Status code: {response.status_code}, Content: {response.text}"
            )
            self.integrity = response.json().get("token", None)
            # logger.info(f"integrity: {self.integrity}")

            if self.isBadBot(self.integrity) is True:
                logger.info(
                    "Uh-oh, Twitch has detected this miner as a \"Bad Bot\". Don't worry.")

            self.integrity_expire = response.json().get("expiration", 0)
            # logger.info(f"integrity_expire: {self.integrity_expire}")
            return self.integrity
        except requests.exceptions.RequestException as e:
            logger.error(f"Error with post_integrity: {e}")
            return self.integrity

    # verify the integrity token's contents for the "is_bad_bot" flag
    def isBadBot(self, integrity):
        stripped_token: str = self.integrity.split('.')[2] + "=="
        messy_json: str = urlsafe_b64decode(
            stripped_token.encode()).decode(errors="ignore")
        match = re.search(r'(.+)(?<="}).+$', messy_json)
        if match is None:
            # raise MinerException("Unable to parse the integrity token")
            logger.info("Unable to parse the integrity token. Don't worry.")
            return
        decoded_header = json.loads(match.group(1))
        # logger.info(f"decoded_header: {decoded_header}")
        if decoded_header.get("is_bad_bot", "false") != "false":
            return True
        else:
            return False"""

    def update_client_version(self):
        try:
            response = requests.get(URL)
            if response.status_code != 200:
                logger.debug(
                    f"Error with update_client_version: {response.status_code}"
                )
                return self.client_version
            matcher = re.search(self.twilight_build_id_pattern, response.text)
            if not matcher:
                logger.debug("Error with update_client_version: no match")
                return self.client_version
            self.client_version = matcher.group(1)
            logger.debug(f"Client version: {self.client_version}")
            return self.client_version
        except requests.exceptions.RequestException as e:
                logger.error(f"Error with update_client_version: {e}")
                return self.client_version

    def _drop_progress_value(self, streamer):
        campaigns = getattr(streamer.stream, "campaigns", []) or []
        progress_values = []
        for campaign in campaigns:
            for drop in getattr(campaign, "drops", []) or []:
                if getattr(drop, "is_claimed", False) or getattr(drop, "dt_match", True) is False:
                    continue
                progress = getattr(drop, "percentage_progress", None)
                if progress is None:
                    continue
                progress_values.append(progress)
        if progress_values:
            return min(progress_values)
        return float("inf")

    # Apply the configured priorities in order; each one appends to the sort key so later priorities
    # only break ties from earlier ones (e.g., [STREAK, DROPS, ORDER] builds a tuple in that order).
    def _priority_sort_key(self, streamers, idx, priorities, order_map, now):
        streamer = streamers[idx]
        effective_priorities = priorities or [Priority.ORDER]
        key_parts = []
        for prior in effective_priorities:
            if prior == Priority.ORDER:
                key_parts.append(order_map.get(idx, idx))
            elif prior == Priority.POINTS_ASCENDING:
                points = (
                    streamer.channel_points
                    if streamer.channel_points is not None
                    else float("inf")
                )
                key_parts.append(points)
            elif prior == Priority.POINTS_DESCENDING:
                points = streamer.channel_points
                key_parts.append(-points if points is not None else float("inf"))
            elif prior == Priority.DROPS:
                drop_rank = 0 if streamer.drops_condition() else 1
                drop_progress = (
                    self._drop_progress_value(streamer) if drop_rank == 0 else float("inf")
                )
                key_parts.append((drop_rank, drop_progress))
            elif prior == Priority.SUBSCRIBED:
                sub_rank = 0 if streamer.viewer_has_points_multiplier() else 1
                points = (
                    streamer.channel_points
                    if streamer.channel_points is not None
                    else float("inf")
                )
                key_parts.append((sub_rank, points))
            elif prior == Priority.STREAK:
                session = self._ensure_watch_streak_session(streamer, now)
                eligible = self._session_is_eligible(session, streamer)
                attempts = session.attempts if session is not None else float("inf")
                key_parts.append((0 if eligible else 1, attempts))
            else:
                key_parts.append(0)
        return tuple(key_parts)

    def _priority_candidates(self, streamers, streamers_index, prior, now):
        if prior == Priority.ORDER:
            # Keep the provided configuration order unless ORDER is explicitly requested
            return list(streamers_index)

        if prior in [Priority.POINTS_ASCENDING, Priority.POINTS_DESCENDING]:
            return sorted(
                streamers_index,
                key=lambda x: streamers[x].channel_points,
                reverse=(prior == Priority.POINTS_DESCENDING),
            )

        if prior == Priority.STREAK:
            candidates = []
            for index in streamers_index:
                streamer = streamers[index]
                if streamer.settings.watch_streak is not True:
                    continue
                session = self._ensure_watch_streak_session(streamer, now)
                if not self._session_is_eligible(session, streamer):
                    continue
                candidates.append(index)
            return candidates

        if prior == Priority.DROPS:
            candidates = [
                index for index in streamers_index if streamers[index].drops_condition()
            ]
            order_map = {idx: pos for pos, idx in enumerate(streamers_index)}

            return sorted(
                candidates,
                key=lambda idx: (self._drop_progress_value(streamers[idx]), order_map.get(idx, idx)),
            )  # DROPS: prefer streams with lowest drop progress

        if prior == Priority.SUBSCRIBED:
            streamers_with_multiplier = [
                index
                for index in streamers_index
                if streamers[index].viewer_has_points_multiplier()
            ]
            order_map = {idx: pos for pos, idx in enumerate(streamers_index)}
            return sorted(
                streamers_with_multiplier,
                key=lambda idx: (
                    streamers[idx].channel_points
                    if streamers[idx].channel_points is not None
                    else float("inf"),
                    order_map.get(idx, idx),
                ),
            )  # SUBSCRIBED: prefer channels with lowest channel points

        return []

    def _select_streamers_to_watch(self, streamers, streamers_index, priority):
        now = time.time()

        if priority and priority[0] != Priority.STREAK and (
            self._last_selection_was_streak or self._last_streak_selection
        ):
            self._last_selection_was_streak = False
            self._last_streak_selection = set()

        # If STREAK is the top priority, dedicate up to two streak sessions for short qualifying windows.
        if priority and priority[0] == Priority.STREAK:
            streak_selection = self._select_streak_streamers(streamers, streamers_index, priority, now)
            selection_names = {streamers[i].username for i in streak_selection}
            if selection_names != self._last_streak_selection:
                self._last_streak_selection = selection_names
            if streak_selection:
                self._last_selection_was_streak = True
                return streak_selection[: self.max_watch_amount]
            self._last_selection_was_streak = False
            start_index = 1
        else:
            start_index = 0

        remaining_priorities = priority[start_index:] if priority else []
        if not remaining_priorities:
            remaining_priorities = [Priority.ORDER]

        order_map = {idx: pos for pos, idx in enumerate(streamers_index)}
        sorted_candidates = sorted(
            streamers_index,
            key=lambda idx: self._priority_sort_key(
                streamers, idx, remaining_priorities, order_map, now
            ),
        )

        return sorted_candidates[: self.max_watch_amount]

    def _offline_gap_seconds(self, streamer) -> Optional[float]:
        if streamer.offline_at and streamer.online_at and streamer.online_at > streamer.offline_at:
            return streamer.online_at - streamer.offline_at
        return None

    def _resolve_broadcast_identity(self, streamer, now: float) -> tuple[str, float, bool]:
        broadcast_id = streamer.stream.broadcast_id
        started_at = streamer.online_at or now
        synthetic = False
        if broadcast_id is None:
            synthetic = True
            started_at = streamer.online_at or now
            started_iso = datetime.fromtimestamp(started_at, tz=timezone.utc).isoformat()
            broadcast_id = f"{streamer.username}:{started_iso}"
        return broadcast_id, started_at, synthetic

    def _ensure_watch_streak_session(self, streamer, now: float) -> Optional[WatchStreakSession]:
        if self.watch_streak_cache is None:
            return None
        broadcast_id, started_at, synthetic = self._resolve_broadcast_identity(streamer, now)
        offline_gap = self._offline_gap_seconds(streamer)
        latest_session = self.watch_streak_cache.latest_session_for_streamer(
            streamer.username, account_name=self.account_username
        )

        if synthetic and offline_gap is not None and offline_gap < MIN_OFFLINE_FOR_NEW_STREAK:
            if latest_session:
                broadcast_id = latest_session.broadcast_id
                started_at = latest_session.started_at

        if broadcast_id:
            self.watch_streak_cache.record_online(
                streamer.username,
                broadcast_id,
                streamer.online_at or now,
                account_name=self.account_username,
            )

        session = self.watch_streak_cache.get_session(
            streamer.username, broadcast_id, account_name=self.account_username
        )
        if session:
            return session

        if (
            latest_session
            and latest_session.broadcast_id == broadcast_id
            and offline_gap is not None
            and offline_gap < MIN_OFFLINE_FOR_NEW_STREAK
        ):
            return latest_session

        if not self.watch_streak_cache.should_create_session(
            streamer.username, account_name=self.account_username
        ):
            return None

        return self.watch_streak_cache.ensure_session(
            streamer.username,
            broadcast_id,
            started_at,
            account_name=self.account_username,
        )

    def _session_is_eligible(self, session: WatchStreakSession, streamer) -> bool:
        if session is None:
            return False
        if session.claimed or session.ended_at is not None:
            return False
        if session.attempts >= self.max_streak_attempts:
            return False
        if streamer.stream.watch_streak_missing is False:
            return False
        return True

    def _log_streak_start(self, session: WatchStreakSession):
        return

    def _log_streak_claimed(self, session: WatchStreakSession):
        return

    def _log_streak_failed(self, session: WatchStreakSession):
        return

    def _cleanup_streak_attempts(self, streamers, now: float):
        if self.watch_streak_cache is None:
            self._active_streak_attempts = {}
            return

        remaining: dict[str, ActiveWatchStreakAttempt] = {}
        for session_key, attempt in list(self._active_streak_attempts.items()):
            session = self.watch_streak_cache.get_session(
                attempt.streamer, attempt.broadcast_id, account_name=self.account_username
            )
            streamer_obj = next((s for s in streamers if s.username == attempt.streamer), None)

            if session is None or streamer_obj is None or streamer_obj.is_online is False:
                self.watch_streak_cache.mark_ended(
                    attempt.streamer,
                    attempt.broadcast_id,
                    ended_at=now,
                    account_name=self.account_username,
                )
                continue

            current_broadcast_id, _, _ = self._resolve_broadcast_identity(streamer_obj, now)
            if current_broadcast_id != attempt.broadcast_id:
                self.watch_streak_cache.mark_ended(
                    attempt.streamer,
                    attempt.broadcast_id,
                    ended_at=now,
                    account_name=self.account_username,
                )
                continue

            if session.claimed or streamer_obj.stream.watch_streak_missing is False:
                session = self.watch_streak_cache.mark_claimed(
                    attempt.streamer,
                    broadcast_id=attempt.broadcast_id,
                    now=now,
                    account_name=self.account_username,
                )
                self._log_streak_claimed(session)
                continue

            elapsed = now - attempt.started_at
            if elapsed < self.streak_watch_seconds:
                remaining[session_key] = attempt
                continue

            session = self.watch_streak_cache.mark_attempt(
                attempt.streamer,
                attempt.broadcast_id,
                now,
                account_name=self.account_username,
                max_attempts=self.max_streak_attempts,
            )

            if streamer_obj.stream.watch_streak_missing is False:
                session = self.watch_streak_cache.mark_claimed(
                    attempt.streamer,
                    broadcast_id=attempt.broadcast_id,
                    now=now,
                    account_name=self.account_username,
                )

            if session.claimed:
                self._log_streak_claimed(session)
                continue

            if session.attempts >= self.max_streak_attempts:
                self.watch_streak_cache.mark_ended(
                    attempt.streamer,
                    attempt.broadcast_id,
                    ended_at=now,
                    account_name=self.account_username,
                )
                self._log_streak_failed(session)
                continue

            # Attempt completed but session is still eligible; release the slot for another round later.
        self._active_streak_attempts = remaining

    def _select_streak_streamers(self, streamers, streamers_index, priority, now: float):
        self._cleanup_streak_attempts(streamers, now)

        active_selection: list[int] = []
        active_streamers = set()
        for attempt in self._active_streak_attempts.values():
            try:
                idx = next(i for i in streamers_index if streamers[i].username == attempt.streamer)
            except StopIteration:
                continue
            active_selection.append(idx)
            active_streamers.add(attempt.streamer)

        if len(active_selection) < self.max_streak_sessions:
            order_map = {idx: pos for pos, idx in enumerate(streamers_index)}
            streak_priorities = priority or [Priority.STREAK]
            candidates = []
            for idx in streamers_index:
                streamer = streamers[idx]
                session = self._ensure_watch_streak_session(streamer, now)
                if session is None or not self._session_is_eligible(session, streamer):
                    continue
                candidates.append(idx)

            sorted_candidates = sorted(
                candidates,
                key=lambda idx: self._priority_sort_key(
                    streamers, idx, streak_priorities, order_map, now
                ),
            )
            for idx in sorted_candidates:
                if len(active_selection) >= self.max_streak_sessions:
                    break
                streamer = streamers[idx]
                if streamer.username in active_streamers:
                    continue
                session = self._ensure_watch_streak_session(streamer, now)
                if session is None or not self._session_is_eligible(session, streamer):
                    continue
                attempt = ActiveWatchStreakAttempt(
                    session_key=session.key(),
                    streamer=streamer.username,
                    broadcast_id=session.broadcast_id,
                    started_at=now,
                )
                self._active_streak_attempts[session.key()] = attempt
                active_streamers.add(streamer.username)
                active_selection.append(idx)
                self._log_streak_start(session)

        return active_selection[: self.max_streak_sessions]

    def send_minute_watched_events(self, streamers, priority, chunk_size=3):
        while self.running:
            try:
                streamers_index = [
                    i
                    for i in range(0, len(streamers))
                    if streamers[i].is_online is True
                    and (
                        streamers[i].online_at == 0
                        or (time.time() - streamers[i].online_at) > 30
                    )
                ]

                for index in streamers_index:
                    if (streamers[index].stream.update_elapsed() / 60) > 10:
                        # Why this user It's currently online but the last updated was more than 10minutes ago?
                        # Please perform a manually update and check if the user it's online
                        self.check_streamer_online(streamers[index])

                """
                Normally we respect the 2-stream limit, but if any watch-streaks are pending
                we temporarily fan out (optionally capped by watch_streak_max_parallel)
                so each live streamer gets a shot.
                """
                streamers_watching = self._select_streamers_to_watch(
                    streamers, streamers_index, priority
                )

                drops_logging_enabled = Priority.DROPS in priority

                for index in streamers_watching:
                    # next_iteration = time.time() + 60 / len(streamers_watching)
                    next_iteration = time.time() + 20 / len(streamers_watching)

                    try:
                        ####################################
                        # Start of fix for 2024/5 API Change
                        # Create the JSON data for the GraphQL request
                        json_data = copy.deepcopy(
                            GQLOperations.PlaybackAccessToken)
                        json_data["variables"] = {
                            "login": streamers[index].username,
                            "isLive": True,
                            "isVod": False,
                            "vodID": "",
                            "playerType": "site"
                            # "playerType": "picture-by-picture",
                        }

                        # Get signature and value using the post_gql_request method
                        try:
                            responsePlaybackAccessToken = self.post_gql_request(
                                json_data)
                            logger.debug(
                                f"Sent PlaybackAccessToken request for {streamers[index]}")

                            if 'data' not in responsePlaybackAccessToken:
                                logger.error(
                                    f"Invalid response from Twitch: {responsePlaybackAccessToken}")
                                continue

                            streamPlaybackAccessToken = responsePlaybackAccessToken["data"].get(
                                'streamPlaybackAccessToken', {})
                            signature = streamPlaybackAccessToken.get(
                                "signature")
                            value = streamPlaybackAccessToken.get("value")

                            if not signature or not value:
                                logger.error(
                                    f"Missing signature or value in Twitch response: {responsePlaybackAccessToken}")
                                continue

                        except Exception as e:
                            logger.error(
                                f"Error fetching PlaybackAccessToken for {streamers[index]}: {str(e)}")
                            continue

                        # encoded_value = quote(json.dumps(value))

                        # Construct the URL for the broadcast qualities
                        RequestBroadcastQualitiesURL = f"https://usher.ttvnw.net/api/channel/hls/{streamers[index].username}.m3u8?sig={signature}&token={value}"

                        # Get list of video qualities
                        responseBroadcastQualities = requests.get(
                            RequestBroadcastQualitiesURL,
                            headers={"User-Agent": self.user_agent},
                            timeout=20,
                        )  # timeout=60
                        logger.debug(
                            f"Send RequestBroadcastQualitiesURL request for {streamers[index]} - Status code: {responseBroadcastQualities.status_code}"
                        )
                        if responseBroadcastQualities.status_code != 200:
                            continue
                        BroadcastQualities = responseBroadcastQualities.text

                        # Just takes the last line, which should be the URL for the lowest quality
                        BroadcastLowestQualityURL = BroadcastQualities.split(
                            "\n")[-1]
                        if not validators.url(BroadcastLowestQualityURL):
                            continue

                        # Get list of video URLs
                        responseStreamURLList = requests.get(
                            BroadcastLowestQualityURL,
                            headers={"User-Agent": self.user_agent},
                            timeout=20,
                        )  # timeout=60
                        logger.debug(
                            f"Send BroadcastLowestQualityURL request for {streamers[index]} - Status code: {responseStreamURLList.status_code}"
                        )
                        if responseStreamURLList.status_code != 200:
                            continue
                        StreamURLList = responseStreamURLList.text

                        # Just takes the last line, which should be the URL for the lowest quality
                        StreamLowestQualityURL = StreamURLList.split("\n")[-2]
                        if not validators.url(StreamLowestQualityURL):
                            continue

                        # Perform a HEAD request to simulate watching the stream
                        responseStreamLowestQualityURL = requests.head(
                            StreamLowestQualityURL,
                            headers={"User-Agent": self.user_agent},
                            timeout=20,
                        )  # timeout=60
                        logger.debug(
                            f"Send StreamLowestQualityURL request for {streamers[index]} - Status code: {responseStreamLowestQualityURL.status_code}"
                        )
                        if responseStreamLowestQualityURL.status_code != 200:
                            continue
                        # End of fix for 2024/5 API Change
                        ##################################
                        response = requests.post(
                            streamers[index].stream.spade_url,
                            data=streamers[index].stream.encode_payload(),
                            headers={"User-Agent": self.user_agent},
                            # timeout=60,
                            timeout=20,
                        )
                        logger.debug(
                            f"Send minute watched request for {streamers[index]} - Status code: {response.status_code}"
                        )
                        if response.status_code == 204:
                            streamers[index].stream.update_minute_watched()

                            """
                            Remember, you can only earn progress towards a time-based Drop on one participating channel at a time.  [ ! ! ! ]
                            You can also check your progress towards Drops within a campaign anytime by viewing the Drops Inventory.
                            For time-based Drops, if you are unable to claim the Drop in time, you will be able to claim it from the inventory page until the Drops campaign ends.
                            """

                            for campaign in streamers[index].stream.campaigns:
                                for drop in campaign.drops:
                                    self._log_drop_progress(streamers[index], drop, drops_logging_enabled)

                    except requests.exceptions.ConnectionError as e:
                        logger.error(
                            f"Error while trying to send minute watched: {e}")
                        self.__check_connection_handler(chunk_size)
                    except requests.exceptions.Timeout as e:
                        logger.error(
                            f"Error while trying to send minute watched: {e}")

                    self.__chuncked_sleep(
                        next_iteration - time.time(), chunk_size=chunk_size
                    )

                if streamers_watching == []:
                    # self.__chuncked_sleep(60, chunk_size=chunk_size)
                    self.__chuncked_sleep(20, chunk_size=chunk_size)
            except Exception:
                logger.error(
                    "Exception raised in send minute watched", exc_info=True)

    # === CHANNEL POINTS / PREDICTION === #
    # Load the amount of current points for a channel, check if a bonus is available
    def load_channel_points_context(self, streamer):
        json_data = copy.deepcopy(GQLOperations.ChannelPointsContext)
        json_data["variables"] = {"channelLogin": streamer.username}

        response = self.post_gql_request(json_data)
        if not response or self._log_gql_errors(json_data.get("operationName"), response):
            return
        try:
            channel = response["data"]["community"]["channel"]
        except (KeyError, TypeError):
            raise StreamerDoesNotExistException

        if channel is None:
            raise StreamerDoesNotExistException

        community_points = (
            channel.get("self", {}).get("communityPoints")
            if isinstance(channel, dict)
            else None
        )
        if community_points is None:
            return

        streamer.channel_points = community_points.get("balance", streamer.channel_points)
        streamer.activeMultipliers = community_points.get("activeMultipliers")
        streamer.subscription_tier = None
        try:
            self_info = channel.get("self", {}) if isinstance(channel, dict) else {}
            sub_benefit = (
                self_info.get("subscriptionBenefit")
                if isinstance(self_info, dict)
                else None
            )
            if isinstance(sub_benefit, dict):
                tier = sub_benefit.get("tier")
                if tier is not None:
                    streamer.subscription_tier = tier
            if streamer.subscription_tier is None and streamer.viewer_has_points_multiplier():
                streamer.subscription_tier = 1
        except Exception:
            pass

        if streamer.settings.community_goals is True:
            goals = channel.get("communityPointsSettings", {}).get("goals", [])
            streamer.community_goals = {
                goal["id"]: CommunityGoal.from_gql(goal)
                for goal in goals
                if isinstance(goal, dict) and "id" in goal
            }

        available_claim = community_points.get("availableClaim")
        if available_claim is not None and isinstance(available_claim, dict):
            self.claim_bonus(streamer, available_claim.get("id"))

        if streamer.settings.community_goals is True:
            self.contribute_to_community_goals(streamer)

    def initialize_streamers_context(self, streamers, max_workers=10):
        if not streamers:
            return set()

        failed_streamers = set()

        def _load_streamer_context(streamer):
            time.sleep(random.uniform(0.15, 0.35))
            self.load_channel_points_context(streamer)
            self.check_streamer_online(streamer)

        # Initialize channel context in parallel so large streamer lists do not block startup
        workers = max(1, min(max_workers, len(streamers)))
        timeout_seconds = STREAMER_INIT_TIMEOUT_PER_STREAMER * len(streamers)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_load_streamer_context, streamer): streamer
                for streamer in streamers
            }
            try:
                for future in as_completed(futures, timeout=timeout_seconds):
                    streamer = futures[future]
                    try:
                        future.result()
                    except StreamerDoesNotExistException:
                        failed_streamers.add(streamer.username)
                        logger.info(
                            f"Streamer {streamer.username} does not exist",
                            extra={"emoji": ":cry:"},
                        )
                    except Exception:
                        failed_streamers.add(streamer.username)
                        logger.error(
                            f"Failed to initialize streamer {streamer.username}",
                            exc_info=True,
                        )
            except TimeoutError:
                logger.error(
                    "Timed out while initializing streamers after %s seconds.",
                    timeout_seconds,
                )
                for future, streamer in futures.items():
                    if not future.done():
                        failed_streamers.add(streamer.username)
        return failed_streamers

    def make_predictions(self, event):
        decision = event.bet.calculate(event.streamer.channel_points)
        # selector_index = 0 if decision["choice"] == "A" else 1

        logger.info(
            f"Going to complete bet for {event}",
            extra={
                "emoji": ":four_leaf_clover:",
                "event": Events.BET_GENERAL,
            },
        )
        if event.status == "ACTIVE":
            skip, compared_value = event.bet.skip()
            if skip is True:
                logger.info(
                    f"Skip betting for the event {event}",
                    extra={
                        "emoji": ":pushpin:",
                        "event": Events.BET_FILTERS,
                    },
                )
                logger.info(
                    f"Skip settings {event.bet.settings.filter_condition}, current value is: {compared_value}",
                    extra={
                        "emoji": ":pushpin:",
                        "event": Events.BET_FILTERS,
                    },
                )
            else:
                if decision["amount"] >= 10:
                    logger.info(
                        # f"Place {_millify(decision['amount'])} channel points on: {event.bet.get_outcome(selector_index)}",
                        f"Place {_millify(decision['amount'])} channel points on: {event.bet.get_outcome(decision['choice'])}",
                        extra={
                            "emoji": ":four_leaf_clover:",
                            "event": Events.BET_GENERAL,
                        },
                    )

                    json_data = copy.deepcopy(GQLOperations.MakePrediction)
                    json_data["variables"] = {
                        "input": {
                            "eventID": event.event_id,
                            "outcomeID": decision["id"],
                            "points": decision["amount"],
                            "transactionID": token_hex(16),
                        }
                    }
                    response = self.post_gql_request(json_data)
                    if (
                        "data" in response
                        and "makePrediction" in response["data"]
                        and "error" in response["data"]["makePrediction"]
                        and response["data"]["makePrediction"]["error"] is not None
                    ):
                        error_code = response["data"]["makePrediction"]["error"]["code"]
                        logger.error(
                            f"Failed to place bet, error: {error_code}",
                            extra={
                                "emoji": ":four_leaf_clover:",
                                "event": Events.BET_FAILED,
                            },
                        )
                else:
                    logger.info(
                        f"Bet won't be placed as the amount {_millify(decision['amount'])} is less than the minimum required 10",
                        extra={
                            "emoji": ":four_leaf_clover:",
                            "event": Events.BET_GENERAL,
                        },
                    )
        else:
            logger.info(
                f"Oh no! The event is not active anymore! Current status: {event.status}",
                extra={
                    "emoji": ":disappointed_relieved:",
                    "event": Events.BET_FAILED,
                },
            )

    def claim_bonus(self, streamer, claim_id):
        if Settings.logger.less is False:
            logger.info(
                f"Claiming the bonus for {streamer}!",
                extra={"emoji": ":gift:", "event": Events.BONUS_CLAIM},
            )

        json_data = copy.deepcopy(GQLOperations.ClaimCommunityPoints)
        json_data["variables"] = {
            "input": {"channelID": streamer.channel_id, "claimID": claim_id}
        }
        self.post_gql_request(json_data)

    # === MOMENTS === #
    def claim_moment(self, streamer, moment_id):
        if Settings.logger.less is False:
            logger.info(
                f"Claiming the moment for {streamer}!",
                extra={"emoji": ":video_camera:",
                       "event": Events.MOMENT_CLAIM},
            )

        json_data = copy.deepcopy(GQLOperations.CommunityMomentCallout_Claim)
        json_data["variables"] = {"input": {"momentID": moment_id}}
        self.post_gql_request(json_data)

    # === CAMPAIGNS / DROPS / INVENTORY === #
    def __get_campaign_ids_from_streamer(self, streamer):
        json_data = copy.deepcopy(
            GQLOperations.DropsHighlightService_AvailableDrops)
        json_data["variables"] = {"channelID": streamer.channel_id}
        response = self.post_gql_request(json_data)
        if self._log_gql_errors(json_data.get("operationName"), response):
            return []
        channel = (
            response.get("data", {}).get("channel", {})
            if isinstance(response, dict)
            else {}
        )
        campaigns = (
            channel.get("viewerDropCampaigns") if isinstance(channel, dict) else None
        )
        if not campaigns:
            return []
        ids = []
        for item in campaigns:
            if isinstance(item, dict) and "id" in item:
                ids.append(item["id"])
        return ids

    def __get_inventory(self):
        json_data = GQLOperations.Inventory
        response = self.post_gql_request(json_data)
        if self._log_gql_errors(json_data.get("operationName"), response):
            return {}
        if not isinstance(response, dict):
            return {}
        return (
            response.get("data", {})
            .get("currentUser", {})
            .get("inventory", {})
            or {}
        )

    def __get_drops_dashboard(self, status=None):
        json_data = GQLOperations.ViewerDropsDashboard
        response = self.post_gql_request(json_data)
        if self._log_gql_errors(json_data.get("operationName"), response):
            return []
        campaigns = (
            response.get("data", {})
            .get("currentUser", {})
            .get("dropCampaigns", [])
            if isinstance(response, dict)
            else []
        ) or []

        if status is not None:
            campaigns = (
                list(filter(lambda x: x["status"] == status.upper(), campaigns)) or []
            )

        return campaigns

    def __get_campaigns_details(self, campaigns):
        result = []
        chunks = create_chunks(campaigns, 20)
        for chunk in chunks:
            json_data = []
            for campaign in chunk:
                json_data.append(copy.deepcopy(
                    GQLOperations.DropCampaignDetails))
                json_data[-1]["variables"] = {
                    "dropID": campaign["id"],
                    "channelLogin": f"{self.twitch_login.get_user_id()}",
                }

            response = self.post_gql_request(json_data)
            if not isinstance(response, list):
                logger.debug("Unexpected campaigns response format, skipping chunk")
                continue
            operation_name = (
                json_data[0].get("operationName") if json_data else "DropCampaignDetails"
            )
            for r in response:
                if self._log_gql_errors(operation_name, r):
                    continue
                drop_campaign = (
                    r.get("data", {}).get("user", {}).get("dropCampaign", None)
                    if isinstance(r, dict)
                    else None
                )
                if drop_campaign is not None:
                    result.append(drop_campaign)
        return result

    def __sync_campaigns(self, campaigns):
        # We need the inventory only for get the real updated value/progress
        logger.debug("Fetching drop inventory for sync")
        inventory = self.__get_inventory()
        if not isinstance(inventory, dict):
            return campaigns
        campaigns_in_progress = inventory.get("dropCampaignsInProgress") or []
        if not campaigns_in_progress:
            return campaigns

        for i in range(len(campaigns)):
            for progress in campaigns_in_progress:
                if progress.get("id") != campaigns[i].id:
                    continue
                campaigns[i].in_inventory = True
                time_based = progress.get("timeBasedDrops") or []
                campaigns[i].sync_drops(time_based, self.claim_drop)
                logger.debug(
                    "Updated drop progress for campaign %s with %d timeBasedDrops",
                    campaigns[i].id,
                    len(time_based),
                )
                campaigns[i].clear_drops()  # Clean up claimed/expired after sync
                break
        return campaigns

    def claim_drop(self, drop):
        logger.info(
            f"Claim {drop}", extra={"emoji": ":package:", "event": Events.DROP_CLAIM}
        )

        json_data = copy.deepcopy(GQLOperations.DropsPage_ClaimDropRewards)
        json_data["variables"] = {
            "input": {"dropInstanceID": drop.drop_instance_id}}
        response = self.post_gql_request(json_data)
        if self._log_gql_errors(json_data.get("operationName"), response):
            return False
        data = response.get("data", {}) if isinstance(response, dict) else {}
        claim_result = data.get("claimDropRewards") if isinstance(data, dict) else None
        if claim_result is None:
            return False
        status = claim_result.get("status") if isinstance(claim_result, dict) else None
        return status in ["ELIGIBLE_FOR_ALL", "DROP_INSTANCE_ALREADY_CLAIMED"]

    def claim_all_drops_from_inventory(self):
        inventory = self.__get_inventory()
        if inventory not in [None, {}]:
            if inventory["dropCampaignsInProgress"] not in [None, {}]:
                for campaign in inventory["dropCampaignsInProgress"]:
                    for drop_dict in campaign["timeBasedDrops"]:
                        drop = Drop(drop_dict)
                        drop.update(drop_dict["self"])
                        if drop.is_claimable is True:
                            drop.is_claimed = self.claim_drop(drop)
                            time.sleep(random.uniform(5, 10))

    def __streamers_require_campaign_sync(self, streamers):
        # Run drop sync whenever at least one online streamer has drops enabled,
        # even if campaign details are not yet loaded (avoid chicken-and-egg).
        return any(
            streamer.settings.claim_drops is True and streamer.is_online is True
            for streamer in streamers
        )

    def sync_campaigns(self, streamers, chunk_size=3):
        campaigns_update = 0
        campaigns = []
        while self.running:
            try:
                # Skip the expensive dashboard sync loop when no streamer can currently farm drops
                if not self.__streamers_require_campaign_sync(streamers):
                    campaigns = []
                    self.__chuncked_sleep(60, chunk_size=chunk_size)
                    continue
                # Get update from dashboard each 60minutes
                if (
                    campaigns_update == 0
                    # or ((time.time() - campaigns_update) / 60) > 60
                    # TEMPORARY AUTO DROP CLAIMING FIX
                    # 30 minutes instead of 60 minutes
                    or ((time.time() - campaigns_update) / 30) > 30
                    #####################################
                ):
                    campaigns_update = time.time()

                    # TEMPORARY AUTO DROP CLAIMING FIX
                    self.claim_all_drops_from_inventory()
                    #####################################

                    # Get full details from current ACTIVE campaigns
                    # Use dashboard so we can explore new drops not currently active in our Inventory
                    campaigns_details = self.__get_campaigns_details(
                        self.__get_drops_dashboard(status="ACTIVE")
                    )
                    campaigns = []

                    # Going to clear array and structure. Remove all the timeBasedDrops expired or not started yet
                    for index in range(0, len(campaigns_details)):
                        if campaigns_details[index] is not None:
                            campaign = Campaign(campaigns_details[index])
                            if campaign.dt_match is True:
                                # Remove all the drops already claimed or with dt not matching
                                campaign.clear_drops()
                                if campaign.drops != []:
                                    campaigns.append(campaign)
                        else:
                            continue

                # Divide et impera :)
                campaigns = self.__sync_campaigns(campaigns)

                # Check if user It's currently streaming the same game present in campaigns_details
                for i in range(0, len(streamers)):
                    if streamers[i].drops_condition() is True:
                        # yes! The streamer[i] have the drops_tags enabled and we It's currently stream a game with campaign active!
                        # With 'campaigns_ids' we are also sure that this streamer have the campaign active.
                        # yes! The streamer[index] have the drops_tags enabled and we It's currently stream a game with campaign active!
                        streamers[i].stream.campaigns = list(
                            filter(
                                lambda x: x.drops != []
                                and x.game == streamers[i].stream.game
                                and x.id in streamers[i].stream.campaigns_ids,
                                campaigns,
                            )
                        )

            except (ValueError, KeyError, requests.exceptions.ConnectionError) as e:
                logger.error(f"Error while syncing inventory: {e}")
                campaigns = []
                self.__check_connection_handler(chunk_size)

            self.__chuncked_sleep(60, chunk_size=chunk_size)

    def contribute_to_community_goals(self, streamer):
        # Don't bother doing the request if no goal is currently started or in stock
        if any(
            goal.status == "STARTED" and goal.is_in_stock
            for goal in streamer.community_goals.values()
        ):
            json_data = copy.deepcopy(GQLOperations.UserPointsContribution)
            json_data["variables"] = {"channelLogin": streamer.username}
            response = self.post_gql_request(json_data)
            if self._log_gql_errors(json_data.get("operationName"), response):
                return
            data = response.get("data", {}) if isinstance(response, dict) else {}
            user_goal_contributions = (
                data.get("user", {})
                .get("channel", {})
                .get("self", {})
                .get("communityPoints", {})
                .get("goalContributions", [])
            )
            if not user_goal_contributions:
                return

            logger.debug(
                f"Found {len(user_goal_contributions)} community goals for the current stream"
            )

            for goal_contribution in user_goal_contributions:
                goal_id = goal_contribution["goal"]["id"]
                goal = streamer.community_goals[goal_id]
                if goal is None:
                    # TODO should this trigger a new load context request
                    logger.error(
                        f"Unable to find context data for community goal {goal_id}"
                    )
                else:
                    user_stream_contribution = goal_contribution[
                        "userPointsContributedThisStream"
                    ]
                    user_left_to_contribute = (
                        goal.per_stream_user_maximum_contribution
                        - user_stream_contribution
                    )
                    amount = min(
                        goal.amount_left(),
                        user_left_to_contribute,
                        streamer.channel_points,
                    )
                    if amount > 0:
                        self.contribute_to_community_goal(
                            streamer, goal_id, goal.title, amount
                        )
                    else:
                        logger.debug(
                            f"Not contributing to community goal {goal.title}, user channel points {streamer.channel_points}, user stream contribution {user_stream_contribution}, all users total contribution {goal.points_contributed}"
                        )

    def contribute_to_community_goal(self, streamer, goal_id, title, amount):
        json_data = copy.deepcopy(
            GQLOperations.ContributeCommunityPointsCommunityGoal)
        json_data["variables"] = {
            "input": {
                "amount": amount,
                "channelID": streamer.channel_id,
                "goalID": goal_id,
                "transactionID": token_hex(16),
            }
        }

        response = self.post_gql_request(json_data)
        if self._log_gql_errors(json_data.get("operationName"), response):
            return

        contribution = (
            response.get("data", {}).get("contributeCommunityPointsCommunityGoal", {})
            if isinstance(response, dict)
            else {}
        )
        error = contribution.get("error") if isinstance(contribution, dict) else None
        if error:
            logger.error(
                f"Unable to contribute channel points to community goal '{title}', reason '{error}'"
            )
            return

        logger.info(f"Contributed {amount} channel points to community goal '{title}'")
        streamer.channel_points -= amount


def _self_check_priority_selection():
    from TwitchChannelPointsMiner.classes.entities.Streamer import (
        Streamer,
        StreamerSettings,
    )
    from TwitchChannelPointsMiner.watch_streak_cache import WatchStreakCache

    twitch = Twitch("self-check", "ua")
    twitch.watch_streak_cache = WatchStreakCache(default_account_name="self-check")
    priorities = [Priority.STREAK, Priority.SUBSCRIBED, Priority.POINTS_ASCENDING]

    def make_streamer(name, points, subscribed=False, watch_streak=True):
        settings = StreamerSettings(
            watch_streak=watch_streak,
            claim_drops=False,
            claim_moments=False,
            make_predictions=False,
            follow_raid=False,
            community_goals=False,
        )
        streamer = Streamer(name, settings=settings)
        streamer.channel_points = points
        streamer.activeMultipliers = [{"factor": 2.0}] if subscribed else None
        streamer.stream.watch_streak_missing = watch_streak
        return streamer

    streamers = [
        make_streamer("subscribed_low", 10, subscribed=True, watch_streak=True),
        make_streamer("other_low", 100, watch_streak=False),
        make_streamer("other_high", 200, watch_streak=False),
    ]
    streamers_index = list(range(len(streamers)))
    selection = twitch._select_streamers_to_watch(
        streamers, streamers_index, priorities
    )
    assert len(selection) == 2, "Expected two watch slots to be filled"
    assert (
        streamers[selection[0]].username == "subscribed_low"
    ), "Subscribed lowest-points streamer should take slot 1"
    assert (
        streamers[selection[1]].username == "other_low"
    ), "Next best by points should take slot 2"
    print("Priority selection self-check passed.")


if __name__ == "__main__":
    _self_check_priority_selection()
