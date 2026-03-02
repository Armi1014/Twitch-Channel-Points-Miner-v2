import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from TwitchChannelPointsMiner.WatchStreakCache import WatchStreakCache
from TwitchChannelPointsMiner.classes.Settings import Priority
from TwitchChannelPointsMiner.classes.Settings import Settings
from TwitchChannelPointsMiner.classes.Twitch import ActiveWatchStreakAttempt, Twitch
from TwitchChannelPointsMiner.classes.entities.Streamer import Streamer, StreamerSettings


class WatchStreakMilestoneTest(unittest.TestCase):
    def _make_streamer(self, username: str) -> Streamer:
        settings = StreamerSettings(
            watch_streak=True,
            claim_drops=False,
            claim_moments=False,
            make_predictions=False,
            follow_raid=False,
            community_goals=False,
        )
        streamer = Streamer(username, settings=settings)
        streamer.channel_id = "123456"
        return streamer

    def test_extract_stream_created_timestamp_handles_null_nodes(self):
        twitch = Twitch("stream-created-null", "ua")
        self.assertIsNone(twitch._extract_stream_created_timestamp({"data": {"user": None}}))
        self.assertIsNone(
            twitch._extract_stream_created_timestamp(
                {"data": {"user": {"stream": None}}}
            )
        )

    def test_get_stream_info_marks_streak_complete_from_milestone_timestamp(self):
        twitch = Twitch("milestone-test", "ua")
        streamer = self._make_streamer("streamer")

        responses = {
            "VideoPlayerStreamInfoOverlayChannel": {
                "data": {
                    "user": {
                        "stream": {
                            "id": "broadcast-1",
                            "tags": [],
                            "viewersCount": 42,
                        },
                        "broadcastSettings": {"title": "title", "game": {}},
                    }
                }
            },
            "WithIsStreamLiveQuery": {
                "data": {
                    "user": {
                        "stream": {
                            "id": "broadcast-1",
                            "createdAt": "2026-03-01T10:00:00Z",
                        }
                    }
                }
            },
            "RewardList": {
                "data": {
                    "channel": {
                        "self": {
                            "watchStreakMilestone": {
                                "watchStreakMilestone": {
                                    "achievementTimestamp": "2026-03-01T10:06:00Z"
                                }
                            }
                        }
                    }
                }
            },
        }

        def fake_post(json_data):
            return responses.get(json_data.get("operationName"), {})

        with patch.object(Twitch, "post_gql_request", side_effect=fake_post):
            stream_info = twitch.get_stream_info(streamer)

        self.assertIsNotNone(stream_info)
        self.assertIn("createdAt", stream_info["stream"])
        self.assertFalse(stream_info.get("watchStreakMissing", True))

    def test_get_stream_info_handles_null_reward_list_channel_without_crashing(self):
        twitch = Twitch("milestone-null-channel", "ua")
        streamer = self._make_streamer("streamer")

        responses = {
            "VideoPlayerStreamInfoOverlayChannel": {
                "data": {
                    "user": {
                        "stream": {
                            "id": "broadcast-null-1",
                            "tags": [],
                            "viewersCount": 12,
                        },
                        "broadcastSettings": {"title": "title", "game": {}},
                    }
                }
            },
            "WithIsStreamLiveQuery": {
                "data": {
                    "user": {
                        "stream": {
                            "id": "broadcast-null-1",
                            "createdAt": "2026-03-01T10:00:00Z",
                        }
                    }
                }
            },
            "RewardList": {
                "data": {
                    "channel": None,
                }
            },
        }

        def fake_post(json_data):
            return responses.get(json_data.get("operationName"), {})

        with patch.object(Twitch, "post_gql_request", side_effect=fake_post):
            stream_info = twitch.get_stream_info(streamer)

        self.assertIsNotNone(stream_info)
        self.assertNotIn("watchStreakMissing", stream_info)

    def test_update_stream_marks_cache_claimed_when_milestone_indicates_completed(self):
        twitch = Twitch("milestone-claim", "ua")
        twitch.watch_streak_cache = WatchStreakCache(default_account_name="milestone-claim")
        streamer = self._make_streamer("streamer")
        Settings.logger = SimpleNamespace(less=True)

        responses = {
            "VideoPlayerStreamInfoOverlayChannel": {
                "data": {
                    "user": {
                        "stream": {
                            "id": "broadcast-claim-1",
                            "tags": [],
                            "viewersCount": 21,
                        },
                        "broadcastSettings": {"title": "title", "game": {}},
                    }
                }
            },
            "WithIsStreamLiveQuery": {
                "data": {
                    "user": {
                        "stream": {
                            "id": "broadcast-claim-1",
                            "createdAt": "2026-03-01T10:00:00Z",
                        }
                    }
                }
            },
            "RewardList": {
                "data": {
                    "channel": {
                        "self": {
                            "watchStreakMilestone": {
                                "watchStreakMilestone": {
                                    "achievementTimestamp": "2026-03-01T10:07:00Z"
                                }
                            }
                        }
                    }
                }
            },
        }

        def fake_post(json_data):
            return responses.get(json_data.get("operationName"), {})

        with patch.object(Twitch, "post_gql_request", side_effect=fake_post):
            updated = twitch.update_stream(streamer)

        self.assertTrue(updated)
        session = twitch.watch_streak_cache.get_session(
            streamer.username,
            "broadcast-claim-1",
            account_name=twitch.account_username,
        )
        self.assertIsNotNone(session)
        self.assertTrue(session.claimed)
        self.assertFalse(streamer.stream.watch_streak_missing)

    def test_cleanup_ends_attempt_after_two_watch_events(self):
        twitch = Twitch("watch-events-test", "ua")
        twitch.watch_streak_cache = WatchStreakCache(default_account_name="watch-events-test")
        streamer = self._make_streamer("streamer")
        streamer.is_online = True
        streamer.online_at = time.time() - 60
        streamer.stream.broadcast_id = "broadcast-2"
        streamer.stream.watch_streak_missing = True
        streamer.history["WATCH"] = {"counter": 2, "amount": 20}

        now = time.time()
        session = twitch.watch_streak_cache.ensure_session(
            streamer.username,
            streamer.stream.broadcast_id,
            started_at=now - 60,
            account_name=twitch.account_username,
        )
        twitch._active_streak_attempts[session.key()] = ActiveWatchStreakAttempt(
            session_key=session.key(),
            streamer=streamer.username,
            broadcast_id=streamer.stream.broadcast_id,
            started_at=now - 30,
            watch_counter_at_start=0,
        )

        twitch._cleanup_streak_attempts([streamer], now)

        self.assertFalse(streamer.stream.watch_streak_missing)
        self.assertEqual(twitch._active_streak_attempts, {})
        updated = twitch.watch_streak_cache.get_session(
            streamer.username,
            streamer.stream.broadcast_id,
            account_name=twitch.account_username,
        )
        self.assertIsNotNone(updated)
        self.assertIsNotNone(updated.ended_at)

    def test_streak_selection_rotates_candidates_when_many_are_eligible(self):
        twitch = Twitch("rotation-test", "ua")
        twitch.watch_streak_cache = WatchStreakCache(default_account_name="rotation-test")
        twitch.max_streak_sessions = 2
        twitch.max_watch_amount = 2

        now = time.time()
        streamers = []
        for i in range(4):
            streamer = self._make_streamer(f"streamer{i}")
            streamer.is_online = True
            streamer.online_at = now - 120
            streamer.stream.broadcast_id = f"broadcast-{i}"
            streamer.stream.watch_streak_missing = True
            twitch.watch_streak_cache.ensure_session(
                streamer.username,
                streamer.stream.broadcast_id,
                started_at=now - 120,
                account_name=twitch.account_username,
            )
            streamers.append(streamer)

        first = twitch._select_streak_streamers(
            streamers,
            list(range(len(streamers))),
            [Priority.STREAK],
            now,
        )
        twitch._active_streak_attempts = {}
        second = twitch._select_streak_streamers(
            streamers,
            list(range(len(streamers))),
            [Priority.STREAK],
            now + 1,
        )

        first_names = [streamers[i].username for i in first]
        second_names = [streamers[i].username for i in second]
        self.assertEqual(len(first_names), 2)
        self.assertEqual(len(second_names), 2)
        self.assertNotEqual(first_names, second_names)
        self.assertGreaterEqual(len(set(first_names + second_names)), 3)

    def test_streak_selection_bootstrap_creates_session_for_online_streamer(self):
        twitch = Twitch("startup-probe-test", "ua")
        twitch.watch_streak_cache = WatchStreakCache(default_account_name="startup-probe-test")
        twitch.watch_streak_cache.mark_bootstrap_done()
        twitch.max_streak_sessions = 1
        twitch.max_watch_amount = 1

        now = time.time()
        streamer = self._make_streamer("streamer")
        streamer.is_online = True
        streamer.online_at = now - 1200
        streamer.stream.broadcast_id = "startup-broadcast-1"
        streamer.stream.created_at = now - 1200
        streamer.stream.watch_streak_missing = True

        selection = twitch._select_streak_streamers(
            [streamer],
            [0],
            [Priority.STREAK],
            now,
        )

        self.assertEqual(selection, [0])
        session = twitch.watch_streak_cache.get_session(
            streamer.username,
            streamer.stream.broadcast_id,
            account_name=twitch.account_username,
        )
        self.assertIsNotNone(session)
        self.assertFalse(session.claimed)
        self.assertIsNone(session.ended_at)


if __name__ == "__main__":
    unittest.main()
