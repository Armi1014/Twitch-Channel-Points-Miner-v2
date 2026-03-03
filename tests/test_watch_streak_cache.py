import json
import os
import tempfile
import time
import unittest

from TwitchChannelPointsMiner.WatchStreakCache import (
    MIN_OFFLINE_FOR_NEW_STREAK,
    STALE_SESSION_TTL_SECONDS,
    WatchStreakCache,
)


class WatchStreakCacheTest(unittest.TestCase):
    def test_cache_session_lifecycle_and_prune(self):
        now = time.time()
        cache = WatchStreakCache(default_account_name="tester")

        session = cache.ensure_session("streamer", "broadcastA", now)
        self.assertEqual(session.attempts, 0)

        cache.mark_attempt("streamer", "broadcastA", now + 10)
        self.assertEqual(cache.get_session("streamer", "broadcastA").attempts, 1)

        cache.mark_claimed("streamer", "broadcastA", now + 20)
        claimed_session = cache.get_session("streamer", "broadcastA")
        self.assertTrue(claimed_session.claimed)
        self.assertIsNotNone(claimed_session.ended_at)

        cache.record_online("streamer", "broadcastA", now + 30)
        self.assertFalse(cache.should_create_session("streamer"))

        cache.record_offline("streamer", now + 60)
        cache.mark_bootstrap_done()
        cache.record_online(
            "streamer",
            "broadcastB",
            now + 60 + MIN_OFFLINE_FOR_NEW_STREAK + 5,
        )
        self.assertTrue(cache.should_create_session("streamer"))

        # Session ended at now + 20 above, so prune after ttl + margin from that point.
        cache._prune_stale_sessions(now + STALE_SESSION_TTL_SECONDS + 60)
        self.assertIsNone(cache.get_session("streamer", "broadcastA"))

    def test_load_from_disk_can_filter_by_account(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "watch_streak_cache.json")
            payload = {
                "version": 2,
                "sessions": [
                    {
                        "account_name": "acc_one",
                        "streamer_login": "streamer-a",
                        "broadcast_id": "b1",
                        "started_at": 1,
                        "attempts": 0,
                        "claimed": False,
                        "last_attempt_at": None,
                        "ended_at": None,
                    },
                    {
                        "account_name": "acc_two",
                        "streamer_login": "streamer-b",
                        "broadcast_id": "b2",
                        "started_at": 2,
                        "attempts": 0,
                        "claimed": False,
                        "last_attempt_at": None,
                        "ended_at": None,
                    },
                ],
            }
            with open(path, "w", encoding="utf-8") as file_obj:
                json.dump(payload, file_obj)

            cache = WatchStreakCache.load_from_disk(
                path,
                default_account_name="acc_one",
                account_filter="acc_one",
            )
            self.assertIsNotNone(cache.get_session("streamer-a", "b1"))
            self.assertIsNone(cache.get_session("streamer-b", "b2", account_name="acc_two"))

    def test_short_offline_gap_does_not_create_session_even_if_broadcast_changes(self):
        now = time.time()
        cache = WatchStreakCache(default_account_name="tester")
        cache.mark_bootstrap_done()

        cache.record_online("streamer", "broadcastA", now)
        cache.record_offline("streamer", now + 5)
        cache.record_online("streamer", "broadcastB", now + 120)

        self.assertFalse(cache.should_create_session("streamer"))

    def test_long_offline_gap_creates_session_when_broadcast_changes(self):
        now = time.time()
        cache = WatchStreakCache(default_account_name="tester")
        cache.mark_bootstrap_done()

        cache.record_online("streamer", "broadcastA", now)
        cache.record_offline("streamer", now + 5)
        cache.record_online(
            "streamer",
            "broadcastB",
            now + 5 + MIN_OFFLINE_FOR_NEW_STREAK + 1,
        )

        self.assertTrue(cache.should_create_session("streamer"))

    def test_bootstrap_online_streamer_can_create_initial_session_without_offline_gap(self):
        now = time.time()
        cache = WatchStreakCache(default_account_name="tester")

        cache.record_online("streamer", "broadcastA", now)
        self.assertFalse(cache.should_create_session("streamer"))

        cache.mark_bootstrap_done()
        self.assertTrue(cache.should_create_session("streamer"))

    def test_custom_min_offline_gap_allows_immediate_new_session(self):
        now = time.time()
        cache = WatchStreakCache(
            default_account_name="tester", min_offline_for_new_streak=0
        )
        cache.mark_bootstrap_done()

        cache.record_online("streamer", "broadcastA", now)
        cache.record_offline("streamer", now + 5)
        cache.record_online("streamer", "broadcastB", now + 20)

        self.assertTrue(cache.should_create_session("streamer"))


if __name__ == "__main__":
    unittest.main()
