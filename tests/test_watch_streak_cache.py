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


if __name__ == "__main__":
    unittest.main()
