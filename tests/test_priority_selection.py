import unittest

from TwitchChannelPointsMiner.WatchStreakCache import WatchStreakCache
from TwitchChannelPointsMiner.classes.Settings import Priority
from TwitchChannelPointsMiner.classes.Twitch import Twitch
from TwitchChannelPointsMiner.classes.entities.Streamer import Streamer, StreamerSettings


class PrioritySelectionTest(unittest.TestCase):
    def test_subscribed_lowest_points_takes_first_slot(self):
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

        self.assertEqual(len(selection), 2)
        self.assertEqual(streamers[selection[0]].username, "subscribed_low")
        self.assertEqual(streamers[selection[1]].username, "other_low")


if __name__ == "__main__":
    unittest.main()
