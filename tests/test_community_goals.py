import json
import unittest
from unittest.mock import Mock

from TwitchChannelPointsMiner.classes.PubSub import PubSubHandler
from TwitchChannelPointsMiner.classes.entities.Message import Message
from TwitchChannelPointsMiner.classes.entities.Streamer import Streamer


class CommunityGoalsTest(unittest.TestCase):
    def test_community_goal_created_adds_goal_and_contributes(self):
        streamer = Streamer("sam")
        streamer.channel_id = "1067547221"
        twitch = Mock()
        handler = PubSubHandler(twitch=twitch, streamers=[streamer], events_predictions={})
        message = Message(
            {
                "topic": "community-points-channel-v1.1067547221",
                "message": json.dumps(
                    {
                        "type": "community-goal-created",
                        "data": {
                            "timestamp": "2026-06-15T18:04:52.377964154Z",
                            "channel_id": "1067547221",
                            "community_goal": {
                                "id": "goal-id",
                                "title": "SAM BEWEG DICH",
                                "is_in_stock": False,
                                "points_contributed": 0,
                                "goal_amount": 9000,
                                "per_stream_maximum_user_contribution": 2000,
                                "status": "UNSTARTED",
                            },
                        },
                    }
                ),
            }
        )

        handler.on_message(message)

        self.assertIn("goal-id", streamer.community_goals)
        self.assertEqual(streamer.community_goals["goal-id"].title, "SAM BEWEG DICH")
        twitch.contribute_to_community_goals.assert_called_once_with(streamer)

    def test_delete_unknown_community_goal_is_safe(self):
        streamer = Streamer("sam")

        streamer.delete_community_goal("missing")

        self.assertEqual(streamer.community_goals, {})


if __name__ == "__main__":
    unittest.main()
