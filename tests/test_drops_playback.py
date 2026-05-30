import unittest
from types import SimpleNamespace
from unittest.mock import patch

from TwitchChannelPointsMiner.classes.Settings import Settings
from TwitchChannelPointsMiner.classes.entities.Streamer import (
    PlaybackSimulationMode,
    Streamer,
    StreamerSettings,
)
from TwitchChannelPointsMiner.classes.Twitch import Twitch
from TwitchChannelPointsMiner.constants import GQLOperations


class DropsPlaybackTest(unittest.TestCase):
    def setUp(self):
        Settings.logger = SimpleNamespace(less=False)
        self.twitch = Twitch("drops-playback-test", "ua")

    def _streamer(
        self,
        *,
        claim_drops=True,
        playback_simulation=PlaybackSimulationMode.EXCEPT_DROPS,
    ):
        return Streamer(
            "TestChannel",
            settings=StreamerSettings(
                claim_drops=claim_drops,
                watch_streak=False,
                playback_simulation=playback_simulation,
            ),
        )

    def test_updated_drop_hashes_are_present(self):
        expected_hashes = {
            "VideoPlayerStreamInfoOverlayChannel": "e785b65ff71ad7b363b34878335f27dd9372869ad0c5740a130b9268bcdbe7e7",
            "ChannelPointsContext": "7fe050e3761eb2cf258d70ee1a21cbd76fa8cf3d7e7b12fc437e7029d446b5e3",
            "Inventory": "8337eb8541b314040b0edde0c09c5c7a2783ba1960aa9edfbf3bac16d0fec404",
            "ViewerDropsDashboard": "d9cae7761dafab85908c85e6683cb4201b449e66ac3bb5e894f15ff12aeafaa7",
            "DropCampaignDetails": "039277bf98f3130929262cc7c6efd9c141ca3749cb6dca442fc8ead9a53f77c1",
            "DropsHighlightService_AvailableDrops": "782dad0f032942260171d2d80a654f88bdd0c5a9dddc392e9bc92218a0f42d20",
        }

        for operation_name, expected_hash in expected_hashes.items():
            operation = getattr(GQLOperations, operation_name)
            actual_hash = operation["extensions"]["persistedQuery"]["sha256Hash"]
            self.assertEqual(actual_hash, expected_hash)

    def test_except_drops_skips_m3u8_when_drops_are_active(self):
        streamer = self._streamer()
        streamer.stream.campaigns_ids = ["campaign-id"]

        self.assertFalse(self.twitch._should_prime_stream_playback(streamer))

    def test_except_drops_keeps_m3u8_when_no_drops_are_active(self):
        streamer = self._streamer()

        self.assertTrue(self.twitch._should_prime_stream_playback(streamer))

    def test_except_drops_keeps_m3u8_for_drops_tag_without_active_campaign(self):
        streamer = self._streamer()
        streamer.stream.drops_tags = True

        self.assertTrue(self.twitch._should_prime_stream_playback(streamer))

    def test_always_preserves_current_m3u8_behavior_for_drops_streams(self):
        streamer = self._streamer(playback_simulation=PlaybackSimulationMode.ALWAYS)
        streamer.stream.campaigns_ids = ["campaign-id"]

        self.assertTrue(self.twitch._should_prime_stream_playback(streamer))

    def test_minute_payload_includes_game_when_claim_drops_is_false(self):
        streamer = self._streamer(claim_drops=False)
        stream_info = {
            "stream": {
                "id": "broadcast-id",
                "tags": [],
                "viewersCount": 1,
            },
            "broadcastSettings": {
                "title": "Testing Drops",
                "game": {
                    "id": "491931",
                    "name": "Escape from Tarkov",
                    "displayName": "Escape from Tarkov",
                },
            },
        }

        with patch.object(Twitch, "get_stream_info", return_value=stream_info):
            with patch.object(
                type(self.twitch.twitch_login), "get_user_id", return_value="user-id"
            ):
                self.assertTrue(self.twitch.update_stream(streamer))

        properties = streamer.stream.payload[0]["properties"]
        self.assertEqual(properties["game"], "Escape from Tarkov")
        self.assertEqual(properties["game_id"], "491931")
        self.assertEqual(streamer.stream.campaigns_ids, [])

    def test_inventory_claiming_tolerates_missing_campaigns(self):
        inventories = [{}, {"dropCampaignsInProgress": None}, {"unexpected": []}]
        for inventory in inventories:
            with self.subTest(inventory=inventory):
                with patch.object(Twitch, "_Twitch__get_inventory", return_value=inventory):
                    self.twitch.claim_all_drops_from_inventory()

    def test_claim_drop_skips_missing_drop_instance_id(self):
        drop = SimpleNamespace(drop_instance_id=None)

        with patch.object(Twitch, "post_gql_request") as mocked_post:
            self.assertFalse(self.twitch.claim_drop(drop))

        mocked_post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
