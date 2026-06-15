import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from TwitchChannelPointsMiner.classes.Settings import Priority
from TwitchChannelPointsMiner.classes.Settings import Settings
from TwitchChannelPointsMiner.classes.entities.Streamer import (
    PlaybackSimulationMode,
    Streamer,
    StreamerSettings,
)
from TwitchChannelPointsMiner.classes.Twitch import Twitch
from TwitchChannelPointsMiner.constants import GQLOperations


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


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

    def _drop_dict(self, *, progress=None):
        return {
            "id": "drop-id",
            "name": "Test Drop",
            "benefitEdges": [{"benefit": {"name": "Test Benefit"}}],
            "requiredMinutesWatched": 60,
            "endAt": "2099-01-01T00:00:00Z",
            "startAt": "2026-01-01T00:00:00Z",
            "self": progress or {},
        }

    def _farmable_drop(self):
        return SimpleNamespace(
            is_claimed=False,
            dt_match=True,
            requires_subscription=False,
        )

    def test_updated_drop_hashes_are_present(self):
        expected_hashes = {
            "VideoPlayerStreamInfoOverlayChannel": "e785b65ff71ad7b363b34878335f27dd9372869ad0c5740a130b9268bcdbe7e7",
            "ChannelPointsContext": "7fe050e3761eb2cf258d70ee1a21cbd76fa8cf3d7e7b12fc437e7029d446b5e3",
            "Inventory": "8337eb8541b314040b0edde0c09c5c7a2783ba1960aa9edfbf3bac16d0fec404",
            "ViewerDropsDashboard": "d9cae7761dafab85908c85e6683cb4201b449e66ac3bb5e894f15ff12aeafaa7",
            "DropCampaignDetails": "039277bf98f3130929262cc7c6efd9c141ca3749cb6dca442fc8ead9a53f77c1",
            "DropsHighlightService_AvailableDrops": "782dad0f032942260171d2d80a654f88bdd0c5a9dddc392e9bc92218a0f42d20",
            "SubscriptionsManagement_SubscriptionBenefits": "b21eec80bf7f902cc52c3f6552cd79b0b651b61bf891c9033efef22c8c8bcca6",
        }

        for operation_name, expected_hash in expected_hashes.items():
            operation = getattr(GQLOperations, operation_name)
            actual_hash = operation["extensions"]["persistedQuery"]["sha256Hash"]
            self.assertEqual(actual_hash, expected_hash)

    def test_default_playback_simulation_is_always(self):
        settings = StreamerSettings()

        settings.default()

        self.assertEqual(settings.playback_simulation, PlaybackSimulationMode.ALWAYS)

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

    def test_off_skips_hls_but_still_sends_spade_minute_event(self):
        streamer = self._streamer(playback_simulation=PlaybackSimulationMode.OFF)
        streamer.is_online = True
        streamer.online_at = time.time() - 60
        streamer.stream.spade_url = "https://spade.example/minute"
        streamer.stream.payload = [{"event": "minute-watched"}]
        self.twitch.running = True

        def stop_loop(*_args, **_kwargs):
            self.twitch.running = False

        with (
            patch.object(Twitch, "_refresh_selection_context"),
            patch.object(Twitch, "_select_streamers_to_watch", return_value=[0]),
            patch.object(Twitch, "_prime_stream_playback") as mocked_prime,
            patch.object(
                Twitch,
                "_request_with_retry",
                return_value=FakeResponse(status_code=204),
            ) as mocked_request,
            patch.object(Twitch, "_Twitch__chuncked_sleep", side_effect=stop_loop),
        ):
            self.twitch.send_minute_watched_events([streamer], [Priority.ORDER])

        mocked_prime.assert_not_called()
        mocked_request.assert_called_once()
        self.assertEqual(mocked_request.call_args.args[:2], ("POST", streamer.stream.spade_url))

    def test_hls_playback_caches_token_and_playlist_url(self):
        streamer = self._streamer(playback_simulation=PlaybackSimulationMode.ALWAYS)
        token_value = json.dumps(
            {"expires": int(time.time()) + 600},
            separators=(",", ":"),
        )

        with (
            patch.object(
                Twitch,
                "post_gql_request",
                return_value={
                    "data": {
                        "streamPlaybackAccessToken": {
                            "signature": "test-signature",
                            "value": token_value,
                        }
                    }
                },
            ) as mocked_post,
            patch.object(
                Twitch,
                "_request_with_retry",
                side_effect=[
                    FakeResponse(
                        200,
                        "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=160000\nhttps://video.example/low.m3u8\n",
                    ),
                    FakeResponse(
                        200,
                        "#EXTM3U\n#EXTINF:2.000,\nhttps://video.example/segment-a.ts\n",
                    ),
                    FakeResponse(200),
                    FakeResponse(
                        200,
                        "#EXTM3U\n#EXTINF:2.000,\nhttps://video.example/segment-b.ts\n",
                    ),
                    FakeResponse(200),
                ],
            ) as mocked_request,
        ):
            self.assertTrue(self.twitch._prime_stream_playback(streamer))
            self.assertTrue(self.twitch._prime_stream_playback(streamer))

        mocked_post.assert_called_once()
        self.assertEqual(
            mocked_request.call_args_list[0].args[:2],
            (
                "GET",
                "https://usher.ttvnw.net/api/channel/hls/testchannel.m3u8"
                f"?sig=test-signature&token={token_value}",
            ),
        )
        self.assertEqual(
            mocked_request.call_args_list[1].args[:2],
            ("GET", "https://video.example/low.m3u8"),
        )
        self.assertEqual(
            mocked_request.call_args_list[3].args[:2],
            ("GET", "https://video.example/low.m3u8"),
        )

    def test_expired_playback_token_refresh_clears_playlist_cache(self):
        streamer = self._streamer(playback_simulation=PlaybackSimulationMode.ALWAYS)
        streamer.stream.playback_access_token = {
            "signature": "old-signature",
            "value": json.dumps({"expires": int(time.time()) - 60}),
            "expires_at": time.time() - 60,
        }
        streamer.stream.hls_url = "https://video.example/old.m3u8"
        refreshed_token = {
            "signature": "new-signature",
            "value": json.dumps({"expires": int(time.time()) + 600}),
            "expires_at": time.time() + 600,
        }

        with patch.object(
            Twitch,
            "_fetch_playback_access_token",
            return_value=refreshed_token,
        ) as mocked_fetch:
            token = self.twitch._get_or_update_playback_access_token(streamer)

        mocked_fetch.assert_called_once_with(streamer)
        self.assertEqual(token, refreshed_token)
        self.assertIsNone(streamer.stream.hls_url)

    def test_stream_update_resets_hls_cache_on_new_broadcast(self):
        streamer = self._streamer(playback_simulation=PlaybackSimulationMode.ALWAYS)
        streamer.stream.update("broadcast-a", "Title A", {}, [], 1)
        streamer.stream.playback_access_token = {"signature": "sig", "value": "token"}
        streamer.stream.hls_url = "https://video.example/low.m3u8"

        streamer.stream.update("broadcast-b", "Title B", {}, [], 1)

        self.assertIsNone(streamer.stream.playback_access_token)
        self.assertIsNone(streamer.stream.hls_url)

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

    def test_inventory_claiming_logs_missing_drop_instance_id(self):
        inventory = {
            "dropCampaignsInProgress": [
                {
                    "timeBasedDrops": [
                        self._drop_dict(
                            progress={
                                "currentMinutesWatched": 60,
                                "hasPreconditionsMet": True,
                                "isClaimed": False,
                            }
                        )
                    ]
                }
            ]
        }

        with (
            patch.object(Twitch, "_Twitch__get_inventory", return_value=inventory),
            patch.object(Twitch, "post_gql_request") as mocked_post,
            self.assertLogs("TwitchChannelPointsMiner.classes.Twitch", level="WARNING") as logs,
        ):
            self.twitch.claim_all_drops_from_inventory()

        mocked_post.assert_not_called()
        self.assertTrue(any("dropInstanceID" in message for message in logs.output))

    def test_inventory_claiming_claims_when_instance_is_present(self):
        inventory = {
            "dropCampaignsInProgress": [
                {
                    "timeBasedDrops": [
                        self._drop_dict(
                            progress={
                                "currentMinutesWatched": 60,
                                "dropInstanceID": "drop-instance-id",
                                "hasPreconditionsMet": True,
                                "isClaimed": False,
                            }
                        )
                    ]
                }
            ]
        }

        with (
            patch.object(Twitch, "_Twitch__get_inventory", return_value=inventory),
            patch.object(
                Twitch,
                "post_gql_request",
                return_value={
                    "data": {
                        "claimDropRewards": {
                            "status": "ELIGIBLE_FOR_ALL",
                        }
                    }
                },
            ) as mocked_post,
            patch("TwitchChannelPointsMiner.classes.Twitch.time.sleep"),
        ):
            self.twitch.claim_all_drops_from_inventory()

        mocked_post.assert_called_once()
        json_data = mocked_post.call_args.args[0]
        self.assertEqual(
            json_data["variables"],
            {"input": {"dropInstanceID": "drop-instance-id"}},
        )

    def test_campaign_sync_runs_when_drops_enabled_even_if_streamers_offline(self):
        streamer = self._streamer(claim_drops=True)
        streamer.is_online = False

        self.assertTrue(self.twitch._Twitch__streamers_require_campaign_sync([streamer]))

    def test_drops_condition_allows_fallback_campaigns_without_highlight_ids(self):
        streamer = self._streamer(claim_drops=True)
        streamer.is_online = True
        streamer.stream.campaigns_ids = []
        streamer.stream.campaigns = [SimpleNamespace(drops=[self._farmable_drop()])]

        self.assertTrue(streamer.drops_condition())

    def test_campaign_matches_streamer_without_highlight_ids_by_game_and_channel(self):
        streamer = self._streamer(claim_drops=True)
        streamer.channel_id = "channel-id"
        streamer.stream.game = {"id": "game-id", "displayName": "Game"}
        streamer.stream.campaigns_ids = []
        campaign = SimpleNamespace(
            id="campaign-id",
            drops=[self._farmable_drop()],
            game={
                "id": "game-id",
                "displayName": "Game",
                "boxArtURL": "https://example.invalid/game.jpg",
            },
            channels=["channel-id"],
        )

        self.assertTrue(self.twitch._campaign_matches_streamer(campaign, streamer))

    def test_available_drops_persisted_query_not_found_falls_back_to_empty_ids(self):
        streamer = self._streamer(claim_drops=True)
        streamer.channel_id = "channel-id"

        with patch.object(
            Twitch,
            "post_gql_request",
            return_value={"errors": [{"message": "PersistedQueryNotFound"}]},
        ):
            ids = self.twitch._Twitch__get_campaign_ids_from_streamer(streamer)

        self.assertEqual(ids, [])


if __name__ == "__main__":
    unittest.main()
