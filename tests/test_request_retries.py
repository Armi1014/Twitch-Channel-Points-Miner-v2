import unittest
from unittest.mock import patch

import requests

from TwitchChannelPointsMiner.classes.entities.Streamer import Streamer
from TwitchChannelPointsMiner.classes.Twitch import Twitch


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


class InvalidJsonResponse(FakeResponse):
    def json(self):
        raise ValueError("invalid json")


class RequestRetryTest(unittest.TestCase):
    def setUp(self):
        self.twitch = Twitch("retry-test", "ua")

    def test_request_with_retry_retries_dns_resolution_failures(self):
        dns_error = requests.exceptions.ConnectionError(
            "Failed to create new connection: [Errno -3] Temporary failure in name resolution"
        )
        ok_response = FakeResponse(status_code=200)

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.requests.request",
            side_effect=[dns_error, ok_response],
        ) as mocked_request:
            response = self.twitch._request_with_retry(
                "GET",
                "https://example.com",
                request_name="test_retry_dns",
                max_attempts=3,
                backoff_base=0,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(mocked_request.call_count, 2)

    def test_request_with_retry_retries_read_timeout(self):
        timeout_error = requests.exceptions.ReadTimeout("read timed out")
        ok_response = FakeResponse(status_code=200)

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.requests.request",
            side_effect=[timeout_error, ok_response],
        ) as mocked_request:
            response = self.twitch._request_with_retry(
                "GET",
                "https://example.com",
                request_name="test_retry_read_timeout",
                max_attempts=3,
                backoff_base=0,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(mocked_request.call_count, 2)

    def test_request_with_retry_retries_chunked_encoding_error(self):
        chunk_error = requests.exceptions.ChunkedEncodingError(
            "InvalidChunkLength(got length b'\\r\\n', 0 bytes read)"
        )
        ok_response = FakeResponse(status_code=200)

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.requests.request",
            side_effect=[chunk_error, ok_response],
        ) as mocked_request:
            response = self.twitch._request_with_retry(
                "GET",
                "https://example.com",
                request_name="test_retry_chunked_error",
                max_attempts=3,
                backoff_base=0,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(mocked_request.call_count, 2)

    def test_request_with_retry_does_not_retry_non_retryable_connection_error(self):
        connection_reset = requests.exceptions.ConnectionError("Connection reset by peer")

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.requests.request",
            side_effect=connection_reset,
        ) as mocked_request:
            with self.assertRaises(requests.exceptions.ConnectionError):
                self.twitch._request_with_retry(
                    "GET",
                    "https://example.com",
                    request_name="test_no_retry_reset",
                    max_attempts=3,
                    backoff_base=0,
                )

        self.assertEqual(mocked_request.call_count, 1)

    def test_post_gql_request_retries_transient_connection_setup_errors(self):
        dns_error = requests.exceptions.ConnectionError(
            "Failed to establish a new connection: [Errno -3] Temporary failure in name resolution"
        )
        gql_response = FakeResponse(
            status_code=200,
            payload={"data": {"viewer": {"id": "1"}}},
            text='{"data":{"viewer":{"id":"1"}}}',
        )

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.requests.request",
            side_effect=[dns_error, gql_response],
        ) as mocked_request, patch(
            "TwitchChannelPointsMiner.classes.Twitch.HTTP_RETRY_BACKOFF_BASE", 0
        ), patch.object(
            Twitch, "update_client_version", return_value="test-version"
        ), patch.object(
            type(self.twitch.twitch_login), "get_auth_token", return_value="test-token"
        ):
            result = self.twitch.post_gql_request({"operationName": "ViewerQuery"})

        self.assertEqual(result, {"data": {"viewer": {"id": "1"}}})
        self.assertEqual(mocked_request.call_count, 2)

    def test_update_client_version_uses_cache_window(self):
        build_id = "11111111-2222-3333-4444-555555555555"
        html = f'window.__twilightBuildID="{build_id}"'
        response = FakeResponse(status_code=200, text=html)

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.requests.request",
            return_value=response,
        ) as mocked_request:
            version_first = self.twitch.update_client_version()
            version_second = self.twitch.update_client_version()

        self.assertEqual(version_first, build_id)
        self.assertEqual(version_second, build_id)
        self.assertEqual(mocked_request.call_count, 1)

    def test_update_client_version_timeout_uses_cooldown(self):
        timeout_error = requests.exceptions.ReadTimeout("read timed out")

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.requests.request",
            side_effect=timeout_error,
        ) as mocked_request:
            self.twitch._client_version_checked_at = 0
            self.twitch.update_client_version()
            self.twitch.update_client_version()

        # First call retries read timeout (3 attempts); second call is skipped by cooldown.
        self.assertEqual(mocked_request.call_count, 3)

    def test_post_gql_request_throttles_repeated_503_and_invalid_json_warnings(self):
        invalid_json_response = InvalidJsonResponse(
            status_code=503,
            text="<html>service unavailable</html>",
        )

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.requests.request",
            return_value=invalid_json_response,
        ), patch.object(
            Twitch, "update_client_version", return_value="test-version"
        ), patch.object(
            type(self.twitch.twitch_login), "get_auth_token", return_value="test-token"
        ), patch(
            "TwitchChannelPointsMiner.classes.Twitch.logger.warning"
        ) as mocked_warning:
            self.twitch.post_gql_request({"operationName": "RewardList"})
            self.twitch.post_gql_request({"operationName": "RewardList"})

        # First call emits 2 warnings (HTTP status + invalid JSON), second call is suppressed.
        self.assertEqual(mocked_warning.call_count, 2)

    def test_log_gql_errors_suppresses_chat_room_ban_status_service_timeout(self):
        response = {"errors": [{"message": "service timeout"}]}

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.logger.warning"
        ) as mocked_warning, patch(
            "TwitchChannelPointsMiner.classes.Twitch.logger.debug"
        ) as mocked_debug:
            handled = self.twitch._log_gql_errors("ChatRoomBanStatus", response)

        self.assertTrue(handled)
        mocked_warning.assert_not_called()
        mocked_debug.assert_called_once()

    def test_log_gql_errors_compacts_repeated_service_timeout_messages(self):
        response = {
            "errors": [
                {"message": "service timeout"},
                {"message": "service timeout"},
                {"message": "service timeout"},
            ]
        }

        with patch(
            "TwitchChannelPointsMiner.classes.Twitch.logger.warning"
        ) as mocked_warning:
            handled = self.twitch._log_gql_errors("SomeCriticalOperation", response)

        self.assertTrue(handled)
        mocked_warning.assert_called_once()
        self.assertIn("service timeout (x3)", mocked_warning.call_args[0][2])

    def test_fetch_playback_access_token_uses_current_web_player_variables(self):
        streamer = Streamer("TestChannel")

        with patch.object(
            Twitch,
            "post_gql_request",
            return_value={
                "data": {
                    "streamPlaybackAccessToken": {
                        "signature": "test-signature",
                        "value": "test-token",
                    }
                }
            },
        ) as mocked_post:
            token = self.twitch._fetch_playback_access_token(streamer)

        self.assertEqual(token, ("test-signature", "test-token"))
        json_data = mocked_post.call_args.args[0]
        self.assertEqual(json_data["operationName"], "PlaybackAccessToken")
        self.assertEqual(
            json_data["variables"],
            {
                "login": "testchannel",
                "isLive": True,
                "isVod": False,
                "vodID": "",
                "playerBackend": "mediaplayer",
                "playerType": "site",
                "platform": "web",
            },
        )

    def test_prime_stream_playback_walks_m3u_playlists_and_heads_segment(self):
        streamer = Streamer("TestChannel")

        with patch.object(
            Twitch,
            "_fetch_playback_access_token",
            return_value=("test-signature", "test-token"),
        ), patch.object(
            Twitch,
            "_request_with_retry",
            side_effect=[
                FakeResponse(
                    status_code=200,
                    text="#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=160000\nhttps://video.example/low.m3u8\n",
                ),
                FakeResponse(
                    status_code=200,
                    text="#EXTM3U\n#EXTINF:2.000,\nhttps://video.example/segment.ts\n",
                ),
                FakeResponse(status_code=200),
            ],
        ) as mocked_request:
            self.assertTrue(self.twitch._prime_stream_playback(streamer))

        self.assertEqual(
            mocked_request.call_args_list[0].args[:2],
            (
                "GET",
                "https://usher.ttvnw.net/api/channel/hls/testchannel.m3u8?sig=test-signature&token=test-token",
            ),
        )
        self.assertEqual(
            mocked_request.call_args_list[1].args[:2],
            ("GET", "https://video.example/low.m3u8"),
        )
        self.assertEqual(
            mocked_request.call_args_list[2].args[:2],
            ("HEAD", "https://video.example/segment.ts"),
        )


if __name__ == "__main__":
    unittest.main()
