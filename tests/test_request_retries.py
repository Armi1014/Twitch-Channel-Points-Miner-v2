import unittest
from unittest.mock import patch

import requests

from TwitchChannelPointsMiner.classes.Twitch import Twitch


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


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


if __name__ == "__main__":
    unittest.main()
