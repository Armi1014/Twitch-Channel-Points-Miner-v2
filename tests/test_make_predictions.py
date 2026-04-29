import unittest
from types import SimpleNamespace
from unittest.mock import patch

from TwitchChannelPointsMiner.classes.Twitch import Twitch


class FakeBet:
    def calculate(self, balance):
        return {"amount": 10, "choice": 0, "id": "outcome-1"}

    def skip(self):
        return False, None

    def get_outcome(self, choice):
        return "Blue"


class MakePredictionsTest(unittest.TestCase):
    def setUp(self):
        self.twitch = Twitch("prediction-test", "ua")

    def _event(self):
        return SimpleNamespace(
            status="ACTIVE",
            event_id="event-1",
            streamer=SimpleNamespace(channel_points=100),
            bet=FakeBet(),
        )

    def test_make_predictions_handles_null_make_prediction_payload(self):
        response = {"data": {"makePrediction": None}}

        with (
            patch.object(
                Twitch, "post_gql_request", return_value=response
            ) as mocked_post,
            patch(
                "TwitchChannelPointsMiner.classes.Twitch.logger.error"
            ) as mocked_error,
        ):
            self.twitch.make_predictions(self._event())

        mocked_post.assert_called_once()
        mocked_error.assert_called_once()
        self.assertEqual(
            mocked_error.call_args.args[0],
            "Failed to place bet, MakePrediction returned no result",
        )

    def test_make_predictions_uses_gql_error_logger_before_payload_check(self):
        response = {
            "data": {"makePrediction": None},
            "errors": [{"message": "prediction is closed"}],
        }

        with (
            patch.object(Twitch, "post_gql_request", return_value=response),
            patch(
                "TwitchChannelPointsMiner.classes.Twitch.logger.warning"
            ) as mocked_warning,
            patch(
                "TwitchChannelPointsMiner.classes.Twitch.logger.error"
            ) as mocked_error,
        ):
            self.twitch.make_predictions(self._event())

        mocked_warning.assert_called_once()
        mocked_error.assert_not_called()


if __name__ == "__main__":
    unittest.main()
