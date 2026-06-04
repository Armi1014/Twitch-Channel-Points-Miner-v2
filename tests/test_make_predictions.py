import unittest
from types import SimpleNamespace
from unittest.mock import patch

import TwitchChannelPointsMiner.classes.entities.Bet as bet_module
from TwitchChannelPointsMiner.classes.Twitch import Twitch
from TwitchChannelPointsMiner.classes.entities.Bet import (
    Bet,
    BetSettings,
    MAX_PREDICTION_BET_POINTS,
    Strategy,
)


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

    def test_prediction_amount_is_clamped_to_twitch_limit(self):
        bet_module._prediction_cap_warning_logged = False
        settings = BetSettings(
            strategy=Strategy.NUMBER_1,
            percentage=100,
            max_points=500000,
            stealth_mode=False,
        )
        settings.default()
        bet = Bet(
            [
                {
                    "id": "outcome-1",
                    "title": "Blue",
                    "color": "BLUE",
                    "total_users": 1,
                    "total_points": 1,
                },
                {
                    "id": "outcome-2",
                    "title": "Pink",
                    "color": "PINK",
                    "total_users": 1,
                    "total_points": 1,
                },
            ],
            settings,
        )

        with patch(
            "TwitchChannelPointsMiner.classes.entities.Bet.logger.warning"
        ) as mocked_warning:
            decision = bet.calculate(999999)

        self.assertEqual(decision["amount"], MAX_PREDICTION_BET_POINTS)
        mocked_warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
