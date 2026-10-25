import unittest
from types import SimpleNamespace
from unittest.mock import patch

import TwitchChannelPointsMiner.classes.entities.Bet as bet_module
from TwitchChannelPointsMiner.classes.Twitch import Twitch
from TwitchChannelPointsMiner.classes.entities.Bet import (
    Bet,
    BetSettings,
    Condition,
    DelayMode,
    FilterCondition,
    MAX_PREDICTION_BET_POINTS,
    OutcomeKeys,
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

    def test_issue_11_settings_place_bet_only_when_300_users_filter_passes(self):
        for total_users in (299, 300):
            with self.subTest(total_users=total_users):
                settings = BetSettings(
                    strategy=Strategy.SMART_MONEY, percentage=10, max_points=50000,
                    minimum_points=1, stealth_mode=True,
                    delay_mode=DelayMode.FROM_END, delay=6,
                    filter_condition=FilterCondition(
                        by=OutcomeKeys.TOTAL_USERS, where=Condition.GTE, value=300,
                    ),
                )
                settings.default()
                event = self._event()
                event.streamer.channel_points = 100000
                event.bet = Bet([
                    {"id": "blue", "title": "Blue", "color": "BLUE", "total_users": 100,
                     "total_points": 10000, "top_predictors": [{"points": 5000}]},
                    {"id": "pink", "title": "Pink", "color": "PINK", "total_users": total_users - 100,
                     "total_points": 1000, "top_predictors": [{"points": 1000}]},
                ], settings)
                with patch.object(Twitch, "post_gql_request", return_value={
                    "data": {"makePrediction": {"error": None}}
                }) as post:
                    self.twitch.make_predictions(event)
                self.assertEqual(post.call_count, int(total_users >= 300))
                if total_users >= 300:
                    placed = post.call_args.args[0]["variables"]["input"]
                    self.assertEqual(placed["outcomeID"], "blue")
                    self.assertGreaterEqual(placed["points"], 4995)
                    self.assertLess(placed["points"], 5000)

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
