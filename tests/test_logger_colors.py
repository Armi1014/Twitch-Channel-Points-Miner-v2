import logging
import unittest

from colorama import Fore

from TwitchChannelPointsMiner.classes.Settings import Events
from TwitchChannelPointsMiner.logger import ColorPalette, GlobalFormatter, LoggerSettings


class LoggerColorsTest(unittest.TestCase):
    def test_issue_11_bet_result_colors_work_with_names_and_colorama_constants(self):
        for green, red in (("GREEN", "RED"), (Fore.GREEN, Fore.RED)):
            palette = ColorPalette(BET_WIN=green, BET_LOSE=red, BET_REFUND=green)
            formatter = GlobalFormatter(
                fmt="%(message)s", settings=LoggerSettings(
                    colored=True, emoji=False, color_palette=palette,
                ),
            )
            for event, color in (
                (Events.BET_WIN, Fore.GREEN), (Events.BET_LOSE, Fore.RED),
                (Events.BET_REFUND, Fore.GREEN), (Events.BET_START, Fore.RESET),
                (Events.BET_GENERAL, Fore.RESET), (Events.BET_FILTERS, Fore.RESET),
            ):
                with self.subTest(green=green, event=event):
                    record = logging.makeLogRecord({"msg": "Prediction", "event": event})
                    self.assertEqual(formatter.format(record), color + "Prediction")


if __name__ == "__main__":
    unittest.main()
