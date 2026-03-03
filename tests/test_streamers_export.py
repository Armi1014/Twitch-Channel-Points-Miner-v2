import os
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd

from TwitchChannelPointsMiner.TwitchChannelPointsMiner import TwitchChannelPointsMiner
from TwitchChannelPointsMiner.classes.entities.Streamer import Streamer
from TwitchChannelPointsMiner.utils import _millify


class StreamersExportTest(unittest.TestCase):
    def _make_miner(self, export_path: str) -> TwitchChannelPointsMiner:
        miner = TwitchChannelPointsMiner.__new__(TwitchChannelPointsMiner)
        miner.streamers = []
        miner.streamer_follow_dates = {}
        miner.streamers_export_path = export_path
        miner.streamers_export_thread = None
        miner.streamers_export_interval_seconds = 600
        miner.running = False
        return miner

    def test_build_streamer_export_rows_sorted_and_formatted(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            miner = self._make_miner(os.path.join(tmp_dir, "streamers.xlsx"))

            easyemi = Streamer("easyemi")
            easyemi.channel_points = 184880
            easyemi.subscription_tier = 1

            rubia = Streamer("rubia")
            rubia.channel_points = 26870
            rubia.subscription_tier = 1

            itsceydi = Streamer("itsceydi")
            itsceydi.channel_points = 82570
            itsceydi.subscription_tier = None

            miner.streamers = [rubia, easyemi, itsceydi]
            miner.streamer_follow_dates = {
                "easyemi": "2025-07-21T12:34:56Z",
                "rubia": None,
            }

            rows = miner._build_streamer_export_rows()

            self.assertEqual([row["Streamer"] for row in rows], ["easyemi", "itsceydi", "rubia"])
            self.assertEqual(rows[0]["Points"], _millify(184880))
            self.assertEqual(rows[1]["Points"], _millify(82570))
            self.assertEqual(rows[2]["Points"], _millify(26870))
            self.assertEqual(rows[0]["Followdate"], "21.07.2025")
            self.assertEqual(rows[1]["Followdate"], "...")
            self.assertEqual(rows[2]["Followdate"], "...")
            self.assertEqual(rows[0]["Sub (yes/no)"], "yes")
            self.assertEqual(rows[1]["Sub (yes/no)"], "no")
            self.assertEqual(rows[2]["Sub (yes/no)"], "yes")

    def test_write_streamers_xlsx_uses_atomic_replace(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            export_path = os.path.join(tmp_dir, "streamers.xlsx")
            miner = self._make_miner(export_path)

            rows = [
                {
                    "Streamer": "easyemi",
                    "Points": "184.88k",
                    "Followdate": "21.07.2025",
                    "Sub (yes/no)": "yes",
                }
            ]

            def fake_to_excel(self, file_path, index=False, engine=None):
                with open(file_path, "wb") as file_obj:
                    file_obj.write(b"xlsx")

            with patch.object(pd.DataFrame, "to_excel", new=fake_to_excel):
                miner._write_streamers_xlsx(rows)

            self.assertTrue(os.path.isfile(export_path))
            with open(export_path, "rb") as file_obj:
                self.assertEqual(file_obj.read(), b"xlsx")

    def test_streamers_export_loop_runs_periodic_export(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            miner = self._make_miner(os.path.join(tmp_dir, "streamers.xlsx"))
            miner.running = True

            calls = []

            def fake_export():
                calls.append(1)
                miner.running = False

            with patch.object(
                TwitchChannelPointsMiner,
                "_export_streamers_snapshot",
                side_effect=fake_export,
            ), patch(
                "TwitchChannelPointsMiner.TwitchChannelPointsMiner.interruptible_sleep",
                return_value=None,
            ):
                miner._streamers_export_loop()

            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
