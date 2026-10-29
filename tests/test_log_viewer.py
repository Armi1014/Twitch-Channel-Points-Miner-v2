import tempfile
import unittest
from pathlib import Path

from scripts.watch_logs import LogFollower, open_log


def record(level, message):
    return f"29/10/26 12:00:00 - {level} - miner - [run]: {message}\n".encode("utf-8")


class LogViewerTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "miner.log"

    def test_recent_info_then_live_updates_without_repeating_or_changing_file(self):
        self.path.write_bytes(record("INFO", "Older") + record("DEBUG", "Noise") + record("INFO", "Recent"))
        viewer = LogFollower(self.path, tail=1)
        self.assertEqual(viewer.read(), ["29/10/26 12:00:00 [INFO] Recent"])
        self.assertEqual(viewer.read(), [])
        with self.path.open("ab") as output:
            output.write(record("WARNING", "Retrying"))
        before = self.path.read_bytes()
        self.assertEqual(viewer.read(), ["29/10/26 12:00:00 [WARNING] Retrying"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_rotation_and_truncation_are_followed_and_open_reader_allows_rename(self):
        self.path.write_bytes(record("INFO", "Original log entry"))
        viewer = LogFollower(self.path)
        viewer.read()
        with open_log(self.path):
            self.path.rename(self.path.with_suffix(".old"))
        self.path.write_bytes(record("ERROR", "Replacement log entry"))
        self.assertEqual(viewer.read(), ["29/10/26 12:00:00 [ERROR] Replacement log entry"])
        self.path.write_bytes(record("INFO", "New"))
        self.assertEqual(viewer.read(), ["29/10/26 12:00:00 [INFO] New"])

    def test_split_unicode_record_is_displayed_only_when_complete(self):
        self.path.write_bytes(b"")
        viewer = LogFollower(self.path)
        self.assertEqual(viewer.read(), [])
        data = record("INFO", "Reward → claimed")
        split = data.index("→".encode("utf-8")) + 1
        self.path.write_bytes(data[:split])
        self.assertEqual(viewer.read(), [])
        with self.path.open("ab") as output:
            output.write(data[split:])
        self.assertEqual(viewer.read(), ["29/10/26 12:00:00 [INFO] Reward → claimed"])

    def test_debug_mode_and_traceback_lines(self):
        self.path.write_bytes(record("DEBUG", "Detail") + record("ERROR", "Failed") + b"Traceback detail\n")
        self.assertEqual(LogFollower(self.path, debug=True).read(), [
            "29/10/26 12:00:00 [DEBUG] Detail", "29/10/26 12:00:00 [ERROR] Failed", "Traceback detail",
        ])


if __name__ == "__main__":
    unittest.main()
