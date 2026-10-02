"""Check the actual commented provider examples without contacting services."""

import ast
import logging
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from TwitchChannelPointsMiner.classes.Discord import Discord
from TwitchChannelPointsMiner.classes.Gotify import Gotify
from TwitchChannelPointsMiner.classes.Matrix import Matrix
from TwitchChannelPointsMiner.classes.Pushover import Pushover
from TwitchChannelPointsMiner.classes.Settings import Events
from TwitchChannelPointsMiner.classes.Telegram import Telegram
from TwitchChannelPointsMiner.classes.Webhook import Webhook
from TwitchChannelPointsMiner.logger import ColorPalette, LoggerSettings

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = {
    "telegram": Telegram,
    "discord": Discord,
    "gotify": Gotify,
    "matrix": Matrix,
    "pushover": Pushover,
    "webhook": Webhook,
}


def logger_settings(source):
    tree = ast.parse(source)
    statements = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id in {"NOTIFICATION_EVENTS", "LOGGER_SETTINGS"}
            for target in node.targets
        )
    ]
    namespace = {
        "Events": Events,
        "LoggerSettings": LoggerSettings,
        "ColorPalette": ColorPalette,
        "logging": logging,
        **{provider.__name__: provider for provider in PROVIDERS.values()},
    }
    exec(
        compile(ast.Module(body=statements, type_ignores=[]), "example.py", "exec"),
        namespace,
    )
    return namespace["LOGGER_SETTINGS"], namespace["NOTIFICATION_EVENTS"]


class SetupExamplesTest(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "example.py").read_text(encoding="utf-8")

    def test_default_example_enables_no_notifications_or_network_calls(self):
        with patch("requests.post") as post, patch("requests.get") as get:
            settings, _ = logger_settings(self.source)
        for name in PROVIDERS:
            self.assertIsNone(getattr(settings, name))
        post.assert_not_called()
        get.assert_not_called()

    def test_all_commented_examples_construct_and_bind_to_logger(self):
        lines = self.source.splitlines()
        enabling = False
        found = set()
        for index, line in enumerate(lines):
            if any(line.startswith(f"    # {name}=") for name in PROVIDERS):
                enabling = True
                found.add(line.split("# ", 1)[1].split("=", 1)[0])
            if enabling:
                self.assertTrue(line.startswith("    # "))
                lines[index] = "    " + line[6:]
                if line.strip() == "# ),":
                    enabling = False
        self.assertEqual(found, set(PROVIDERS))
        login = Mock()
        login.json.return_value = {"access_token": "fake-test-token"}
        with (
            patch("requests.post", return_value=login) as post,
            patch("requests.get") as get,
        ):
            settings, events = logger_settings("\n".join(lines))
        for name, provider in PROVIDERS.items():
            instance = getattr(settings, name)
            self.assertIsInstance(instance, provider)
            self.assertEqual(instance.events, [str(event) for event in events])
        self.assertEqual(post.call_count, 1)  # Matrix logs in during construction.
        self.assertEqual(post.call_args.kwargs["json"]["type"], "m.login.password")
        get.assert_not_called()

    def test_miner_receives_the_settings_created_before_startup(self):
        tree = ast.parse(self.source)
        assignments = {
            node.targets[0].id: node
            for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
        }
        startup = assignments["twitch_miner"]
        argument = next(
            keyword.value
            for keyword in startup.value.keywords
            if keyword.arg == "logger_settings"
        )
        self.assertIsInstance(argument, ast.Name)
        self.assertEqual(argument.id, "LOGGER_SETTINGS")
        self.assertLess(assignments["LOGGER_SETTINGS"].lineno, startup.lineno)


if __name__ == "__main__":
    unittest.main()
