import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from irc.client import Event

from TwitchChannelPointsMiner.classes.Chat import ClientIRC
from TwitchChannelPointsMiner.classes.PubSub import PubSubHandler
from TwitchChannelPointsMiner.classes.Settings import Events
from TwitchChannelPointsMiner.classes.SubscriptionNotifications import (
    build_subscription_dedupe_key,
    should_emit_subscription_notification,
)
from TwitchChannelPointsMiner.classes.Twitch import Twitch
from TwitchChannelPointsMiner.classes.entities.Message import Message
from TwitchChannelPointsMiner.classes.entities.Streamer import Streamer


class ChatSubscriptionNotificationsTest(unittest.TestCase):
    def _make_client(self, name="streamer", points=184880, nickname="myuser"):
        client = ClientIRC.__new__(ClientIRC)
        client.streamer = Streamer(name)
        client.streamer.channel_points = points
        client.channel_name = name
        client.channel = f"#{name}"
        client._nickname = nickname
        return client

    def _make_event(self, msg_id, tags):
        payload = [{"key": "msg-id", "value": msg_id}]
        payload.extend({"key": key, "value": value} for key, value in tags.items())
        return Event("usernotice", "tmi.twitch.tv", "#streamer", ["ignored"], payload)

    def test_builds_pretty_subgift_message(self):
        client = self._make_client(nickname="LuckyViewer")
        event = self._make_event(
            "subgift",
            {
                "display-name": "GiftGiver",
                "msg-param-recipient-user-name": "luckyviewer",
                "msg-param-recipient-display-name": "LuckyViewer",
                "msg-param-sub-plan": "1000",
            },
        )

        message = client._build_subscription_message(event)

        self.assertEqual(
            message,
            "\n".join(
                [
                    "**Received Subgift**",
                    "",
                    "**Channel:** `streamer` (`184.88k points`)",
                    "**Recipient:** **LuckyViewer**",
                    "**From:** **GiftGiver**",
                    "**Tier:** `Tier 1`",
                ]
            ),
        )

    def test_builds_pretty_resub_message_with_months(self):
        client = self._make_client(
            name="resubchannel",
            points=1200,
            nickname="ReturningViewer",
        )
        event = self._make_event(
            "resub",
            {
                "display-name": "ReturningViewer",
                "login": "returningviewer",
                "msg-param-sub-plan": "Prime",
                "msg-param-cumulative-months": "7",
            },
        )

        message = client._build_subscription_message(event)

        self.assertEqual(
            message,
            "\n".join(
                [
                    "**Subscription Renewed**",
                    "",
                    "**Channel:** `resubchannel` (`1.2k points`)",
                    "**Subscriber:** **ReturningViewer**",
                    "**Tier:** `Prime`",
                    "**Months:** `7`",
                ]
            ),
        )

    def test_emits_subscription_event_with_package_emoji(self):
        client = self._make_client(nickname="FreshSub")
        event = self._make_event(
            "sub",
            {
                "display-name": "FreshSub",
                "login": "freshsub",
                "msg-param-sub-plan": "1000",
            },
        )

        with patch("TwitchChannelPointsMiner.classes.Chat.logger.info") as info_log:
            client.on_usernotice(None, event)

        info_log.assert_called_once()
        args, kwargs = info_log.call_args
        self.assertIn("**New Subscription**", args[0])
        self.assertEqual(kwargs["extra"]["emoji"], ":partying_face:")
        self.assertEqual(kwargs["extra"]["event"], Events.SUBSCRIPTION)

    def test_ignores_subscription_events_for_other_users(self):
        client = self._make_client(nickname="myuser")
        event = self._make_event(
            "subgift",
            {
                "display-name": "GiftGiver",
                "msg-param-recipient-user-name": "someoneelse",
                "msg-param-recipient-display-name": "SomeoneElse",
            },
        )

        self.assertIsNone(client._build_subscription_message(event))

        with patch("TwitchChannelPointsMiner.classes.Chat.logger.info") as info_log:
            client.on_usernotice(None, event)

        info_log.assert_not_called()

    def test_ignores_resub_events_for_other_users(self):
        client = self._make_client(nickname="myuser")
        event = self._make_event(
            "resub",
            {
                "display-name": "isacshyne",
                "login": "isacshyne",
                "msg-param-sub-plan": "1000",
                "msg-param-cumulative-months": "19",
            },
        )

        self.assertIsNone(client._build_subscription_message(event))

        with patch("TwitchChannelPointsMiner.classes.Chat.logger.info") as info_log:
            client.on_usernotice(None, event)

        info_log.assert_not_called()

    def test_usernotice_uses_hidden_dedupe_cache(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_path = os.path.join(tmp_dir, ".state", "subscription_notifications.json")
            client = self._make_client(nickname="LuckyViewer")
            client.streamer.subscription_notification_cache_path = cache_path
            event = self._make_event(
                "subgift",
                {
                    "display-name": "GiftGiver",
                    "msg-param-recipient-user-name": "luckyviewer",
                    "msg-param-recipient-display-name": "LuckyViewer",
                    "msg-param-sub-plan": "1000",
                },
            )

            with patch("TwitchChannelPointsMiner.classes.Chat.logger.info") as info_log:
                client.on_usernotice(None, event)
                client.on_usernotice(None, event)

            info_log.assert_called_once()
            self.assertTrue(os.path.isfile(cache_path))

    def test_subscription_dedupe_ignores_points_label_changes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_path = os.path.join(tmp_dir, ".state", "subscription_notifications.json")
            dedupe_key = build_subscription_dedupe_key(
                msg_id="subgift",
                channel="streamer",
                recipient="LuckyViewer",
                gifter="GiftGiver",
                plan="Tier 1",
            )

            self.assertTrue(
                should_emit_subscription_notification(
                    cache_path,
                    "**Received Subgift**\n\n**Channel:** `streamer` (`1.00k points`)",
                    dedupe_key=dedupe_key,
                )
            )
            self.assertFalse(
                should_emit_subscription_notification(
                    cache_path,
                    "**Received Subgift**\n\n**Channel:** `streamer` (`1.10k points`)",
                    dedupe_key=dedupe_key,
                )
            )

    def test_pubsub_user_subscribe_event_triggers_gift_sub_lookup(self):
        twitch = Mock()
        handler = PubSubHandler(twitch=twitch, streamers=[], events_predictions={})
        message = Message(
            {
                "topic": "user-subscribe-events-v1.123",
                "message": json.dumps(
                    {
                        "type": "notification",
                        "notification": {
                            "pubsub": json.dumps(
                                {
                                    "user_id": "123",
                                    "channel_id": "456",
                                }
                            )
                        },
                    }
                ),
            }
        )

        handler.on_message(message)

        twitch.notify_gift_sub_from_channel_id.assert_called_once_with("456", [])

    def test_pubsub_onsite_notification_triggers_gift_sub_lookup(self):
        twitch = Mock()
        handler = PubSubHandler(twitch=twitch, streamers=[], events_predictions={})
        notification = {
            "type": "sub_gift_received",
            "category": "gift_subscriptions",
            "mobile_destination_key": "456",
        }
        message = Message(
            {
                "topic": "onsite-notifications.123",
                "message": json.dumps(
                    {
                        "type": "create-notification",
                        "data": {"notification": notification},
                    }
                ),
            }
        )

        handler.on_message(message)

        twitch.notify_gift_sub_from_onsite_notification.assert_called_once_with(
            notification,
            [],
        )

    def test_twitch_gift_sub_notification_preserves_subscription_message_shape(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            twitch = Twitch("LuckyViewer", "ua")
            twitch.subscription_notification_cache_path = os.path.join(
                tmp_dir,
                ".state",
                "subscription_notifications.json",
            )
            streamer = Streamer("streamer")
            streamer.channel_id = "456"
            streamer.channel_points = 184880
            benefit = {
                "tier": "1000",
                "gift": {
                    "isGift": True,
                    "gifter": {
                        "displayName": "GiftGiver",
                        "login": "giftgiver",
                    },
                },
                "product": {"tier": "1000", "name": "streamer"},
                "user": {
                    "id": "456",
                    "login": "streamer",
                    "displayName": "Streamer",
                },
            }

            with (
                patch.object(
                    Twitch,
                    "get_gift_subscription_benefits",
                    return_value=[benefit],
                ),
                patch("TwitchChannelPointsMiner.classes.Twitch.logger.info") as info_log,
            ):
                self.assertTrue(
                    twitch.notify_gift_sub_from_channel_id("456", [streamer])
                )
                streamer.channel_points = 184881
                self.assertFalse(
                    twitch.notify_gift_sub_from_channel_id("456", [streamer])
                )

            info_log.assert_called_once()
            args, kwargs = info_log.call_args
            self.assertEqual(
                args[0],
                "\n".join(
                    [
                        "**Received Subgift**",
                        "",
                        "**Channel:** `streamer` (`184.88k points`)",
                        "**Recipient:** **LuckyViewer**",
                        "**From:** **GiftGiver**",
                        "**Tier:** `Tier 1`",
                    ]
                ),
            )
            self.assertEqual(kwargs["extra"]["event"], Events.SUBSCRIPTION)

    def test_gift_subscription_lookup_uses_wide_paginated_default(self):
        twitch = Twitch("LuckyViewer", "ua")
        first_page = {
            "data": {
                "currentUser": {
                    "subscriptionBenefits": {
                        "pageInfo": {"hasNextPage": True},
                        "edges": [
                            {
                                "cursor": "cursor-1",
                                "node": {
                                    "gift": {"isGift": True},
                                    "user": {"id": "111", "login": "other"},
                                },
                            }
                        ],
                    }
                }
            }
        }
        second_page = {
            "data": {
                "currentUser": {
                    "subscriptionBenefits": {
                        "pageInfo": {"hasNextPage": False},
                        "edges": [
                            {
                                "cursor": "cursor-2",
                                "node": {
                                    "gift": {"isGift": True},
                                    "user": {"id": "456", "login": "streamer"},
                                },
                            }
                        ],
                    }
                }
            }
        }

        with patch.object(
            Twitch,
            "post_gql_request",
            side_effect=[first_page, second_page],
        ) as mocked_post:
            benefit = twitch.find_gift_subscription_benefit(channel_id="456")

        self.assertIsNotNone(benefit)
        self.assertEqual(benefit["user"]["id"], "456")
        first_request = mocked_post.call_args_list[0].args[0]
        second_request = mocked_post.call_args_list[1].args[0]
        self.assertEqual(first_request["variables"]["limit"], 100)
        self.assertEqual(first_request["variables"]["criteria"], {})
        self.assertIsNone(first_request["variables"]["cursor"])
        self.assertEqual(second_request["variables"]["cursor"], "cursor-1")
        self.assertNotIn("filter", first_request["variables"])
        self.assertNotIn("platform", first_request["variables"])
