import inspect
import json
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

from TwitchChannelPointsMiner import TwitchChannelPointsMiner
from TwitchChannelPointsMiner.classes.PubSub import MessageListener
from TwitchChannelPointsMiner.classes.entities.PubsubTopic import PubsubTopic
from TwitchChannelPointsMiner.classes.websocket import (
    HermesWebSocketPool,
    PubSubWebSocketPool,
)
from TwitchChannelPointsMiner.classes.websocket.hermes.Client import State
from TwitchChannelPointsMiner.classes.websocket.hermes.data import (
    JsonDecoder,
    JsonEncoder,
)
from TwitchChannelPointsMiner.classes.websocket.hermes.data.request import (
    SubscribePubSubRequest,
)
from TwitchChannelPointsMiner.classes.websocket.hermes.data.response import (
    AuthenticateResponse,
    NotificationResponse,
    SubscribeResponse,
    Subscription,
    WelcomeResponse,
)


class Collector(MessageListener):
    def __init__(self):
        self.messages = []

    def on_message(self, message):
        self.messages.append(message)


class HermesTransportTest(unittest.TestCase):
    def setUp(self):
        self.twitch = SimpleNamespace(twitch_login=SimpleNamespace())

    def _build_miner_for_pool(self, use_hermes: bool):
        miner = object.__new__(TwitchChannelPointsMiner)
        miner.twitch = self.twitch
        miner.streamers = []
        miner.events_predictions = {}
        miner.use_hermes = use_hermes
        return miner

    def _fake_client(self, topic):
        subscriptions = {"sub-1": (topic, object())}

        def topic_lookup(subscription_id):
            pair = subscriptions.get(subscription_id)
            return None if pair is None else pair[0]

        return SimpleNamespace(
            index=0,
            id="client-1",
            state=State.OPEN,
            subscriptions=subscriptions,
            topic=topic_lookup,
            last_message_timestamp=None,
            last_message_identifier=None,
            describe=lambda: "#0",
        )

    def test_use_hermes_constructor_default_is_true(self):
        default = inspect.signature(TwitchChannelPointsMiner.__init__).parameters[
            "use_hermes"
        ].default
        self.assertTrue(default)

    def test_create_ws_pool_defaults_to_hermes(self):
        miner = self._build_miner_for_pool(use_hermes=True)

        pool = miner._create_ws_pool()

        self.assertIsInstance(pool, HermesWebSocketPool)
        self.assertIn("clientId=", pool.url)

    def test_create_ws_pool_can_force_pubsub(self):
        miner = self._build_miner_for_pool(use_hermes=False)

        pool = miner._create_ws_pool()

        self.assertIsInstance(pool, PubSubWebSocketPool)

    def test_json_encoder_encodes_hermes_subscribe_request(self):
        request = SubscribePubSubRequest.create(
            PubsubTopic("community-points-user-v1", user_id="123")
        )

        payload = json.loads(JsonEncoder().encode(request))

        self.assertEqual(payload["type"], "subscribe")
        self.assertEqual(payload["subscribe"]["type"], "pubsub")
        self.assertEqual(
            payload["subscribe"]["pubsub"]["topic"],
            "community-points-user-v1.123",
        )

    def test_json_decoder_decodes_welcome_response(self):
        raw = json.dumps(
            {
                "id": "welcome-1",
                "type": "welcome",
                "timestamp": "2024-01-01T00:00:00Z",
                "welcome": {
                    "keepaliveSec": 25,
                    "recoveryUrl": "wss://example.invalid/recover",
                    "sessionId": "session-1",
                },
            }
        )

        response = JsonDecoder().decode(raw)

        self.assertIsInstance(response, WelcomeResponse)
        self.assertEqual(response.welcome.keepalive_sec, 25)
        self.assertEqual(response.welcome.session_id, "session-1")

    def test_hermes_pool_welcome_authenticate_and_subscribe_flow(self):
        pool = HermesWebSocketPool(
            url="wss://hermes.example/ws",
            twitch=self.twitch,
            listeners=[],
            request_encoder=JsonEncoder(),
            response_decoder=JsonDecoder(),
        )
        client = SimpleNamespace(
            message_timeout_seconds=0,
            state=State.UNWELCOMED,
            authenticate=Mock(),
            subscribe_pending=Mock(),
            subscriptions={
                "sub-1": (
                    PubsubTopic("community-points-user-v1", user_id="123"),
                    object(),
                )
            },
            topic=lambda subscription_id: PubsubTopic(
                "community-points-user-v1", user_id="123"
            ),
            describe=lambda: "#0",
        )

        pool.on_welcome(client, 30)
        self.assertEqual(client.message_timeout_seconds, 35)
        self.assertEqual(client.state, State.UNAUTHENTICATED)
        client.authenticate.assert_called_once()

        ok_response = AuthenticateResponse(
            "auth-1",
            "parent-1",
            datetime.now(timezone.utc),
            AuthenticateResponse.DataOk(),
        )
        pool.on_authenticate(client, ok_response)
        self.assertEqual(client.state, State.OPEN)
        client.subscribe_pending.assert_called_once()

        failed_subscribe = SubscribeResponse(
            "subresp-1",
            "parent-2",
            datetime.now(timezone.utc),
            SubscribeResponse.Data("error", Subscription("sub-1")),
        )
        pool.on_subscribe(client, failed_subscribe)
        self.assertNotIn("sub-1", client.subscriptions)

    def test_hermes_pool_normalizes_notifications_to_messages(self):
        collector = Collector()
        pool = HermesWebSocketPool(
            url="wss://hermes.example/ws",
            twitch=self.twitch,
            listeners=[collector],
            request_encoder=JsonEncoder(),
            response_decoder=JsonDecoder(),
        )

        cases = [
            (
                PubsubTopic("community-points-user-v1", user_id="123"),
                {
                    "type": "points-earned",
                    "data": {
                        "balance": {"balance": 250, "channel_id": "456"},
                        "point_gain": {"total_points": 12, "reason_code": "WATCH"},
                        "timestamp": "2024-01-01T00:00:00Z",
                    },
                },
                "points-earned",
                "456",
            ),
            (
                PubsubTopic(
                    "video-playback-by-id",
                    streamer=SimpleNamespace(channel_id="456"),
                ),
                {
                    "type": "viewcount",
                    "server_time": 1704067200,
                },
                "viewcount",
                "456",
            ),
            (
                PubsubTopic(
                    "predictions-channel-v1",
                    streamer=SimpleNamespace(channel_id="456"),
                ),
                {
                    "type": "event-created",
                    "data": {
                        "channel_id": "456",
                        "timestamp": "2024-01-01T00:00:01Z",
                        "event": {
                            "id": "evt-1",
                            "status": "ACTIVE",
                            "prediction_window_seconds": "60",
                            "title": "Test Prediction",
                            "created_at": "2024-01-01T00:00:01Z",
                            "outcomes": [],
                        },
                    },
                },
                "event-created",
                "456",
            ),
        ]

        for topic, payload, expected_type, expected_channel_id in cases:
            with self.subTest(topic=str(topic)):
                collector.messages.clear()
                fake_client = self._fake_client(topic)
                pool.clients = [fake_client]
                raw_response = json.dumps(
                    {
                        "id": "notif-1",
                        "type": "notification",
                        "timestamp": "2024-01-01T00:00:02Z",
                        "notification": {
                            "type": "pubsub",
                            "subscription": {"id": "sub-1"},
                            "pubsub": json.dumps(payload),
                        },
                    }
                )

                response = JsonDecoder().decode(raw_response)
                self.assertIsInstance(response, NotificationResponse)

                pool.on_notification(fake_client, response)

                self.assertEqual(len(collector.messages), 1)
                message = collector.messages[0]
                self.assertEqual(message.topic, topic.topic)
                self.assertEqual(message.type, expected_type)
                self.assertEqual(str(message.channel_id), expected_channel_id)


if __name__ == "__main__":
    unittest.main()
