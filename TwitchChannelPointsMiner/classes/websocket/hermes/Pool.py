import logging
import random
import threading
import time

from websocket import WebSocketConnectionClosedException

from TwitchChannelPointsMiner.classes.websocket.Pool import WebSocketPool
from TwitchChannelPointsMiner.classes.websocket.hermes.Client import (
    HermesClient,
    HermesWebSocketListener,
    State,
)
from TwitchChannelPointsMiner.classes.websocket.hermes.data.response import (
    AuthenticateResponse,
    NotificationResponse,
)
from TwitchChannelPointsMiner.classes.entities.Message import Message
from TwitchChannelPointsMiner.utils import internet_connection_available

logger = logging.getLogger(__name__)


class HermesWebSocketPool(WebSocketPool, HermesWebSocketListener):
    def __init__(
        self,
        url: str,
        twitch,
        listeners,
        request_encoder,
        response_decoder,
        max_subscriptions_per_client: int = 50,
    ):
        self.url = url
        self.twitch = twitch
        self.request_encoder = request_encoder
        self.response_decoder = response_decoder
        self.max_subscriptions_per_client = max_subscriptions_per_client
        self.clients = []
        self.pubsub_message_listeners = [listener for listener in listeners]
        self.force_close = False
        self.__lock = threading.Lock()

    def topic(self, subscription_id: str):
        for client in self.clients:
            topic = client.topic(subscription_id)
            if topic is not None:
                return topic
        return None

    def __create_new_client(self, auth, topics, index=None):
        index = len(self.clients) if index is None else index
        logger.debug("Creating new HermesClient at index %s", index)
        client = HermesClient(
            index=index,
            url=self.url,
            auth=auth,
            pending_topics=list(topics),
            json_encoder=self.request_encoder,
            json_decoder=self.response_decoder,
        )
        client.add_listener(self)
        if index == len(self.clients):
            self.clients.append(client)
        else:
            self.clients[index] = client
        return client

    def __next_available_client(self):
        client = next(
            (
                current
                for current in self.clients
                if current.state is not State.CLOSED
                and len(current.all_topics()) < self.max_subscriptions_per_client
            ),
            None,
        )
        if client is None:
            client = self.__create_new_client(self.twitch.twitch_login, [])
            client.open()
        return client

    def __subscribed(self, topic) -> bool:
        return any(client.subscribed(topic) for client in self.clients)

    def submit(self, topic):
        try:
            str(topic)
        except Exception as exc:
            logger.warning(
                "Skipping invalid Hermes topic '%s' (%s)",
                getattr(topic, "topic", topic.__class__.__name__),
                exc,
            )
            return

        with self.__lock:
            if self.__subscribed(topic):
                logger.debug("Already subscribed to topic, %s", topic)
            else:
                self.__next_available_client().subscribe(topic)

    def __reconnect(self, client: HermesClient):
        with self.__lock:
            client.close()
            if self.force_close:
                return
            if client.index >= len(self.clients):
                return
            if self.clients[client.index].id != client.id:
                logger.debug("%s already reconnecting", client.describe())
                return
            new_client = self.__create_new_client(
                self.twitch.twitch_login,
                client.all_topics(),
                client.index,
            )
        logger.debug("%s - Reconnecting to Twitch Hermes server in ~30 seconds", client.describe())
        time.sleep(30)
        while not internet_connection_available() and not self.force_close:
            random_sleep = random.randint(1, 3)
            logger.warning(
                "%s - No internet connection available! Retrying websocket reconnection after %sm",
                client.describe(),
                random_sleep,
            )
            time.sleep(random_sleep * 60)
        if not self.force_close:
            new_client.open()

    def on_welcome(self, client: HermesClient, keepalive_secs: int):
        client.message_timeout_seconds = keepalive_secs + 5
        client.state = State.UNAUTHENTICATED
        client.authenticate()

    def on_authenticate(self, client: HermesClient, response: AuthenticateResponse):
        if response.has_error():
            logger.error("%s - Authentication error, %s", client.describe(), response)
            client.close()
        else:
            logger.debug("%s - Authentication success", client.describe())
            client.state = State.OPEN
            client.subscribe_pending()

    def on_subscribe(self, client: HermesClient, response):
        result = response.subscribe_response.result
        subscription_id = response.subscribe_response.subscription.id
        if result != "ok":
            topic = client.topic(subscription_id)
            client.subscriptions.pop(subscription_id, None)
            logger.error(
                "%s - Subscription error for %s: %s",
                client.describe(),
                topic if topic is not None else subscription_id,
                result,
            )

    def on_keepalive(self, client: HermesClient):
        logger.debug("%s - Received keepalive", client.describe())

    def on_notification(self, client: HermesClient, response: NotificationResponse):
        notification = response.notification
        if not isinstance(notification, NotificationResponse.PubSubData):
            logger.warning(
                "%s - Received unknown notification type %s",
                client.describe(),
                type(notification),
            )
            return

        topic = self.topic(notification.subscription.id)
        if topic is None:
            logger.warning(
                "%s - Unable to find topic for subscription %s",
                client.describe(),
                notification.subscription.id,
            )
            return

        message = Message({"topic": str(topic), "message": notification.pubsub})
        if (
            client.last_message_identifier is not None
            and client.last_message_timestamp is not None
            and client.last_message_timestamp == message.timestamp
            and client.last_message_identifier == message.identifier
        ):
            return
        client.last_message_timestamp = message.timestamp
        client.last_message_identifier = message.identifier

        for listener in self.pubsub_message_listeners:
            listener.on_message(message)

    def on_reconnect(self, client: HermesClient, url: str):
        self.__reconnect(client)

    def on_close(self, client: HermesClient, code: int, reason: str):
        self.__reconnect(client)

    def on_error(self, client: HermesClient, error: Exception):
        is_closed_error = isinstance(error, WebSocketConnectionClosedException)
        if is_closed_error:
            logger.debug("%s - WebSocket error: %s", client.describe(), error)
            self.__reconnect(client)
        else:
            logger.error(
                "%s - WebSocket error: %s",
                client.describe(),
                error,
                exc_info=isinstance(error, BaseException),
            )

    def start(self):
        logger.debug("Starting Hermes WebSocket Pool")

    def end(self):
        logger.debug("Closing Hermes WebSocket Pool")
        self.force_close = True
        with self.__lock:
            for client in self.clients:
                try:
                    client.close()
                except Exception as exc:
                    logger.error(
                        "%s - Error closing client",
                        client.describe(),
                        exc_info=exc,
                    )
            self.clients.clear()

    def check_stale_connections(self):
        logger.debug("Checking stale connections")
        for client in list(self.clients):
            if client.stale():
                self.__reconnect(client)
