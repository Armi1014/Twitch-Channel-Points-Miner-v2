import abc
import json
import logging
import threading
from datetime import datetime
from enum import Enum
from threading import Thread
from uuid import uuid4

from websocket import WebSocketApp, WebSocketConnectionClosedException

from TwitchChannelPointsMiner.classes.Settings import Settings
from TwitchChannelPointsMiner.classes.websocket.hermes.data.request import (
    AuthenticateRequest,
    SubscribePubSubRequest,
)
from TwitchChannelPointsMiner.classes.websocket.hermes.data.response import (
    AuthenticateResponse,
    KeepaliveResponse,
    NotificationResponse,
    ReconnectResponse,
    SubscribeResponse,
    WelcomeResponse,
)
from TwitchChannelPointsMiner.utils import combine, internet_connection_available

logger = logging.getLogger(__name__)


class State(Enum):
    UNOPENED = 0
    UNWELCOMED = 1
    UNAUTHENTICATED = 2
    OPEN = 3
    CLOSED = 4

    def __repr__(self):
        return self.name.capitalize()

    def __str__(self):
        return repr(self)


class HermesClient(WebSocketApp):
    def __init__(
        self,
        index: int,
        url: str,
        auth,
        pending_topics: list,
        json_encoder,
        json_decoder,
    ):
        super().__init__(
            url,
            on_open=HermesClient.on_open,
            on_message=HermesClient.on_message,
            on_close=HermesClient.on_close,
            on_error=HermesClient.on_error,
        )
        self.index = index
        self.url = url
        self.auth = auth
        self.pending_topics = pending_topics
        self.json_encoder = json_encoder
        self.json_decoder = json_decoder

        self.id = str(uuid4())
        self.state = State.UNOPENED
        self.subscriptions = {}
        self.listeners = []

        self.last_message_timestamp = None
        self.last_message_identifier = None

        self.message_timeout_seconds = 20
        self.last_message_time = datetime.now()
        self.created_timeout_seconds = 300
        self.created_time = datetime.now()

        self.pending_topics_lock = threading.Lock()
        self.close_lock = threading.Lock()
        self.thread_ws = None

    def describe(self):
        less = bool(getattr(getattr(Settings, "logger", None), "less", False))
        return f"#{self.index}" if less else f"#{self.index} - {self.id}"

    def open(self):
        if self.state != State.UNOPENED:
            logger.warning(
                "%s: Cannot open Client, wrong state: %s",
                self.describe(),
                self.state,
            )
            return
        if self.thread_ws is not None:
            logger.warning(
                "%s: Cannot open Client, thread already running",
                self.describe(),
            )
            return
        if Settings.disable_ssl_cert_verification is True:
            import ssl

            self.thread_ws = Thread(
                target=lambda: self.run_forever(
                    sslopt={"cert_reqs": ssl.CERT_NONE},
                    origin="https://www.twitch.tv",
                )
            )
            logger.warning("SSL certificate verification is disabled! Be aware!")
        else:
            self.thread_ws = Thread(
                target=lambda: self.run_forever(origin="https://www.twitch.tv")
            )
        self.thread_ws.daemon = True
        self.thread_ws.name = f"WebSocket #{self.index}"
        self.thread_ws.start()

    def close(self):
        should_close = False
        with self.close_lock:
            if self.state is not State.CLOSED:
                self.state = State.CLOSED
                should_close = True
        if should_close:
            super().close()

    def __send_request(self, request):
        try:
            data = self.json_encoder.encode(request)
            log_data = (
                "AuthenticateRequest(REDACTED)"
                if isinstance(request, AuthenticateRequest)
                else data
            )
            logger.debug("%s - Send: %s", self.describe(), log_data)
            self.send(data)
            return True
        except WebSocketConnectionClosedException:
            logger.warning("%s - Cannot send, WebSocket is closed", self.describe())
            self.state = State.CLOSED
            return False

    def send_request(self, request):
        if self.state == State.OPEN:
            return self.__send_request(request)
        if self.state in {State.UNOPENED, State.UNWELCOMED, State.UNAUTHENTICATED}:
            logger.warning(
                "%s - Cannot send, WebSocket is not yet open: %s",
                self.describe(),
                self.state,
            )
        else:
            logger.warning("%s - Cannot send, WebSocket is closed", self.describe())
        return False

    def authenticate(self):
        if self.state is State.UNAUTHENTICATED:
            if not self.__send_request(
                AuthenticateRequest.create(str(self.auth.get_auth_token()))
            ):
                logger.warning(
                    "%s - Failed to send Authentication request",
                    self.describe(),
                )
        else:
            logger.warning(
                "%s - Cannot authenticate, wrong state %s",
                self.describe(),
                self.state,
            )

    def subscribe_now(self, topic):
        request = SubscribePubSubRequest.create(topic)
        if self.send_request(request):
            self.subscriptions[request.subscribe.id] = (topic, request)
            return True
        return False

    def subscribe(self, topic):
        with self.pending_topics_lock:
            if self.state == State.OPEN:
                self.subscribe_now(topic)
            else:
                self.pending_topics.append(topic)

    def elapsed_created(self) -> float:
        return (datetime.now() - self.created_time).total_seconds()

    def elapsed_last_message(self) -> float:
        return (datetime.now() - self.last_message_time).total_seconds()

    def stale(self):
        if self.state == State.CLOSED:
            logger.debug("%s - Stale due to being closed", self.describe())
            return True
        if self.state == State.UNOPENED:
            if (
                self.elapsed_created() > self.created_timeout_seconds
                and internet_connection_available()
            ):
                logger.debug(
                    "%s - Stale due to being Unopened and sitting idle too long",
                    self.describe(),
                )
                return True
        elif (
            self.elapsed_last_message() > self.message_timeout_seconds
            and internet_connection_available()
        ):
            logger.debug("%s - Stale due to no recent messages", self.describe())
            return True
        return False

    def topic(self, subscription_id: str):
        subscription = self.subscriptions.get(subscription_id)
        return None if subscription is None else subscription[0]

    def all_topics(self):
        with self.pending_topics_lock:
            return list(
                combine(
                    (pair[0] for pair in self.subscriptions.values()),
                    self.pending_topics,
                )
            )

    def add_listener(self, listener):
        self.listeners.append(listener)

    def subscribed(self, topic) -> bool:
        topic_str = str(topic)
        return any(str(self_topic) == topic_str for self_topic in self.all_topics())

    def subscribe_pending(self):
        if self.state != State.OPEN:
            logger.warning(
                "%s - Cannot subscribe to pending subscriptions, state is %s",
                self.describe(),
                self.state,
            )
            return

        with self.pending_topics_lock:
            while len(self.pending_topics) > 0:
                topic = self.pending_topics.pop()
                try:
                    self.subscribe_now(topic)
                except Exception:
                    self.pending_topics.append(topic)
                    raise

    @staticmethod
    def on_open(client):
        logger.debug("Hermes client opened: index=%s, id='%s'", client.index, client.id)
        client.state = State.UNWELCOMED

    @staticmethod
    def on_message(client, message: str):
        logger.debug("%s - Received: %s", client.describe(), message.strip())
        client.last_message_time = datetime.now()
        try:
            response = client.json_decoder.decode(message)
            try:
                if isinstance(response, WelcomeResponse):
                    for listener in client.listeners:
                        listener.on_welcome(client, response.welcome.keepalive_sec)
                elif isinstance(response, AuthenticateResponse):
                    for listener in client.listeners:
                        listener.on_authenticate(client, response)
                elif isinstance(response, SubscribeResponse):
                    for listener in client.listeners:
                        listener.on_subscribe(client, response)
                elif isinstance(response, KeepaliveResponse):
                    for listener in client.listeners:
                        listener.on_keepalive(client)
                elif isinstance(response, NotificationResponse):
                    for listener in client.listeners:
                        listener.on_notification(client, response)
                elif isinstance(response, ReconnectResponse):
                    for listener in client.listeners:
                        listener.on_reconnect(client, response.reconnect.url)
                else:
                    logger.error("%s - Unknown response: %s", client.describe(), response)
            except Exception as exc:
                if isinstance(response, NotificationResponse):
                    topic = client.topic(response.notification.subscription.id)
                    logger.error(
                        "%s - Exception raised for topic: %s and message: %s",
                        client.describe(),
                        str(topic),
                        message,
                        exc_info=exc,
                    )
                else:
                    logger.error(
                        "%s - Exception raised for response: %s",
                        client.describe(),
                        response,
                        exc_info=exc,
                    )
                HermesClient.on_error(client, exc)
        except (json.JSONDecodeError, ValueError) as exc:
            HermesClient.on_error(client, exc)

    @staticmethod
    def on_close(client, status_code, reason):
        logger.debug(
            "%s - WebSocket closed: %s - %s",
            client.describe(),
            status_code,
            reason,
        )
        client.state = State.CLOSED
        try:
            for listener in client.listeners:
                listener.on_close(client, status_code, reason)
        except Exception as exc:
            HermesClient.on_error(client, exc)

    @staticmethod
    def on_error(client, error):
        try:
            for listener in client.listeners:
                listener.on_error(client, error)
        except Exception as exc:
            logger.error(
                "%s - Error while handling another error - '%s'",
                client.describe(),
                error,
                exc_info=exc,
            )


class HermesWebSocketListener(abc.ABC):
    def on_welcome(self, client: HermesClient, keepalive_secs: int):
        pass

    def on_authenticate(self, client: HermesClient, response: AuthenticateResponse):
        pass

    def on_subscribe(self, client: HermesClient, response: SubscribeResponse):
        pass

    def on_keepalive(self, client: HermesClient):
        pass

    def on_notification(self, client: HermesClient, response: NotificationResponse):
        pass

    def on_reconnect(self, client: HermesClient, url: str):
        pass

    def on_close(self, client: HermesClient, code: int, reason: str):
        pass

    def on_error(self, client: HermesClient, error: Exception):
        pass
