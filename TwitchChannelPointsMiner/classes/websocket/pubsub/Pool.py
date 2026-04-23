import json
import logging
import random
import time
from threading import Thread

from TwitchChannelPointsMiner.classes.Settings import Settings
from TwitchChannelPointsMiner.classes.entities.Message import Message
from TwitchChannelPointsMiner.classes.websocket.Pool import WebSocketPool
from TwitchChannelPointsMiner.classes.websocket.pubsub.Client import PubSubWebSocket
from TwitchChannelPointsMiner.constants import WEBSOCKET
from TwitchChannelPointsMiner.utils import internet_connection_available

logger = logging.getLogger(__name__)


class PubSubWebSocketPool(WebSocketPool):
    __slots__ = ["forced_close", "listeners", "twitch", "ws"]

    def __init__(self, twitch, listeners):
        self.ws = []
        self.twitch = twitch
        self.listeners = [listener for listener in listeners]
        self.forced_close = False

    def start(self):
        logger.debug("Starting PubSub WebSocket Pool")

    def submit(self, topic):
        if self.ws == [] or len(self.ws[-1].topics) >= 50:
            self.ws.append(self.__new(len(self.ws)))
            self.__start(-1)

        self.__submit(-1, topic)

    def __submit(self, index, topic):
        try:
            str(topic)
        except Exception as exc:
            logger.warning(
                "Skipping invalid PubSub topic '%s' (%s)",
                getattr(topic, "topic", topic.__class__.__name__),
                exc,
            )
            return

        if topic not in self.ws[index].topics:
            self.ws[index].topics.append(topic)

        if self.ws[index].is_opened is False:
            self.ws[index].pending_topics.append(topic)
        else:
            self.ws[index].listen(topic, self.twitch.twitch_login.get_auth_token())

    def __new(self, index):
        return PubSubWebSocket(
            index=index,
            parent_pool=self,
            url=WEBSOCKET,
            on_message=PubSubWebSocketPool.on_message,
            on_open=PubSubWebSocketPool.on_open,
            on_error=PubSubWebSocketPool.on_error,
            on_close=PubSubWebSocketPool.on_close,
        )

    def __start(self, index):
        if Settings.disable_ssl_cert_verification is True:
            import ssl

            thread_ws = Thread(
                target=lambda: self.ws[index].run_forever(
                    sslopt={"cert_reqs": ssl.CERT_NONE}
                )
            )
            logger.warning("SSL certificate verification is disabled! Be aware!")
        else:
            thread_ws = Thread(target=lambda: self.ws[index].run_forever())
        thread_ws.daemon = True
        thread_ws.name = f"WebSocket #{self.ws[index].index}"
        thread_ws.start()

    def end(self):
        logger.debug("Closing PubSub WebSocket Pool")
        self.forced_close = True
        for ws in self.ws:
            ws.forced_close = True
            ws.close()

    def check_stale_connections(self):
        for index in range(0, len(self.ws)):
            if (
                self.ws[index].is_reconnecting is False
                and self.ws[index].elapsed_last_ping() > 10
                and internet_connection_available() is True
            ):
                logger.info(
                    f"#{index} - The last PING was sent more than 10 minutes ago. Reconnecting to the WebSocket..."
                )
                PubSubWebSocketPool.handle_reconnection(self.ws[index])

    @staticmethod
    def _log_ws_throttled(ws, level, key, message, *args, ttl=60):
        cache = getattr(ws, "_last_ws_log", None)
        if cache is None:
            cache = {}
            setattr(ws, "_last_ws_log", cache)
        now = time.time()
        last_logged = cache.get(key, 0)
        if now - last_logged >= ttl:
            logger.log(level, message, *args)
            cache[key] = now

    @staticmethod
    def on_open(ws):
        def run():
            ws.is_opened = True
            try:
                ws.ping()
            except Exception:
                PubSubWebSocketPool.handle_reconnection(ws)
                return

            for topic in ws.pending_topics:
                ws.listen(topic, ws.twitch.twitch_login.get_auth_token())

            while ws.is_closed is False:
                if ws.is_reconnecting is False:
                    try:
                        ws.ping()
                    except Exception:
                        PubSubWebSocketPool.handle_reconnection(ws)
                        return
                    time.sleep(random.uniform(25, 30))

                    if ws.elapsed_last_pong() > 5:
                        logger.info(
                            f"#{ws.index} - The last PONG was received more than 5 minutes ago"
                        )
                        PubSubWebSocketPool.handle_reconnection(ws)

        thread_ws = Thread(target=run)
        thread_ws.daemon = True
        thread_ws.start()

    @staticmethod
    def on_error(ws, error):
        error_message = str(error)
        normalized = error_message.lower()
        transient_patterns = (
            "ping pong failed",
            "connection is already closed",
            "broken pipe",
            "bad file descriptor",
            "timed out",
            "ssl",
        )
        is_transient = any(pattern in normalized for pattern in transient_patterns)
        level = logging.WARNING if is_transient else logging.ERROR
        ttl = 120 if is_transient else 30
        key = ("on_error", "transient" if is_transient else error_message)
        PubSubWebSocketPool._log_ws_throttled(
            ws,
            level,
            key,
            "#%s - WebSocket error: %s",
            ws.index,
            error_message,
            ttl=ttl,
        )

    @staticmethod
    def on_close(ws, close_status_code, close_reason):
        logger.info(f"#{ws.index} - WebSocket closed")
        PubSubWebSocketPool.handle_reconnection(ws)

    @staticmethod
    def handle_reconnection(ws):
        if ws.is_reconnecting is False:
            ws.is_closed = True
            ws.keep_running = False
            ws.is_reconnecting = True

            if ws.forced_close is False:
                logger.info(
                    f"#{ws.index} - Reconnecting to Twitch PubSub server in ~60 seconds"
                )
                time.sleep(30)

                while internet_connection_available() is False:
                    random_sleep = random.randint(1, 3)
                    logger.warning(
                        f"#{ws.index} - No internet connection available! Retry after {random_sleep}m"
                    )
                    time.sleep(random_sleep * 60)

                self = ws.parent_pool
                self.ws[ws.index] = self.__new(ws.index)

                self.__start(ws.index)
                time.sleep(30)

                for topic in ws.topics:
                    self.__submit(ws.index, topic)

    @staticmethod
    def on_message(ws, message):
        logger.debug(f"#{ws.index} - Received: {message.strip()}")
        response = json.loads(message)

        if response["type"] == "MESSAGE":
            parsed_message = Message(response["data"])

            if (
                ws.last_message_type_channel is not None
                and ws.last_message_timestamp is not None
                and ws.last_message_timestamp == parsed_message.timestamp
                and ws.last_message_type_channel == parsed_message.identifier
            ):
                return

            ws.last_message_timestamp = parsed_message.timestamp
            ws.last_message_type_channel = parsed_message.identifier

            for listener in ws.parent_pool.listeners:
                listener.on_message(parsed_message)

        elif response["type"] == "RESPONSE":
            nonce = response.get("nonce")
            topic = None
            if nonce and hasattr(ws, "listen_nonces"):
                topic = ws.listen_nonces.pop(nonce, None)

            error_message = response.get("error", "")
            if len(error_message) > 0:
                if "ERR_BADTOPIC" in error_message:
                    if topic is not None:
                        if topic in ws.topics:
                            ws.topics.remove(topic)
                        if topic in ws.pending_topics:
                            ws.pending_topics.remove(topic)
                        try:
                            topic_label = str(topic)
                        except Exception:
                            topic_label = getattr(topic, "topic", "<unknown-topic>")
                        logger.warning(
                            "#%s - Dropping invalid PubSub topic after ERR_BADTOPIC: %s",
                            ws.index,
                            topic_label,
                        )
                    else:
                        logger.warning(
                            "#%s - Received ERR_BADTOPIC but no matching LISTEN nonce was found",
                            ws.index,
                        )
                    return

                logger.error(
                    "Error while trying to listen for a topic: %s",
                    error_message,
                )

                if "ERR_BADAUTH" in error_message:
                    username = ws.twitch.twitch_login.username
                    logger.error(
                        'Received the ERR_BADAUTH error, most likely you have an outdated cookie file "cookies\\%s.pkl". Delete this file and try again.',
                        username,
                    )

        elif response["type"] == "RECONNECT":
            logger.info(f"#{ws.index} - Reconnection required")
            PubSubWebSocketPool.handle_reconnection(ws)

        elif response["type"] == "PONG":
            ws.last_pong = time.time()
