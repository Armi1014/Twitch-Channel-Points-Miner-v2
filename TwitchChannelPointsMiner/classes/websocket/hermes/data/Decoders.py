import abc
import json

from dateutil import parser

from TwitchChannelPointsMiner.classes.websocket.hermes.data.response import (
    AuthenticateResponse,
    KeepaliveResponse,
    NotificationResponse,
    ReconnectResponse,
    Response,
    SubscribeResponse,
    Subscription,
    WelcomeResponse,
)


def decode_timestamp(value: str):
    return parser.parse(value)


def decode_welcome_data(data: dict):
    return WelcomeResponse.Data(
        int(data["keepaliveSec"]),
        data["recoveryUrl"],
        data["sessionId"],
    )


def decode_authenticate_response_data(data: dict):
    result = data["result"]
    if result == "ok":
        return AuthenticateResponse.DataOk()
    return AuthenticateResponse.DataError(
        result=result,
        error=data.get("error", ""),
        error_code=data.get("errorCode", data.get("error_code", "")),
    )


def decode_subscription(data: dict):
    return Subscription(data["id"])


def decode_subscribe_response_data(data: dict):
    return SubscribeResponse.Data(
        result=data["result"],
        subscription=decode_subscription(data["subscription"]),
    )


def decode_notification_response_data(data: dict):
    notification_type = data["type"]
    if notification_type == "pubsub":
        return NotificationResponse.PubSubData(
            subscription=decode_subscription(data["subscription"]),
            pubsub=data["pubsub"],
        )
    raise ValueError(
        f"Invalid subscription type {notification_type} when decoding NotificationResponse."
    )


def decode_reconnect_response_data(data: dict):
    return ReconnectResponse.Data(data["url"])


def decode_response(data: dict) -> Response:
    response_id = data["id"]
    response_type = data["type"]
    timestamp = decode_timestamp(data["timestamp"])
    if response_type == "welcome":
        return WelcomeResponse(response_id, timestamp, decode_welcome_data(data["welcome"]))
    if response_type == "keepalive":
        return KeepaliveResponse(response_id, timestamp)
    if response_type == "authenticateResponse":
        return AuthenticateResponse(
            response_id,
            data["parentId"],
            timestamp,
            decode_authenticate_response_data(data["authenticateResponse"]),
        )
    if response_type == "subscribeResponse":
        return SubscribeResponse(
            response_id,
            data["parentId"],
            timestamp,
            decode_subscribe_response_data(data["subscribeResponse"]),
        )
    if response_type == "notification":
        return NotificationResponse(
            response_id,
            timestamp,
            decode_notification_response_data(data["notification"]),
        )
    if response_type == "reconnect":
        return ReconnectResponse(
            response_id,
            timestamp,
            decode_reconnect_response_data(data["reconnect"]),
        )
    raise ValueError(f"Invalid type {response_type} when decoding Response.")


class ResponseDecoder(abc.ABC):
    @abc.abstractmethod
    def decode(self, data: str) -> Response:
        raise NotImplementedError()


class JsonDecoder(ResponseDecoder):
    def decode(self, data: str) -> Response:
        return decode_response(json.loads(data))
