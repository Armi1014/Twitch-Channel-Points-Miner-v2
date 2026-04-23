import abc

from TwitchChannelPointsMiner.classes.websocket.hermes.data.response.Base import (
    ResponseBase,
    Subscription,
)
from TwitchChannelPointsMiner.utils import simple_repr


class NotificationResponse(ResponseBase):
    class DataBase(abc.ABC):
        def __init__(self, subscription: Subscription, notification_type: str):
            self.subscription = subscription
            self.type = notification_type

        def __repr__(self):
            return simple_repr(self)

    class PubSubData(DataBase):
        def __init__(self, subscription: Subscription, pubsub: str):
            super().__init__(subscription, "pubsub")
            self.pubsub = pubsub

    def __init__(self, response_id: str, timestamp, notification):
        super().__init__(response_id, "notification", timestamp)
        self.notification = notification
