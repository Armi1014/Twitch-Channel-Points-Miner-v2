import abc

from TwitchChannelPointsMiner.classes.entities.PubsubTopic import PubsubTopic
from TwitchChannelPointsMiner.classes.websocket.hermes.data.request.Base import RequestBase
from TwitchChannelPointsMiner.utils import create_random_id, format_timestamp, simple_repr


class SubscribeRequestBase(RequestBase, abc.ABC):
    class DataBase(abc.ABC):
        def __init__(self, subscription_type: str, subscription_id: str | None = None):
            self.id = subscription_id or create_random_id(21)
            self.type = subscription_type

        def __repr__(self):
            return simple_repr(self)

    def __init__(self, request_id: str | None = None, timestamp=None):
        super().__init__("subscribe", request_id, timestamp)


class SubscribePubSubRequest(SubscribeRequestBase):
    class Data(SubscribeRequestBase.DataBase):
        class PubSub:
            def __init__(self, topic: str):
                self.topic = topic

            def to_dict(self):
                return {"topic": self.topic}

        def __init__(self, pubsub, subscription_id: str | None = None):
            super().__init__("pubsub", subscription_id)
            self.pubsub = pubsub

        def to_dict(self):
            return {
                "id": self.id,
                "type": self.type,
                "pubsub": self.pubsub.to_dict(),
            }

    def __init__(self, subscribe: Data, request_id: str | None = None, timestamp=None):
        super().__init__(request_id, timestamp)
        self.subscribe = subscribe

    def topic(self):
        return PubsubTopic(self.subscribe.pubsub.topic)

    def to_dict(self):
        return {
            "type": self.type,
            "id": self.id,
            "subscribe": self.subscribe.to_dict(),
            "timestamp": format_timestamp(self.timestamp),
        }

    @staticmethod
    def create(topic: PubsubTopic):
        return SubscribePubSubRequest(
            SubscribePubSubRequest.Data(
                SubscribePubSubRequest.Data.PubSub(str(topic))
            )
        )
