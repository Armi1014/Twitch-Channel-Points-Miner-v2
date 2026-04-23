import abc

from TwitchChannelPointsMiner.utils import simple_repr


class ResponseBase(abc.ABC):
    def __init__(self, response_id: str, response_type: str, timestamp):
        self.id = response_id
        self.type = response_type
        self.timestamp = timestamp

    def __repr__(self):
        return simple_repr(self)


class Subscription:
    def __init__(self, subscription_id: str):
        self.id = subscription_id

    def __repr__(self):
        return simple_repr(self)
