import abc
from datetime import datetime, timezone

from TwitchChannelPointsMiner.utils import create_random_id, simple_repr


class RequestBase(abc.ABC):
    def __init__(self, request_type: str, request_id: str | None = None, timestamp: datetime | None = None):
        self.id = request_id or create_random_id(21)
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.type = request_type

    def __repr__(self):
        return simple_repr(self)
