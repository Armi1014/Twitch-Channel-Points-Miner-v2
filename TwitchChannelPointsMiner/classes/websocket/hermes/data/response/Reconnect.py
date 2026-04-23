from TwitchChannelPointsMiner.classes.websocket.hermes.data.response.Base import ResponseBase
from TwitchChannelPointsMiner.utils import simple_repr


class ReconnectResponse(ResponseBase):
    class Data:
        def __init__(self, url: str):
            self.url = url

        def __repr__(self):
            return simple_repr(self)

    def __init__(self, response_id: str, timestamp, reconnect: Data):
        super().__init__(response_id, "reconnect", timestamp)
        self.reconnect = reconnect
