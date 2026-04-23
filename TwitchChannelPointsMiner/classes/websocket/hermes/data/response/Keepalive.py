from TwitchChannelPointsMiner.classes.websocket.hermes.data.response.Base import ResponseBase


class KeepaliveResponse(ResponseBase):
    def __init__(self, response_id: str, timestamp):
        super().__init__(response_id, "keepalive", timestamp)
