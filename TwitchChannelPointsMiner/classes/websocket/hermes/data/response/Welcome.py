from TwitchChannelPointsMiner.classes.websocket.hermes.data.response.Base import ResponseBase
from TwitchChannelPointsMiner.utils import simple_repr


class WelcomeResponse(ResponseBase):
    class Data:
        def __init__(self, keepalive_sec: int, recovery_url: str, session_id: str):
            self.keepalive_sec = keepalive_sec
            self.recovery_url = recovery_url
            self.session_id = session_id

        def __repr__(self):
            return simple_repr(self)

    def __init__(self, response_id: str, timestamp, welcome: Data):
        super().__init__(response_id, "welcome", timestamp)
        self.welcome = welcome
