from TwitchChannelPointsMiner.classes.websocket.hermes.data.request.Base import RequestBase
from TwitchChannelPointsMiner.utils import format_timestamp, simple_repr


class AuthenticateRequest(RequestBase):
    class Data:
        def __init__(self, token: str):
            self.token = token

        def to_dict(self):
            return {"token": self.token}

        def __repr__(self):
            return simple_repr(self)

    def __init__(self, authenticate: Data, request_id: str | None = None, timestamp=None):
        super().__init__("authenticate", request_id, timestamp)
        self.authenticate = authenticate

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "authenticate": self.authenticate.to_dict(),
            "timestamp": format_timestamp(self.timestamp),
        }

    @staticmethod
    def create(token: str):
        return AuthenticateRequest(AuthenticateRequest.Data(token))
