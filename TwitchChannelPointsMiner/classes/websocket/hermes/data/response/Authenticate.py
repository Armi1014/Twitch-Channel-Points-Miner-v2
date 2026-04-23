import abc

from TwitchChannelPointsMiner.classes.websocket.hermes.data.response.Base import ResponseBase
from TwitchChannelPointsMiner.utils import simple_repr


class AuthenticateResponse(ResponseBase):
    class DataBase(abc.ABC):
        def __init__(self, result: str):
            self.result = result

        def __repr__(self):
            return simple_repr(self)

    class DataOk(DataBase):
        def __init__(self):
            super().__init__("ok")

    class DataError(DataBase):
        def __init__(self, result: str, error: str, error_code: str):
            super().__init__(result)
            self.error = error
            self.error_code = error_code

    def __init__(self, response_id: str, parent_id: str, timestamp, authenticate_response):
        super().__init__(response_id, "authenticateResponse", timestamp)
        self.parent_id = parent_id
        self.authenticate_response = authenticate_response

    def has_error(self):
        return isinstance(self.authenticate_response, AuthenticateResponse.DataError)
