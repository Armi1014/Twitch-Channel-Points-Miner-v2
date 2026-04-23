from TwitchChannelPointsMiner.classes.websocket.hermes.data.response.Base import (
    ResponseBase,
    Subscription,
)


class SubscribeResponse(ResponseBase):
    class Data:
        def __init__(self, result: str, subscription: Subscription):
            self.result = result
            self.subscription = subscription

    def __init__(self, response_id: str, parent_id: str, timestamp, subscribe_response: Data):
        super().__init__(response_id, "subscribeResponse", timestamp)
        self.parent_id = parent_id
        self.subscribe_response = subscribe_response
