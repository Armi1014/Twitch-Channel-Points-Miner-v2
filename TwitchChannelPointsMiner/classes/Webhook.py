from textwrap import dedent

import requests

from TwitchChannelPointsMiner.classes.Settings import Events


class Webhook(object):
    __slots__ = ["endpoint", "method", "events"]

    def __init__(self, endpoint: str, method: str, events: list):
        self.endpoint = endpoint
        self.method = method
        self.events = [str(e) for e in events]

    def send(self, message: str, event: Events) -> None:

        if str(event) in self.events:
            params = {"event_name": str(event), "message": dedent(message)}

            if self.method.lower() == "get":
                requests.get(
                    url=self.endpoint, params=params, timeout=20
                ).raise_for_status()
            elif self.method.lower() == "post":
                requests.post(
                    url=self.endpoint, params=params, timeout=20
                ).raise_for_status()
            else:
                raise ValueError("Invalid method, use POST or GET")
