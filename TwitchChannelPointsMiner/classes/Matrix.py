from textwrap import dedent

import logging
import requests
from urllib.parse import quote
from uuid import uuid4

from TwitchChannelPointsMiner.classes.Settings import Events


class Matrix(object):
    __slots__ = ["access_token", "homeserver", "room_id", "events"]

    def __init__(self, username: str, password: str, homeserver: str, room_id: str, events: list):
        self.homeserver = homeserver.rstrip("/")
        if "://" not in self.homeserver:
            self.homeserver = f"https://{self.homeserver}"
        self.room_id = quote(room_id, safe="")
        self.events = [str(e) for e in events]

        self.access_token = None
        try:
            response = requests.post(
                url=f"{self.homeserver}/_matrix/client/v3/login",
                json={
                    "user": username,
                    "password": password,
                    "type": "m.login.password",
                },
                timeout=20,
            )
            response.raise_for_status()
            body = response.json()
            self.access_token = (
                body.get("access_token") if isinstance(body, dict) else None
            )
        except requests.exceptions.RequestException as exc:
            logging.getLogger(__name__).warning(
                "Matrix login failed (%s)", type(exc).__name__
            )
            return

        if not self.access_token:
            logging.getLogger(__name__).info(
                "Invalid Matrix password provided. Notifications will not be sent."
            )

    def send(self, message: str, event: Events) -> None:
        if str(event) in self.events and self.access_token:
            requests.put(
                url=f"{self.homeserver}/_matrix/client/v3/rooms/{self.room_id}/send/m.room.message/{uuid4().hex}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"body": dedent(message), "msgtype": "m.text"},
                timeout=20,
            ).raise_for_status()
