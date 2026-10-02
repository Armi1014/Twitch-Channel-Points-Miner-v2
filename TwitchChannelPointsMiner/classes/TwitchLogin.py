# Based on https://github.com/derrod/twl.py
# Original Copyright (c) 2020 Rodney
# The MIT License (MIT)

import copy
# import getpass
import logging
import os
import pickle

# import webbrowser
# import browser_cookie3

import requests

from TwitchChannelPointsMiner.classes.Exceptions import (
    BadCredentialsException,
    WrongCookiesException,
)
from TwitchChannelPointsMiner.constants import CLIENT_ID, GQLOperations, USER_AGENTS

from time import sleep, monotonic

logger = logging.getLogger(__name__)

"""def interceptor(request) -> str:
    if (
        request.method == 'POST'
        and request.url == 'https://passport.twitch.tv/protected_login'
    ):
        import json
        body = request.body.decode('utf-8')
        data = json.loads(body)
        data['client_id'] = CLIENT_ID
        request.body = json.dumps(data).encode('utf-8')
        del request.headers['Content-Length']
        request.headers['Content-Length'] = str(len(request.body))"""


class TwitchLogin(object):
    __slots__ = [
        "client_id",
        "device_id",
        "token",
        "login_check_result",
        "session",
        "session",
        "username",
        "password",
        "user_id",
        "email",
        "cookies",
        "shared_cookies"
    ]

    def __init__(self, client_id, device_id, username, user_agent, password=None):
        self.client_id = client_id
        self.device_id = device_id
        self.token = None
        self.login_check_result = False
        self.session = requests.session()
        self.session.headers.update(
            {"Client-ID": self.client_id,
                "X-Device-Id": self.device_id, "User-Agent": user_agent}
        )
        self.username = username
        self.password = password
        self.user_id = None
        self.email = None

        self.cookies = []
        self.shared_cookies = []

    def login_flow(self):
        logger.info("You'll have to login to Twitch!")
        response = self.send_oauth_request(
            "https://id.twitch.tv/oauth2/device",
            {
                "client_id": self.client_id,
                "scopes": (
                    "channel_read chat:read user_blocks_edit "
                    "user_blocks_read user_follows_edit user_read"
                ),
            },
        )
        if response.status_code != 200:
            logger.error(
                "Unable to request a Twitch login code (HTTP %s)", response.status_code
            )
            return False
        device = response.json()
        if not all(
            device.get(key) for key in ("user_code", "device_code", "expires_in")
        ):
            logger.error("Twitch did not return a valid device login code")
            return False
        interval = max(1, float(device.get("interval", 5)))
        expires_at = monotonic() + float(device["expires_in"])
        logger.info(
            "Open https://www.twitch.tv/activate and enter this code: %s",
            device["user_code"],
        )
        post_data = {
            "client_id": self.client_id,
            "device_code": device["device_code"],
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }
        while monotonic() < expires_at:
            sleep(min(interval, max(0, expires_at - monotonic())))
            if monotonic() >= expires_at:
                break
            response = self.send_oauth_request(
                "https://id.twitch.tv/oauth2/token", post_data
            )
            payload = response.json()
            if response.status_code == 200 and payload.get("access_token"):
                self.set_token(payload["access_token"])
                return self.check_login()
            error = payload.get("error") or payload.get("message") or "unknown error"
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            logger.error("Twitch device login failed: %s", error)
            return False
        logger.error("Twitch login code expired; start again to request a new code")
        return False

    def set_token(self, new_token):
        self.token = new_token
        self.login_check_result = False
        self.user_id = None
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    # def send_login_request(self, json_data):
    def send_oauth_request(self, url, json_data):
        # response = self.session.post("https://passport.twitch.tv/protected_login", json=json_data)
        """response = self.session.post("https://passport.twitch.tv/login", json=json_data, headers={
            'Accept': 'application/vnd.twitchtv.v3+json',
            'Accept-Encoding': 'gzip',
            'Accept-Language': 'en-US',
            'Content-Type': 'application/json; charset=UTF-8',
            'Host': 'passport.twitch.tv'
        },)"""
        response = self.session.post(
            url,
            data=json_data,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
                "Accept-Language": "en-US",
                "Cache-Control": "no-cache",
                "Client-Id": self.client_id,
                "Host": "id.twitch.tv",
                "Origin": "https://android.tv.twitch.tv",
                "Pragma": "no-cache",
                "Referer": "https://android.tv.twitch.tv/",
                "User-Agent": USER_AGENTS["Android"]["TV"],
                "X-Device-Id": self.device_id,
            },
            timeout=20,
        )
        return response

    def login_flow_backup(self, password=None):
        """Backup OAuth Selenium login
        from undetected_chromedriver import ChromeOptions
        import seleniumwire.undetected_chromedriver.v2 as uc
        from selenium.webdriver.common.by import By
        from time import sleep

        HEADLESS = False

        options = uc.ChromeOptions()
        if HEADLESS is True:
            options.add_argument('--headless')
        options.add_argument('--log-level=3')
        options.add_argument('--disable-web-security')
        options.add_argument('--allow-running-insecure-content')
        options.add_argument('--lang=en')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-gpu')
        # options.add_argument("--user-agent=\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36\"")
        # options.add_argument("--window-size=1920,1080")
        # options.set_capability("detach", True)

        logger.info(
            'Now a browser window will open, it will login with your data.')
        driver = uc.Chrome(
            options=options, use_subprocess=True  # , executable_path=EXECUTABLE_PATH
        )
        driver.request_interceptor = interceptor
        driver.get('https://www.twitch.tv/login')

        driver.find_element(By.ID, 'login-username').send_keys(self.username)
        driver.find_element(By.ID, 'password-input').send_keys(password)
        sleep(0.3)
        driver.execute_script(
            'document.querySelector("#root > div > div.scrollable-area > div.simplebar-scroll-content > div > div > div > div.Layout-sc-nxg1ff-0.gZaqky > form > div > div:nth-child(3) > button > div > div").click()'
        )

        logger.info(
            'Enter your verification code in the browser and wait for the Twitch website to load, then press Enter here.'
        )
        input()

        logger.info("Extracting cookies...")
        self.cookies = driver.get_cookies()
        # print(self.cookies)
        # driver.close()
        driver.quit()
        self.username = self.get_cookie_value("login")
        # print(f"self.username: {self.username}")

        if not self.username:
            logger.error("Couldn't extract login, probably bad cookies.")
            return False

        return self.get_cookie_value("auth-token")"""

        # logger.error("Backup login flow is not available. Use a VPN or wait a while to avoid the CAPTCHA.")
        # return False

        """Backup OAuth login flow in case manual captcha solving is required"""
        browser = input(
            "What browser do you use? Chrome (1), Firefox (2), Other (3): "
        ).strip()
        if browser not in ("1", "2"):
            logger.info("Your browser is unsupported, sorry.")
            return None

        input(
            "Please login inside your browser of choice (NOT incognito mode) and press Enter..."
        )
        logger.info("Loading cookies saved on your computer...")
        twitch_domain = ".twitch.tv"
        if browser == "1":  # chrome
            cookie_jar = browser_cookie3.chrome(domain_name=twitch_domain)
        else:
            cookie_jar = browser_cookie3.firefox(domain_name=twitch_domain)
        # logger.info(f"cookie_jar: {cookie_jar}")
        cookies_dict = requests.utils.dict_from_cookiejar(cookie_jar)
        # logger.info(f"cookies_dict: {cookies_dict}")
        self.username = cookies_dict.get("login")
        self.shared_cookies = cookies_dict
        return cookies_dict.get("auth-token")

    def check_login(self):
        if self.login_check_result:
            return self.login_check_result
        if self.token is None:
            return False

        response = self.session.get(
            "https://id.twitch.tv/oauth2/validate",
            headers={"Authorization": f"OAuth {self.token}"},
            timeout=20,
        )
        if response.status_code == 401:
            return False
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not data.get("user_id"):
            return False
        if str(data.get("login", "")).lower() != self.username.lower():
            logger.error("Twitch token belongs to a different account")
            return False
        self.user_id = int(data["user_id"])
        self.login_check_result = True
        return self.login_check_result

    def save_cookies(self, cookies_file):
        logger.info("Saving cookies to your computer..")
        cookies_dict = self.session.cookies.get_dict()
        # print(f"cookies_dict2pickle: {cookies_dict}")
        cookies_dict["auth-token"] = self.token
        if "persistent" not in cookies_dict:  # saving user id cookies
            cookies_dict["persistent"] = self.user_id

        # old way saves only 'auth-token' and 'persistent'
        self.cookies = []
        # cookies_dict = self.shared_cookies
        # print(f"cookies_dict2pickle: {cookies_dict}")
        for cookie_name, value in cookies_dict.items():
            self.cookies.append({"name": cookie_name, "value": value})
        # print(f"cookies2pickle: {self.cookies}")
        pickle.dump(self.cookies, open(cookies_file, "wb"))

    def get_cookie_value(self, key):
        for cookie in self.cookies:
            if cookie["name"] == key:
                if cookie["value"] is not None:
                    return cookie["value"]
        return None

    def load_cookies(self, cookies_file):
        if os.path.isfile(cookies_file):
            self.cookies = pickle.load(open(cookies_file, "rb"))
        else:
            raise WrongCookiesException("There must be a cookies file!")

    def get_user_id(self):
        if self.user_id is not None:
            return self.user_id
        persistent = self.get_cookie_value("persistent")
        user_id = (
            int(persistent.split("%")[
                0]) if persistent is not None else self.user_id
        )
        if user_id is None:
            if self.__set_user_id() is True:
                return self.user_id
        return user_id

    def __set_user_id(self):
        json_data = copy.deepcopy(GQLOperations.GetIDFromLogin)
        json_data["variables"]["login"] = self.username
        response = self.session.post(GQLOperations.url, json=json_data, timeout=20)

        if response.status_code == 200:
            json_response = response.json()
            if (
                "data" in json_response
                and "user" in json_response["data"]
                and json_response["data"]["user"]["id"] is not None
            ):
                self.user_id = json_response["data"]["user"]["id"]
                return True
        return False

    def get_auth_token(self):
        return (
            self.token
            if self.token is not None
            else self.get_cookie_value("auth-token")
        )
