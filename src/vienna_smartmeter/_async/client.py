"""Contains the Async Smartmeter API Client."""
import asyncio
import json
import logging
import socket
from datetime import datetime
from urllib import parse

import aiohttp
import async_timeout
from lxml import html

from ..errors import SmartmeterLoginError

import base64
import hashlib
import os
import re

logger = logging.getLogger(__name__)

TIMEOUT = 10

class AsyncSmartmeter:
    """Async Smartmeter Client."""

    API_URL_WSTW = "https://api.wstw.at/gateway/WN_SMART_METER_PORTAL_API_B2C/1.0/"
    API_URL_WSTW_B2B = "https://api.wstw.at/gateway/WN_SMART_METER_PORTAL_API_B2B/1.0/"
    API_URL_WN = "https://service.wienernetze.at/sm/api/"
    API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
    AUTH_URL = "https://log.wien/auth/realms/logwien/protocol/openid-connect/"  # noqa
    ORIGIN = "https://smartmeter-web.wienernetze.at"
    REFERER = "https://smartmeter-web.wienernetze.at/"

    def __init__(self, username, password, session=None, timeout=TIMEOUT, input_code_verifier=None):
        """Access the Smart Meter API asynchronously.

        Args:
            username (str): Username used for API Login
            password (str): Password used for API Login
            session (aiohttp.ClientSession): An optional session object
            timeout (int): Timeout for all session calls. Defaults to TIMEOUT.
            input_code_verifier (str): An optional fixed code_verifier for creating a code_challenge
        """
        self._username = username
        self._password = password
        self._session = session or aiohttp.ClientSession()
        self._timeout = timeout
        self._access_token = None

        self._code_verifier = None
        if input_code_verifier is not None:
            if self.is_valid_code_verifier(input_code_verifier):
                self._code_verifier = input_code_verifier

        self._code_challenge = None

    def generate_code_verifier(self):
        """
        generate a code verifier
        """
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

    def generate_code_challenge(self, code_verifier):
        """
        generate a code challenge from the code verifier
        """
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(code_challenge).decode('utf-8').rstrip('=')

    def is_valid_code_verifier(self, code_verifier):
        if not (43 <= len(code_verifier) <= 128):
            return False

        pattern = r'^[A-Za-z0-9\-._~]+$'
        if not re.match(pattern, code_verifier):
            return False

        return True

    async def _get_login_action(self):
        if not hasattr(self, '_code_verifier') or self._code_verifier is None:
           #only generate if it does not exist 
           self._code_verifier = self.generate_code_verifier()

        #generate a code challenge from the code verifier to enhance security
        self._code_challenge = self.generate_code_challenge(self._code_verifier)

        args = {
            "client_id": "wn-smartmeter",
            "redirect_uri": self.REFERER,
            "response_mode": "fragment",
            "response_type": "code",
            "scope": "openid",
            "nonce": "",
            "prompt": "login",
            "code_challenge": self._code_challenge,
            "code_challenge_method": "S256"
        }
        login_url = self.AUTH_URL + "auth?" + parse.urlencode(args)
        logging.debug(f"login_url: {login_url}")
        async with self._session.get(login_url) as response:
            tree = html.fromstring(await response.text())
            return tree.xpath("(//form/@action)")[0]

    async def _get_auth_code(self):
        url = await self._get_login_action()
        logging.debug(f"url: {url}")

        async with self._session.post(
            url,
            data={
                "username": self._username,
                "login": " "
            },
            allow_redirects=False,
        ) as result:
            if result.status != 200:
                raise SmartmeterLoginError("Login action failed.")

            tree = html.fromstring(await result.text())
            action = tree.xpath("(//form/@action)")[0]

        async with self._session.post(
            action,
            data={
                "username": self._username,
                "password": self._password
           },
            allow_redirects=False
        ) as resp:
            if "Location" not in resp.headers:
                raise SmartmeterLoginError(
                    "Authentication failed. Check user credentials."
                )
            auth_code = resp.headers["Location"].split("&code=", 1)[1]
        return auth_code

    async def refresh_token(self):
        """Create a valid access token."""
        async with self._session.request(
            "POST",
            self.AUTH_URL + "token",
            data={
                "code": await self._get_auth_code(),
                "grant_type": "authorization_code",
                "client_id": "wn-smartmeter",
                "redirect_uri": self.REFERER,
                "code_verifier": self._code_verifier
            },
        ) as response:
            if response.status != 200:
                raise SmartmeterLoginError(
                    "Authentication failed. Check user credentials."
                )
            self._access_token = json.loads(await response.text())["access_token"]

        logger.debug("Successfully authenticated Smart Meter API")

    async def async_get_access_token(self):
        """Return a valid access token."""
        pass

    def _dt_string(self, dt):
        return dt.strftime(self.API_DATE_FORMAT)[:-3] + "Z"

    def _get_first_zaehlpunkt(self):
        """Get first zaehlpunkt."""
        return self.get_zaehlpunkte()[0]["zaehlpunkte"][0]["zaehlpunktnummer"]

    def _get_customerid(self):
        """Returns 'geschaeftspartner' = CustomerID for currently logged in user."""
        return self.profil()["defaultGeschaeftspartnerRegistration"]["geschaeftspartner"]

    async def get_zaehlpunkte(self):
        """Get zaehlpunkte for currently logged in user."""
        return await self._request("zaehlpunkte")

    async def get_verbrauch_raw(
        self,
        date_from,
        date_to=None,
        zaehlpunkt=None,
    ):
        """Get verbrauch_raw from the API."""
        if date_to is None:
            date_to = datetime.now()
        if zaehlpunkt is None:
            zaehlpunkt = self._get_first_zaehlpunkt()
        endpoint = f"messdaten/{self._get_customerid()}/{zaehlpunkt}/verbrauchRaw"
        query = {
            "dateFrom": self._dt_string(date_from),
            "dateTo": self._dt_string(date_to),
            "granularity": "DAY",
        }
        return await self._request(endpoint, query=query)

    async def profil(self):
        """Get profil of logged in user."""
        return await self._request("user/profile", base_url=self.API_URL_WN)

    async def zaehlpunkte(self):
        """Returns zaehlpunkte for currently logged in user."""
        return await self._request("zaehlpunkte")

    async def welcome(self):
        """Returns response from 'welcome' endpoint."""
        return await self._request("zaehlpunkt/default/welcome")

    async def _request(
        self,
        endpoint,
        base_url=None,
        method="GET",
        data=None,
        query=None,
    ):
        """Send requests to the Smartmeter API."""
        if base_url is None:
            base_url = self.API_URL_WSTW
        url = "{0}{1}".format(base_url, endpoint)

        if query:
            separator = "?" if "?" not in endpoint else "&"
            url += separator + parse.urlencode(query)

        logger.debug(f"REQUEST: {url}")

        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "X-Gateway-APIKey": "afb0be74-6455-44f5-a34d-6994223020ba",
        }

        try:
            async with async_timeout.timeout(self._timeout):
                response = await self._session.request(
                    method, url, headers=headers, json=data
                )
                logger.debug(f"REQUEST: {response}")
                if response.status == 401:
                    await self.refresh_token()
                    return await self._request(endpoint, base_url, method, data, query)
                return await response.json()

        except asyncio.TimeoutError as exception:
            logger.error(f"Timeout error fetching information from {url} - {exception}")
        except (KeyError, TypeError) as exception:
            logger.error(f"Error parsing information from {url} - {exception}")
        except (aiohttp.ClientError, socket.gaierror) as exception:
            logger.error(f"Error fetching information from {url} - {exception}")
        except Exception as exception:
            logger.error(f"Something really wrong happened! - {exception}")
