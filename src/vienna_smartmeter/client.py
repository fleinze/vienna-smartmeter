"""Contains the Smartmeter API Client."""
import logging
from datetime import datetime
from urllib import parse

import requests, base64, hashlib, os, re
from lxml import html

from .errors import SmartmeterLoginError

logger = logging.getLogger(__name__)


class Smartmeter:
    """Smartmeter client."""

    API_URL_WSTW = "https://api.wstw.at/gateway/WN_SMART_METER_PORTAL_API_B2C/1.0/"
    API_URL_WSTW_B2B = "https://api.wstw.at/gateway/WN_SMART_METER_PORTAL_API_B2B/1.0/"
    API_URL_WN = "https://service.wienernetze.at/sm/api/"
    API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
    AUTH_URL = "https://log.wien/auth/realms/logwien/protocol/openid-connect/"  # noqa
    ORIGIN = "https://smartmeter-web.wienernetze.at"
    REFERER = "https://smartmeter-web.wienernetze.at/"
    USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0" # optional
    def __init__(self, username, password, login=True, input_code_verifier=None):
        """Access the Smartmeter API.

        Args:
            username (str): Username used for API Login.
            password (str): Password used for API Login.
            login (bool, optional): If _login() should be called. Defaults to True.
            input_code_verifier (str): An optional fixed code_verifier for creating a code_challenge
        """
        self.username = username
        self.password = password
        self.session = requests.Session()
        self._access_token = None

        self._code_verifier = None
        if input_code_verifier is not None:
            if self.is_valid_code_verifier(input_code_verifier):
                self._code_verifier = input_code_verifier

        self.session.headers.update({
           "User-Agent": self.USER_AGENT, #optional
           "Referer": self.REFERER,
           "Origin": self.ORIGIN,
        })

        if login:
            self._login()


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
        """
        validate input
        """
        if not (43 <= len(code_verifier) <= 128):
            return False

        pattern = r'^[A-Za-z0-9\-._~]+$'
        if not re.match(pattern, code_verifier):
            return False

        return True

    def _login(self):
        if not hasattr(self, '_code_verifier') or self._code_verifier is None:
            #only generate code_verifier if it does not exist 
            self._code_verifier = self.generate_code_verifier()

        #generate a code challenge from the code_verifier to enhance security
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
            "code_challenge_method": "S256",
        }
        login_url = self.AUTH_URL + "auth?" + parse.urlencode(args)
        result = self.session.get(login_url)
        tree = html.fromstring(result.content)

        forms = tree.xpath("(//form/@action)")
        action = forms[0]

        result = self.session.post(
           action,
           data={
              "username": self.username,
              "login": ""
           },
           allow_redirects=False,
        )
        tree = html.fromstring(result.content)
        action = tree.xpath("(//form/@action)")[0]

        result = self.session.post(
            action,
            data={
                "username": self.username,
                "password": self.password,
            },
            allow_redirects=False,
        )

        if "Location" not in result.headers:
            raise SmartmeterLoginError("Login failed. Check username/password.")

        code = result.headers["Location"].split("&code=", 1)[1]

        result = self.session.post(
            self.AUTH_URL + "token",
            data={
                "code": code,
                "grant_type": "authorization_code",
                "client_id": "wn-smartmeter",
                "redirect_uri": self.REFERER,
                "code_verifier": self._code_verifier,
            },
        )

        self._access_token = result.json()["access_token"]

    def _dt_string(self, datetime_string):
        return datetime_string.strftime(self.API_DATE_FORMAT)[:-3] + "Z"

    def _call_api_wstw(
        self,
        endpoint,
        base_url=None,
        method="GET",
        data=None,
        query=None,
        return_response=False,
    ):
        if base_url is None:
            base_url = self.API_URL_WSTW
        url = "{0}{1}".format(base_url, endpoint)

        if query:
            url += ("?" if "?" not in endpoint else "&") + parse.urlencode(query)

        logger.debug("REQUEST: {}", url)

        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "X-Gateway-APIKey": "afb0be74-6455-44f5-a34d-6994223020ba",
            "Accept": "application/json",
        }

        if data:
            logger.debug("DATA: {}", data)
            headers["Content-Type"] = "application/json"

        response = self.session.request(method, url, headers=headers, json=data)

        if return_response:
            return response

        return response.json()

    def _call_api_wstw_b2b(
        self,
        endpoint,
        base_url=None,
        method="GET",
        data=None,
        query=None,
        return_response=False,
    ):
        if base_url is None:
            base_url = self.API_URL_WSTW_B2B
        url = "{0}{1}".format(base_url, endpoint)

        if query:
            url += ("?" if "?" not in endpoint else "&") + parse.urlencode(query)

        logger.debug("REQUEST: {}", url)

        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "X-Gateway-APIKey": "93d5d520-7cc8-11eb-99bc-ba811041b5f6",
            "Accept": "application/json",
        }

        if data:
            logger.debug("DATA: {}", data)
            headers["Content-Type"] = "application/json"

        response = self.session.request(method, url, headers=headers, json=data)

        if return_response:
            return response

        return response.json()

    def _call_api_wn(
        self,
        endpoint,
        base_url=None,
        method="GET",
        data=None,
        query=None,
        return_response=False,
    ):
        if base_url is None:
            base_url = self.API_URL_WN
        url = "{0}{1}".format(base_url, endpoint)

        if query:
            url += ("?" if "?" not in endpoint else "&") + parse.urlencode(query)

        logger.debug("REQUEST: {}", url)

        headers = {
            "Authorization": f"Bearer {self._access_token}",
        }

        if data:
            logger.debug("DATA: {}", data)
            headers["Content-Type"] = "application/json"

        response = self.session.request(method, url, headers=headers, json=data)

        if return_response:
            return response

        return response.json()

    def _get_first_zaehlpunkt(self):
        return self.zaehlpunkte()[0]["zaehlpunkte"][0]["zaehlpunktnummer"]

    def _get_customerid(self):
        """Returns 'geschaeftspartner' = CustomerID for currently logged in user."""
        return self.profil()["defaultGeschaeftspartnerRegistration"]["geschaeftspartner"]

    def zaehlpunkte(self):
        """Returns zaehlpunkte for currently logged in user."""
        return self._call_api_wstw("zaehlpunkte")

    def baseInformation(self):
        """Returns response from 'baseInformation' endpoint."""
        return self._call_api_wstw("zaehlpunkt/baseInformation")

    def consumptions(self):
        """Returns response from 'consumptions' endpoint."""
        return self._call_api_wstw("zaehlpunkt/consumptions")

    def pmaxReadings(self):
        """Returns response from 'pmaxReadings' endpoint."""
        return self._call_api_wstw("zaehlpunkt/pmaxReadings")

    def meterReadings(self):
        """Returns response from 'meterReadings' endpoint."""
        return self._call_api_wstw("zaehlpunkt/meterReadings")

    def verbrauch_raw(self, date_from, date_to=None, zaehlpunkt=None, rolle=None):
        """
        Legacy, do not use for new implementations

        Returns energy usage.

        Args:
            date_from (datetime): Start date for energy usage request
            date_to (datetime, optional): End date for energy usage request.
                Defaults to datetime.now().
            zaehlpunkt (str, optional): Id for desired smartmeter.
                If None check for first meter in user profile.

        Returns:
            dict: JSON response of api call
        """
        if rolle is None:
            rolle = "V001"
        if date_to is None:
            date_to = datetime.now()
        if zaehlpunkt is None:
            zaehlpunkt = self._get_first_zaehlpunkt()
        customerid = self._get_customerid()
        endpoint = "/user/messwerte/bewegungsdaten"
        query = {
            "geschaeftspartner": customerid,
            "zaehlpunktnummer": zaehlpunkt,
            "rolle": rolle,
            "zeitpunktVon": self._dt_string(date_from),
            "zeitpunktBis": self._dt_string(date_to),
            "aggregat": "SUM_PER_DAY",
        }
        return self._call_api_wn(endpoint, query=query)

    def verbrauch(self, date_from, date_to=None, zaehlpunkt=None, rolle=None):
        """
        Legacy, do not use for new implementations

        Returns energy usage.

        Args:
            date_from (datetime.datetime): Starting date for energy usage request
            date_to (datetime.datetime, optional): Ending date for energy usage request.
                Defaults to datetime.datetime.now().
            zaehlpunkt (str, optional): Id for desired smartmeter.
                If None check for first meter in user profile.

        Returns:
            dict: JSON response of api call to
        """
        if rolle is None:
            rolle = "V002"
        if date_to is None:
            date_to = datetime.now()
        if zaehlpunkt is None:
            zaehlpunkt = self._get_first_zaehlpunkt()
        customerid = self._get_customerid()
        endpoint = "/user/messwerte/bewegungsdaten"
        query = {
            "geschaeftspartner": customerid,
            "zaehlpunktnummer": zaehlpunkt,
            "rolle": rolle,
            "zeitpunktVon": self._dt_string(date_from),
            "zeitpunktBis": self._dt_string(date_to),
            "aggregat": "NONE",
        }
        return self._call_api_wn(endpoint, query=query)

    def bewegungsdaten(self, date_from, date_to=None, zaehlpunkt=None, rolle=None, aggregat=None):
        """
        Returns energy usage.

        Args:
            date_from (datetime.datetime): Starting date for energy usage request
            date_to (datetime.datetime, optional): Ending date for energy usage request.
                Defaults to datetime.datetime.now().
            zaehlpunkt (str, optional): Id for desired smartmeter.
                If None check for first meter in user profile.
            rolle (str, optional):
                'V001' for quarter hour (default)
                'V002' for daily averages
            aggregat (str, optional):
                'NONE' or 'SUM_PER_DAY' are valid values

        Returns:
            dict: JSON response of api call to 
            '/user/messwerte/bewegungsdaten'
        """
        if rolle is None:
            rolle = "V001"
        if date_to is None:
            date_to = datetime.now()
        if zaehlpunkt is None:
            zaehlpunkt = self._get_first_zaehlpunkt()
        customerid = self._get_customerid()
        endpoint = "/user/messwerte/bewegungsdaten"
        query = {
            "geschaeftspartner": customerid,
            "zaehlpunktnummer": zaehlpunkt,
            "rolle": rolle,
            "zeitpunktVon": self._dt_string(date_from),
            "zeitpunktBis": self._dt_string(date_to),
        }
        if aggregat is not None:
            query["aggregat"]=aggregat
        return self._call_api_wn(endpoint, query=query)

    def messwerte(self, date_from, date_to=None, zaehlpunkt=None,wertetyp="METER_READ"):
        """Returns energy usage / Response from messwerte endpoint.

        Args:
            date_from (datetime.datetime): Starting date for energy usage request
            date_to (datetime.datetime, optional): Ending date for energy usage request.
                Defaults to datetime.datetime.now().
            zaehlpunkt (str, optional): Id for desired smartmeter.
                If None check for first meter in user profile.
            wertetyp (str, optional): "DAY", "QUARTER_HOUR" or "METER_READ".
                Defaults to "METER_READ"

        Returns:
            dict: JSON response of api call to
                'zaehlpunkte/CUSTOMERID/ZAEHLPUNKT/messwerte'
        """
        if date_to is None:
            date_to = datetime.now()
        if zaehlpunkt is None:
            zaehlpunkt = self._get_first_zaehlpunkt()
        endpoint = "zaehlpunkte/{0}/{1}/messwerte".format(self._get_customerid(),zaehlpunkt)
        query = {
            "datumVon": date_from.strftime("%Y-%m-%d"),
            "datumBis": date_to.strftime("%Y-%m-%d"),
            "wertetyp": wertetyp,
        }
        return self._call_api_wstw_b2b(endpoint, query=query)

    def profil(self):
        """Returns profil of logged in user.

        Returns:
            dict: JSON response of api call to 'w/user/profile'
        """
        return self._call_api_wn("user/profile")

    def ereignisse(self, date_from, date_to=None, zaehlpunkt=None):
        """Returns events between date_from and date_to of a specific smart meter.

        Args:
            date_from (datetime.datetime): Starting date for request
            date_to (datetime.datetime, optional): Ending date for request.
                Defaults to datetime.datetime.now().
            zaehlpunkt (str, optional): Id for desired smart meter.
                If is None check for first meter in user profile.

        Returns:
            dict: JSON response of api call to 'w/user/ereignisse'
        """
        if date_to is None:
            date_to = datetime.now()
        if zaehlpunkt is None:
            zaehlpunkt = self._get_first_zaehlpunkt()
        query = {
            "zaehlpunkt": zaehlpunkt,
            "dateFrom": self._dt_string(date_from),
            "dateUntil": self._dt_string(date_to),
        }
        return self._call_api_wn("user/ereignisse", query=query)

    def create_ereignis(self, zaehlpunkt, name, date_from, date_to=None):
        """Creates new event.

        Args:
            zaehlpunkt (str): Id for desired smartmeter.
            name (str): Event name
            date_from (datetime.datetime): (Starting) date for request
            date_to (datetime.datetime, optional): Ending date for request.

        Returns:
            dict: JSON response of api call to 'w/user/ereignis'
        """
        if date_to is None:
            dto = None
            typ = "ZEITPUNKT"
        else:
            dto = self._dt_string(date_to)
            typ = "ZEITSPANNE"

        data = {
            "endAt": dto,
            "name": name,
            "startAt": self._dt_string(date_from),
            "typ": typ,
            "zaehlpunkt": zaehlpunkt,
        }

        return self._call_api_wn("user/ereignis", data=data, method="POST")

    def delete_ereignis(self, ereignis_id):
        """Deletes ereignis."""
        return self._call_api_wn("user/ereignis/{}".format(ereignis_id), method="DELETE", return_response=True)
