import logging
import asyncio
import collections
import time

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.discovery import async_load_platform
import homeassistant.helpers.config_validation as cv
import voluptuous as vol

from .refresh_token import get_refresh_token

_LOGGER = logging.getLogger(__name__)

DOMAIN = 'grohe_sense'
CONF_USERNAME = 'username'
CONF_PASSWORD = 'password'

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema({
            vol.Required(CONF_USERNAME): cv.string,
            vol.Required(CONF_PASSWORD): cv.string
        }),
    },
    extra=vol.ALLOW_EXTRA,
)

BASE_URL = 'https://idp2-apigw.cloud.grohe.com/'
LOGIN = BASE_URL + 'v3/iot/oidc/login'
LOCATIONS = BASE_URL + 'v3/iot/locations'
REFRESH = BASE_URL + 'v3/iot/oidc/refresh'

GROHE_SENSE_TYPE = 101 # Type identifier for the battery powered water detector
GROHE_SENSE_GUARD_TYPE = 103 # Type identifier for sense guard, the water guard installed on your water pipe

GroheDevice = collections.namedtuple('GroheDevice', ['locationId', 'roomId', 'applianceId', 'type', 'name'])

async def async_setup(hass: HomeAssistant, config):
    _LOGGER.debug("Loading Grohe Sense")

    await initialize_shared_objects(hass, config.get(DOMAIN).get(CONF_USERNAME), config.get(DOMAIN).get(CONF_PASSWORD))

    await async_load_platform(hass, 'sensor', DOMAIN, {}, config)
    await async_load_platform(hass, 'switch', DOMAIN, {}, config)
    return True

async def initialize_shared_objects(hass, username, password):
    session = async_get_clientsession(hass)
    auth_session = OauthSession(hass, session, username, password)
    devices = []

    hass.data[DOMAIN] = { 'session': auth_session, 'devices': devices }

    locations = await auth_session.get(LOCATIONS)
    for location in locations:
        _LOGGER.debug('Found location %s', location)
        locationId = location['id']
        rooms = await auth_session.get(f'{LOCATIONS}/{locationId}/rooms')
        for room in rooms:
            _LOGGER.debug('Found room %s', room)
            roomId = room['id']
            appliances = await auth_session.get(f'{LOCATIONS}/{locationId}/rooms/{roomId}/appliances')
            for appliance in appliances:
                _LOGGER.debug('Found appliance %s', appliance)
                applianceId = appliance['appliance_id']
                devices.append(GroheDevice(locationId, roomId, applianceId, appliance['type'], appliance['name']))

class OauthException(Exception):
    def __init__(self, error_code, reason):
        self.error_code = error_code
        self.reason = reason

class OauthSession:
    def __init__(self, hass, session, username, password):
        self._hass = hass
        self._session = session
        self._username = username
        self._password = password
        self._refresh_token = None
        self._access_token = None
        self._fetching_new_token = None

    def get_refresh_token(self):
        return get_refresh_token(self._username, self._password, BASE_URL, LOGIN)

    @property
    def session(self):
        return self._session

    async def token(self, old_token=None, forceRefesh=False):
        """ Returns an authorization header. If one is supplied as old_token, invalidate that one """
        if self._access_token not in (None, old_token):
            return self._access_token

        if forceRefesh is True:
            self._refresh_token = None
        elif self._fetching_new_token is not None:
            await self._fetching_new_token.wait()
            return self._access_token
        else:
            self._access_token = None
            self._fetching_new_token = asyncio.Event()

        if self._refresh_token is not None:
            data = { 'refresh_token': self._refresh_token }
            headers = { 'Content-Type': 'application/json' }
        
            refresh_response = await self._http_request(REFRESH, 'post', headers=headers, json=data)
            if not 'access_token' in refresh_response:
                _LOGGER.error('OAuth token refresh did not yield access token! Got back %s', refresh_response)
            else:
                self._access_token = 'Bearer ' + refresh_response['access_token'] 
        else:
            _LOGGER.debug('Trying to get refresh token using username %s and password %s', self._username, self._password)
            _token = await self._hass.async_add_executor_job(self.get_refresh_token)
            if _token is not None:
                self._refresh_token = _token['refresh_token']
                _LOGGER.debug('Refresh token received: %s', self._refresh_token)
                self._access_token = 'Bearer ' + _token['access_token']
                _LOGGER.debug('Access token received: %s', self._access_token)
            else:
                _LOGGER.debug('Unable to get refresh_token')
                raise OauthException("401", "Unable to get refresh_token")
        
        if self._fetching_new_token is not None:
            self._fetching_new_token.set()
        
        self._fetching_new_token = None
        return self._access_token

    async def get(self, url, **kwargs):
        return await self._http_request(url, auth_token=self, **kwargs)

    async def post(self, url, json, **kwargs):
        return await self._http_request(url, method='post', auth_token=self, json=json, **kwargs)

    async def _http_request(self, url, method='get', auth_token=None, headers={}, **kwargs):
        _LOGGER.debug('Making http %s request to %s, headers %s', method, url, headers)
        headers = headers.copy()
        tries = 0
        token = None
        while True:
            if auth_token != None:
                # Cache token so we know which token was used for this request,
                # so we know if we need to invalidate.
                token = await auth_token.token()
                headers['Authorization'] = token
            try:
                async with self._session.request(method, url, headers=headers, **kwargs) as response:
                    _LOGGER.debug('Http %s request to %s got response %d', method, url, response.status)
                    if response.status in (200, 201):
                        return await response.json()
                    elif response.status == 401:
                        if auth_token != None:
                            _LOGGER.debug('Request to %s returned status %d, refreshing auth token', url, response.status)
                            token = await auth_token.token(token)
                        else:
                            token = await self.token(token, True)
                    else:
                        _LOGGER.debug('Request to %s returned status %d, %s', url, response.status, await response.text())
            except OauthException as oe:
                raise
            except Exception as e:
                _LOGGER.debug('Exception for http %s request to %s: %s', method, url, e)

            tries += 1
            await asyncio.sleep(min(600, 2**tries))