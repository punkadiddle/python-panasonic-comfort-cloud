'''
Panasonic session, using Panasonic Comfort Cloud app api
'''

import hashlib
import json
import logging
import os

import requests
import urllib3

from . import constants, urls


class Error(Exception):
    ''' Panasonic session error '''


class RequestError(Error):
    ''' Wrapped requests.exceptions.RequestException '''


class LoginError(Error):
    ''' Login failed '''


class ResponseError(Error):
    ''' Unexcpected response '''
    def __init__(self, status_code, text):
        super(ResponseError, self).__init__(
            'Invalid response'
            ', status code: {0} - Data: {1}'.format(
                status_code,
                text))
        self.status_code = status_code
        try:
          self.text = json.loads(text)
        except:
          self.text = text

class Cache():
    ''' Cloud Configuration Cache '''
    _logger = logging.getLogger(__name__)

    def __init__(self, caching=constants.Cache.Token, vid=None, groups=None):
        self._dirty = False
        self._caching = caching
        self._groups = groups
        self._vid = vid

    def clear(self):
        self._dirty = False
        self._groups = None
        self._vid = None

    @property
    def groups(self):
        return self._groups

    @groups.setter
    def groups(self, value):
        self._groups = value
        self._dirty = True

    @property
    def vid(self):
        return self._vid

    @vid.setter
    def vid(self, value):
        if self._vid != value or value is None:
            self._logger.debug("new vid differs from cached value, resetting cache")
            self.clear()
            self._vid = value
            self._dirty = True

    @property
    def is_dirty(self):
        return self._dirty

    @property
    def is_valid(self):
        return self._vid is not None

    def to_file(self, fileName):
        """ Store cache values in given file """

        dct = {}
        if self._caching in [constants.Cache.Token, constants.Cache.All]:
            dct['vid'] = self._vid
        if self._caching in [constants.Cache.All]:
            dct['groups'] = self._groups

        if len(dct) > 0:
            with open(fileName, 'w') as f:
                json.dump(dct, f, indent=2, sort_keys=True)

            self._logger.info("%s written to cache '%s'", dct.keys(), fileName)

        self._dirty = False

    def from_dict(self, dct):
        self.clear()

        if self._caching in [constants.Cache.Token, constants.Cache.All]:
            self._vid = dct.get('vid', None)
        if self._caching in [constants.Cache.All]:
            self._groups = dct.get('groups', None)

    def from_file(self, fileName):
        """ Read cache values from given file a create a Cache object """

        self.clear()

        if os.path.exists(fileName):
            self._logger.debug("attempting to read cache from '%s'", fileName)
            try:
                with open(fileName, 'r') as cookieFile:
                    dct = json.load(cookieFile)
                    self._logger.info("%s read from cache '%s'", dct.keys(), fileName)
                    self.from_dict(dct)

            except json.decoder.JSONDecodeError as ex:
                self._logger.debug("invalid JSON in cache file: %s", ex.msg)


class Session(object):
    """ Verisure app session

    Args:
        username (str): Username used to login to verisure app
        password (str): Password used to login to verisure app

    """

    def __init__(self, username, password, tokenFileName='~/.panasonic-token.js', raw=False, verifySsl=True,
                 caching=constants.Cache.Token):
        self._username = username
        self._password = password
        self._tokenFileName = os.path.expanduser(tokenFileName)
        self._cache = Cache(caching)
        self._devices = None
        self._deviceIndexer = {}
        self._raw = raw

        if verifySsl is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self._verifySsl = verifySsl
        else:
            self._verifySsl = os.path.join(os.path.dirname(__file__),
                                           "certificatechain.pem")

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def login(self, useCache=True):
        """ Login to verisure app api """

        if useCache:
            self._read_token()
        else:
            self._cache.clear()

        if not self._cache.is_valid:
            self._create_token()

        if self._cache.groups is None:
            self._get_groups()

        if self._cache.is_dirty:
            self._cache.to_file(self._tokenFileName)

    def logout(self):
        """ Logout """

    def _headers(self):
        return {
            "X-APP-TYPE": "1",
            "X-APP-VERSION": "1.10.0",
            "X-User-Authorization": self._cache.vid,
            "User-Agent": "G-RAC",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def _request(self, url, method='get', payload=None, allowReauth=True, requestErrorClass=RequestError):
        """ Send any REST request to the cloud api and return it's response.

        Provide error handling and try to re-authenticate in case the X-Auth token expired.

        Args:
            url  (str): Id of the device
            method (str): name of the http method to use
            payload (str): payload, if any
            allowReauth (bool): if re-authentication should be attempted
            requestErrorClass (class): class to use for wrapping RequestExceptions

        Return: response
        """
        try:
            response = requests.request(method=method, url=url,
                                        json=payload, headers=self._headers(),
                                        verify=self._verifySsl)
            if response.status_code == requests.codes.unauthorized and allowReauth:
                # expired token response contains the following message: {'message': 'Token expires', 'code': 4100}
                self.login(useCache=False)
                response = requests.request(method=method, url=url,
                                            json=payload, headers=self._headers(),
                                            verify=self._verifySsl)

        except requests.exceptions.RequestException as ex:
            raise requestErrorClass(ex)

        if response.status_code != requests.codes.ok:
            raise ResponseError(response.status_code, response.text)

        return response

    def _create_token(self):
        """ Login and obtain X-Auth Token """

        payload = {
            "language": "0",
            "loginId": self._username,
            "password": self._password
        }

        if self._raw: print("--- creating token by authenticating")
        self._cache.clear()

        response = self._request(urls.login(), method='post', payload=payload, allowReauth=False,
                                 requestErrorClass=LoginError)

        if self._raw is True:
            print("--- raw beginning ---")
            print(response.text)
            print("--- raw ending    ---\n")

        self._cache.vid = json.loads(response.text)['uToken']

    def _read_token(self):
        self._cache.from_file(self._tokenFileName)

    def _get_groups(self):
        """ Get information about groups """

        response = self._request(urls.get_groups())

        if(self._raw is True):
            print("--- _get_groups()")
            print("--- raw beginning ---")
            print(response.text)
            print("--- raw ending    ---\n")

        self._cache.groups = json.loads(response.text)
        self._devices = None

    def get_devices(self, group=None):
        if not self._cache.is_valid:
            self.login()

        if self._devices is None:
            self._devices = []

            for group in self._cache.groups['groupList']:
                if 'deviceList' in group:
                    deviceList = group.get('deviceList', [])
                else:
                    deviceList = group.get('deviceIdList', [])

                for device in deviceList:
                    if device:
                        deviceId = None
                        if 'deviceHashGuid' in device:
                            deviceId = device['deviceHashGuid']
                        else:
                            deviceId = hashlib.md5(device['deviceGuid'].encode('utf-8')).hexdigest()

                        self._deviceIndexer[deviceId] = device['deviceGuid']
                        self._devices.append({
                            'id': deviceId,
                            'name': device['deviceName'],
                            'group': group['groupName'],
                            'model': device['deviceModuleNumber'] if 'deviceModuleNumber' in device else ''
                        })

        return self._devices

    def dump(self, deviceId):
        deviceGuid = self._deviceIndexer.get(deviceId)

        if(deviceGuid):
            response = self._request(urls.status(deviceGuid))
            return json.loads(response.text)

        return None

    def history(self, deviceId, mode, date, tz="+01:00"):
        deviceGuid = self._deviceIndexer.get(deviceId)

        if(deviceGuid):
            try:
                dataMode = constants.dataMode[mode].value
            except KeyError:
                raise Exception("Wrong mode parameter")

            payload = {
                "deviceGuid": deviceGuid,
                "dataMode": dataMode,
                "date": date,
                "osTimezone": tz
            }

            response = self._request(urls.history(), method='post', payload=payload)

            if(self._raw is True):
                print("--- history()")
                print("--- raw beginning ---")
                print(response.text)
                print("--- raw ending    ---")

            _json = json.loads(response.text)
            return {
                'id': id,
                'parameters': self._read_parameters(_json)
            }

        return None

    def get_device(self, id):
        deviceGuid = self._deviceIndexer.get(id)

        if(deviceGuid):
            response = self._request(urls.status(deviceGuid))

            if(self._raw is True):
                print("--- get_device()")
                print("--- raw beginning ---")
                print(response.text)
                print("--- raw ending    ---")

            _json = json.loads(response.text)
            return {
                'id': id,
                'parameters': self._read_parameters(_json['parameters'])
            }

        return None

    def set_device(self, id, **kwargs):
        """ Set parameters of device

        Args:
            id  (str): Id of the device
            kwargs   : {temperature=float}, {mode=OperationMode}, {fanSpeed=FanSpeed}, {power=Power}, {airSwingHorizontal=}, {airSwingVertical=}, {eco=EcoMode}
        """

        parameters = {}
        airX = None
        airY = None

        if kwargs is not None:
            for key, value in kwargs.items():
                if key == 'power' and isinstance(value, constants.Power):
                    parameters['operate'] = value.value

                if key == 'temperature':
                    parameters['temperatureSet'] = value

                if key == 'mode' and isinstance(value, constants.OperationMode):
                    parameters['operationMode'] = value.value

                if key == 'fanSpeed' and isinstance(value, constants.FanSpeed):
                    parameters['fanSpeed'] = value.value

                if key == 'airSwingHorizontal' and isinstance(value, constants.AirSwingLR):
                    airX = value

                if key == 'airSwingVertical' and isinstance(value, constants.AirSwingUD):
                    airY = value

                if key == 'eco' and isinstance(value, constants.EcoMode):
                    parameters['ecoMode'] = value.value

                if key == 'nanoe' and isinstance(value, constants.NanoeMode) and value != constants.NanoeMode.Unavailable:
                    parameters['nanoe'] = value.value

        # routine to set the auto mode of fan (either horizontal, vertical, both or disabled)
        if airX is not None or airY is not None:
            fanAuto = 0
            device = self.get_device(id)

            if device and device['parameters']['airSwingHorizontal'].value == -1:
                fanAuto = fanAuto | 1

            if device and device['parameters']['airSwingVertical'].value == -1:
                fanAuto = fanAuto | 2

            if airX is not None:
                if airX.value == -1:
                    fanAuto = fanAuto | 1
                else:
                    fanAuto = fanAuto & ~1
                    parameters['airSwingLR'] = airX.value

            if airY is not None:
                if airY.value == -1:
                    fanAuto = fanAuto | 2
                else:
                    fanAuto = fanAuto & ~2
                    print(airY.name)
                    parameters['airSwingUD'] = airY.value

            if fanAuto == 3:
                parameters['fanAutoMode'] = constants.AirSwingAutoMode.Both.value
            elif fanAuto == 1:
                parameters['fanAutoMode'] = constants.AirSwingAutoMode.AirSwingLR.value
            elif fanAuto == 2:
                parameters['fanAutoMode'] = constants.AirSwingAutoMode.AirSwingUD.value
            else:
                parameters['fanAutoMode'] = constants.AirSwingAutoMode.Disabled.value

        deviceGuid = self._deviceIndexer.get(id)
        if(deviceGuid):
            payload = {
                "deviceGuid": deviceGuid,
                "parameters": parameters
            }

            if(self._raw is True):
                print("--- set_device()")
                print("--- raw out beginning ---")
                print(payload)
                print("--- raw out ending    ---")

            response = self._request(urls.control(), method='post', payload=payload)

            if(self._raw is True):
                print("--- raw in beginning ---")
                print(response.text)
                print("--- raw in ending    ---\n")

            json.loads(response.text)

            return True

        return False

    def _read_parameters(self, parameters):
        value = {}

        _convert = {
            'insideTemperature': 'temperatureInside',
            'outTemperature': 'temperatureOutside',
            'temperatureSet': 'temperature',
            'currencyUnit': 'currencyUnit',
            'energyConsumption': 'energyConsumption',
            'estimatedCost': 'estimatedCost',
            'historyDataList': 'historyDataList',
        }
        for key in _convert:
            if key in parameters:
                value[_convert[key]] = parameters[key]

        if 'operate' in parameters:
            value['power'] = constants.Power(parameters['operate'])

        if 'operationMode' in parameters:
            value['mode'] = constants.OperationMode(parameters['operationMode'])

        if 'fanSpeed' in parameters:
            value['fanSpeed'] = constants.FanSpeed(parameters['fanSpeed'])

        if 'airSwingLR' in parameters:
            value['airSwingHorizontal'] = constants.AirSwingLR(parameters['airSwingLR'])

        if 'airSwingUD' in parameters:
            value['airSwingVertical'] = constants.AirSwingUD(parameters['airSwingUD'])

        if 'ecoMode' in parameters:
            value['eco'] = constants.EcoMode(parameters['ecoMode'])

        if 'nanoe' in parameters:
            value['nanoe'] = constants.NanoeMode(parameters['nanoe'])

        if 'fanAutoMode' in parameters:
            if parameters['fanAutoMode'] == constants.AirSwingAutoMode.Both.value:
                value['airSwingHorizontal'] = constants.AirSwingLR.Auto
                value['airSwingVertical'] = constants.AirSwingUD.Auto
            elif parameters['fanAutoMode'] == constants.AirSwingAutoMode.AirSwingLR.value:
                value['airSwingHorizontal'] = constants.AirSwingLR.Auto
            elif parameters['fanAutoMode'] == constants.AirSwingAutoMode.AirSwingUD.value:
                value['airSwingVertical'] = constants.AirSwingUD.Auto

        return value
