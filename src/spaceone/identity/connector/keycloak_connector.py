# -*- coding: utf-8 -*-
#
#   Copyright 2020 The SpaceONE Authors.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

__all__ = ["KeycloakConnector"]

import json
import requests
import logging

from spaceone.core.error import *
from spaceone.identity.error import *
from spaceone.core.connector import BaseConnector

_LOGGER = logging.getLogger(__name__)

class KeycloakConnector(BaseConnector):
    def __init__(self, transaction, config):
        super().__init__(transaction, config)
        self.authorization_endpoint = None
        self.token_endpoint = None
        self.userinfo_endpoint = None

    def verify(self, options):
        # This is connection check for Google Authorization Server
        # URL: https://www.googleapis.com/oauth2/v4/token
        # After connection without param.
        # It should return 404
        self.get_endpoint(options)

        r = requests.get(self.authorization_endpoint)
        if r.status_code == 400:
            return "ACTIVE"
        else:
            _LOGGER.debug(f'[verify] status code: {r.status_code}')
            raise ERROR_NOT_FOUND(key='authorization_endpoint', value=self.authorization_endpoint)

    def login(self, options, credentials, user_credentials):
        """
        options
        credentials:
          - access_token
        """
        self.get_endpoint(options)
        # Authorization Grant
        access_token = user_credentials.get('access_token', '')
        headers={'Content-Type':'application/json',
                 'Authorization': 'Bearer {}'.format(access_token)}
        # Check tokeninfo
        r = requests.get(self.userinfo_endpoint, headers=headers)
        if r.status_code != 200:
            _LOGGER.debug("KeycloakConnector return code:%s" % r.status_code)
            _LOGGER.debug("KeycloakConnector return code:%s" % r.json())
            raise ERROR_NOT_FOUND(key='userinfo', value=headers)
        # status_code == 200
        r2 = r.json()
        _LOGGER.debug(f'response: {r2}')
        result = {}
        if 'email' in r2:
            result['email'] = r2['email']
            result['user_id'] = r2['email']
            if 'preferred_username' in r2:
                result['name'] = r2['preferred_username']
            result['state'] = 'ENABLED'
            return result
        raise ERROR_NOT_FOUND(key='user', value='<from access_token>')


    def find(self, options, params):
        # TODO: NOT SUPPORT
        raise ERROR_NOT_FOUND(key='find', value='does not support')

    def get_endpoint(self, options):
        """ Find endpoints
        authorization_endpoint
        token_endpoint
        userinfo_endpoint
        """
        result = {}
        if 'openid-configuration' in options:
            config_url = options['openid-configuration']
            result = self._parse_configuration(config_url)
        else:
            endpoints_keys = ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint']
            for key in endpoints_keys:
                value = options[key]
                result[key] = value
        self.authorization_endpoint = result['authorization_endpoint']
        self.token_endpoint = result['token_endpoint']
        self.userinfo_endpoint = result['userinfo_endpoint']

        return result


    def _parse_configuration(self, config_url):
        """ discover endpoints
        """
        result = {}
        try:
            r = requests.get(config_url)
            if r.status_code == 200:
                json_result = r.json()
                _LOGGER.debug(f'[_parse_configuration] {json_result}')
                endpoints_keys = ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint']
                for key in endpoints_keys:
                    value = json_result[key]
                    result[key] = value
                return result
            else:
                raise AUTHORIZATION_SERVER_ERROR(error_code=r.status_code)

        except Exception as e:
            raise INVALID_PLUGIN_OPTIONS(options=config_url)


