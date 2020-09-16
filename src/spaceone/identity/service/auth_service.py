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

import logging

from spaceone.core.error import *
from spaceone.core.service import *

from spaceone.identity.error import *
from spaceone.identity.manager.auth_manager import AuthManager

_LOGGER = logging.getLogger(__name__)

@authentication_handler
class AuthService(BaseService):
    def __init__(self, metadata):
        super().__init__(metadata)

    @transaction
    @check_required(['options'])
    def init(self, params):
        """ verify options
        Args:
            params
              - options

        Returns:
            - metadata
        Raises:
            ERROR_NOT_FOUND:
        """
        manager = self.locator.get_manager('AuthManager')
        options = params['options']
        active = manager.verify(options)
        options['auth_type'] = 'keycloak'
        endpoints = manager.get_endpoint(options)
        capability= endpoints
        return {'metadata': capability}

    @transaction
    @check_required(['options','secret_data'])
    def verify(self, params):
        """ verify options
        Args:
            params
              - options
              - secret_data: may be empty dictionary

        Returns:

        Raises:
            ERROR_NOT_FOUND:
        """
        manager = self.locator.get_manager('AuthManager')
        options = params['options']
        manager.verify(options)
        return {}

    @transaction
    @check_required(['options','secret_data'])
    def find(self, params):
        """ verify options
        Args:
            params
              - options
              - secret_data: may be empty dictionary
              - user_id
              - keyword
        Returns:

        Raises:
            ERROR_NOT_FOUND:
        """
        _LOGGER.debug(f'[find] params: {params}')
        manager = self.locator.get_manager('AuthManager')
        options = params['options']
        credentials = params['secret_data']
        # collect plugins_info
        user_id = params.get('user_id', None)
        keyword = params.get('keyword', None)

        user_info = manager.find(options, credentials, user_id, keyword)
        _LOGGER.debug(f'[find] user_info: {user_info}')
        return [user_info], 1

    @transaction
    @check_required(['options','secret_data', 'user_credentials'])
    def login(self, params):
        """ verify options
        options = configuration (https://<domain>/auth/realms/<Realm>/.well-known/openid-configuration)
        Args:
            params
              - options
              - secret_data
              - user_credentials

        Returns:

        Raises:
            ERROR_NOT_FOUND:
        """
        manager = self.locator.get_manager('AuthManager')
        options = params['options']
        credentials = params['secret_data']
        user_credentials = params['user_credentials']
        return manager.login(options, credentials, user_credentials)
