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

__all__ = ['AuthManager']

import logging

from spaceone.core import config
from spaceone.core.error import *
from spaceone.core.manager import BaseManager

from spaceone.identity.error.custom import *

_LOGGER = logging.getLogger(__name__)

DEFAULT_DOMAIN='gmail.com'

class AuthManager(BaseManager):
    def __init__(self, transaction):
        super().__init__(transaction)

    ###################
    # Verify
    ###################
    def verify(self, options, secret_data=None, schema=None):
        """ Check Google OAuth connection

        Args:
            options:
              - client_id
            secret_data:
              - secret_data
              - schema
            schema: oauth2_client_credentials
        """
        connector = self.locator.get_connector('KeycloakConnector')
        r = connector.verify(options)
        # ACTIVE/UNKNOWN
        return r

    def login(self, options, secret_data, schema, user_credentials):
        """ Get access_token from credentials
        Args:
            options(dict):
              - domain: domain name of company (ex. gmail.com)
            user_credentials(dict)
              - access_token: google_oauth access_token for verifying
        """
        connector = self.locator.get_connector('KeycloakConnector')
        user_info = connector.login(options, secret_data, schema, user_credentials)
        return user_info

    def find(self, options, secret_data, schema, user_id=None, keyword=None):
        """ Find User information

        GoogleOauth cannot find keyword search,
        Please send user_id only.

        Args:
            options(dict):
              - domain: domain name of company
            user_id: user_id for exact matching (ex. example@gmail.com)
            keyword: any string for partial match
        Returns:
            users_info
        """
        connector = self.locator.get_connector('KeycloakConnector')
        user_infos = connector.find(options, secret_data, schema, user_id, keyword)
        _LOGGER.debug(f'[find] {user_infos}')
        return user_infos
        #user_info = {
        #    'user_id': my_user_id,
        #    'email': my_user_id,
        #    'state': 'ENABLED'
        #}

    def get_endpoint(self, options):
        """
        Discover endpoints
        """
        connector = self.locator.get_connector('KeycloakConnector')
        endpoints = connector.get_endpoint(options)
        return endpoints


