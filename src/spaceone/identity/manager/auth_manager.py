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
    def verify(self, options):
        """ Check Google OAuth connection

        Args:
            options:
              - client_id
        """
        connector = self.locator.get_connector('KeycloakConnector')
        r = connector.verify(options)
        # ACTIVE/UNKNOWN
        return r

    def login(self, options, credentials, user_credentials):
        """ Get access_token from credentials
        Args:
            options(dict):
              - domain: domain name of company (ex. gmail.com)
            user_credentials(dict)
              - access_token: google_oauth access_token for verifying
        """
        connector = self.locator.get_connector('KeycloakConnector')
        user_info = connector.login(options, credentials, user_credentials)
        # check user_info, if needed
        if 'domain' in options:
            domain = options['domain']
            user_id = user_info['user_id']
            self._verify_user_id(domain, user_id)
        return user_info

    def find(self, options, credentials, user_id, keyword=None):
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
        if user_id == None and keyword != None:
            raise ERROR_NOT_SUPPORT_KEYWORD_SEARCH()

        if 'domain' in options:
            domain = options['domain']
        else:
            domain = DEFAULT_DOMAIN
        my_user_id = self._verify_user_id(domain, user_id)
        user_info = {
            'user_id': my_user_id,
            'email': my_user_id,
            'state': 'UNIDENTIFIED'
        }
        return user_info

    def get_endpoint(self, options):
        """
        Discover endpoints
        """
        connector = self.locator.get_connector('KeycloakConnector')
        endpoints = connector.get_endpoint(options)
        return endpoints

    def _verify_user_id(self, domain, user_id):
        """
        Args:
            domain: domain name (ex. gmail.com or mz.co.kr)
            user_id: user_id (ex. choonho.son or choonho.son@gmail.com)

        Returns:
            user_id: full user_id (ex. choonho.son@gmail.com)
        Errors:
            ERROR_NOT_FOUND_USER_ID: if there is no matching
        """
        if user_id.endswith(f'@{domain}'):
            return user_id
        raise ERROR_NOT_FOUND_USER_ID(user_id=user_id)

