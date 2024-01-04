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

__all__ = ["ExternalAuthManager"]

import logging

from spaceone.core.error import *
from spaceone.core.manager import BaseManager

from spaceone.identity.connector.keycloak_connector import KeycloakConnector
from spaceone.identity.error.custom import *

_LOGGER = logging.getLogger(__name__)

DEFAULT_DOMAIN = "gmail.com"


class ExternalAuthManager(BaseManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.keycloak_connector: KeycloakConnector = self.locator.get_connector(
            "KeycloakConnector"
        )

    def init(self, options: dict, secret_data: dict = None, schema: dict = None):
        """Check Google OAuth connection

        Args:
            options:
              - client_id
        """

        response = self.keycloak_connector.init(options)
        # ACTIVE/UNKNOWN
        return response

    def authorize(
        self, options: dict, secret_data: dict, schema_id: str, credentials: dict
    ):
        """Get access_token from credentials
        Args:
            options(dict):
              - domain: domain name of company (ex. gmail.com)
            user_credentials(dict)
              - access_token: google_oauth access_token for verifying
        Return:
            user_info(dict)
        """

        user_info = self.keycloak_connector.authorize(
            options, secret_data, schema_id, credentials
        )
        return user_info

    def get_endpoint(self, options) -> dict:
        """
        Discover endpoints
        """

        endpoints = {
            "authorization_endpoint": self.keycloak_connector.authorization_endpoint,
            "token_endpoint": self.keycloak_connector.token_endpoint,
            "userinfo_endpoint": self.keycloak_connector.userinfo_endpoint,
            "end_session_endpoint": self.keycloak_connector.end_session_endpoint,
        }
        return endpoints

    def get_metadata(self) -> dict:
        metadata = {}
        if client_id := self.keycloak_connector.client_id:
            metadata.update({"client_id": client_id})
        if realm := self.keycloak_connector.realm:
            metadata.update({"realm": realm})
        return metadata
