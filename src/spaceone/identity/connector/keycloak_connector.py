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

import requests
import logging

from spaceone.core.error import *
from spaceone.core.connector import BaseConnector

from spaceone.identity.error import *

_LOGGER = logging.getLogger(__name__)

# Number of Maximum find user result
MAX_FIND = 25

DEFAULT_FIELD_MAPPER = {"user_id": "username", "name": "name", "email": "email"}

DEFAULT_KEYCLOAK_ADMIN_BASE_URL = "/auth/admin/realms/"

DEFAULT_CONFIGURATION_KEYS = [
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "issuer",
    "end_session_endpoint",
]


class KeycloakConnector(BaseConnector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authorization_endpoint = None
        self.token_endpoint = None
        self.userinfo_endpoint = None
        self.end_session_endpoint = None
        self.user_find_url = None
        self.issuer = None
        self.realm = None

    def init(self, options: dict) -> str:
        # This is connection check for Google Authorization Server
        # URL: https://www.googleapis.com/oauth2/v4/token
        # After connection without param.
        # It should return 404
        self.set_endpoint(options)
        verify = options.get("verify", True)

        response = requests.get(self.authorization_endpoint, verify=verify)
        if response.status_code == 400:
            return "ACTIVE"
        else:
            _LOGGER.debug(f"[verify] status code: {response.status_code}")
            raise ERROR_NOT_FOUND(
                key="authorization_endpoint", value=self.authorization_endpoint
            )

    def authorize(self, options, secret_data, schema_id, credentials):
        """
        options
        credentials:
          - access_token
        """

        field_mapper = options.get("field_mapper", DEFAULT_FIELD_MAPPER)
        user_id_field = self._convert_oidc_field(field_mapper["user_id"])
        name_field = self._convert_oidc_field(field_mapper.get("name"))
        email_field = self._convert_oidc_field(field_mapper.get("email"))

        self.set_endpoint(options)
        verify = options.get("verify", True)

        # Authorization Grant
        access_token = credentials.get("access_token", "")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        }
        # Check token info
        response = requests.get(self.userinfo_endpoint, headers=headers, verify=verify)
        if response.status_code != 200:
            _LOGGER.debug("KeycloakConnector return code:%s" % response.status_code)
            _LOGGER.debug("KeycloakConnector return code:%s" % response.json())
            raise ERROR_NOT_FOUND(key="userinfo", value=headers)

        # status_code == 200
        response_info = response.json()
        _LOGGER.debug(f"response: {response_info}")
        """
        response: {
        'sub': 'aca4e676-2b9b-4e30-84c2-e3cf0d524104',
        'email_verified': False,
        'name': 'Choonho test2 Son',
        'preferred_username': 'choonho.son',
        'given_name': 'Choonho test2',
        'family_name': 'Son',
        'email': 'choonho@example.com'}
        """

        if "sub" not in response_info:
            raise ERROR_NOT_FOUND(key="user", value="<from access_token>")

        result = {"state": "ENABLED"}

        if user_id_field in response_info:
            result["user_id"] = response_info[user_id_field]
        else:
            # where is username
            _LOGGER.error(f"no user_id field: {response_info}")
            raise ERROR_KEYCLOAK_CONFIGURATION(field=response_info[user_id_field])

        if name_field and name_field in response_info:
            result["name"] = response_info[name_field]

        if email_field and email_field in response_info:
            result["email"] = response_info[email_field]

        return result

    def set_endpoint(self, options: dict) -> None:
        """Find endpoints
        authorization_endpoint
        token_endpoint
        userinfo_endpoint
        """
        try:
            if metadata := options.get("metadata"):
                self.authorization_endpoint = metadata["authorization_endpoint"]
                self.token_endpoint = metadata["token_endpoint"]
                self.userinfo_endpoint = metadata["userinfo_endpoint"]
                self.user_find_url = metadata["user_find_url"]
            elif "openid-configuration" in options:
                config_url = options["openid-configuration"]
                verify = options.get("verify", True)

                # fix : To support keycloak API version v18++, KEYCLOAK_API_BASE_PATH need to set '/admin/realms/'
                admin_url_base_path = options.get(
                    "admin_url_base_path", DEFAULT_KEYCLOAK_ADMIN_BASE_URL
                )

                self.set_configuration_info(config_url, verify, admin_url_base_path)
            else:
                raise ERROR_INVALID_PLUGIN_OPTIONS(options=options)

        except Exception as e:
            _LOGGER.error(f"[get_endpoint] {e}")
            raise ERROR_INVALID_ARGUMENT(options=options)

    def set_configuration_info(
        self, config_url: str, verify: bool, admin_url_base_path: str
    ) -> None:
        """discover endpoints"""
        try:
            response = requests.get(config_url, verify=verify)
            if response.status_code == 200:
                response_info = response.json()

                for key in DEFAULT_CONFIGURATION_KEYS:
                    if key not in response_info:
                        raise ERROR_AUTHORIZATION_SERVER_RESPONSE(
                            keys=key, response=response_info
                        )
                    setattr(self, key, response_info[key])

                # add realm
                self.realm = self.get_realm_from_issuer(response_info["issuer"])
                self.user_find_url = self.get_user_find_url(
                    response_info["issuer"], admin_url_base_path
                )
                _LOGGER.debug(
                    f"[get_configuration_info] extract info list from response {DEFAULT_CONFIGURATION_KEYS}"
                )
            else:
                raise ERROR_AUTHORIZATION_SERVER(error_code=response.status_code)

        except Exception as e:
            _LOGGER.error(f"[get_configuration_info] {e}")
            raise ERROR_INVALID_PLUGIN_OPTIONS(options=config_url)

    @staticmethod
    def _convert_oidc_field(field):
        if field == "username":
            return "preferred_username"
        elif field == "firstName":
            return "given_name"
        elif field == "lastName":
            return "family_name"
        else:
            return field

    @staticmethod
    def get_realm_from_issuer(issuer: str) -> str:
        """
        issuer: https://sso.stargate.spaceone.dev/auth/realms/SpaceOne
        """
        items = issuer.split("/")[:-1]
        realm = items[-1]
        return realm

    @staticmethod
    def get_user_find_url(issuer: str, admin_url_base_path: str) -> str:
        """
        issuer: https://sso.stargate.spaceone.dev/auth/realms/SpaceOne
        """
        temp = issuer.split("/")
        realm = temp[-1]

        base_path = f"{admin_url_base_path}{realm}/users"

        return f"{issuer}{base_path}"
