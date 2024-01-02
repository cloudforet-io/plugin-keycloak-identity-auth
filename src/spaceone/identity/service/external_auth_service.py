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
from spaceone.identity.manager.external_auth_manager import ExternalAuthManager

_LOGGER = logging.getLogger(__name__)

_AVAILABLE_KEYCLOAK_FIELDS = ["username", "email", "firstName", "lastName", "name"]


@authentication_handler
class ExternalAuthService(BaseService):
    def __init__(self, metadata):
        super().__init__(metadata)
        self.external_auth_manager: ExternalAuthManager = self.locator.get_manager(
            "ExternalAuthManager"
        )

    @transaction
    @check_required(["options", "domain_id"])
    def init(self, params):
        """verify options
        Args:
            params
              - options

        Returns:
            - metadata
        Raises:
            ERROR_NOT_FOUND:
        """

        options = params["options"]
        self.external_auth_manager.init(options)

        endpoints = self.external_auth_manager.get_endpoint(options)

        if "field_mapper" in options:
            self._check_field_mapper(options["field_mapper"])

        metadata = {}
        metadata.update(endpoints)
        metadata.update({"protocol": "oidc", "identity_provider": "keycloak"})

        return {"metadata": metadata}

    @transaction
    @check_required(["options", "secret_data", "credentials"])
    def authorize(self, params):
        """verify options
        options = configuration
            (https://<domain>/auth/realms/<Realm>/.well-known/openid-configuration)
        Args:
            params
              - options
              - secret_data
              - schema_id
              - user_credentials

        Returns:

        Raises:
            ERROR_NOT_FOUND:
        """
        options = params["options"]
        secret_data = params["secret_data"]
        schema_id = params.get("schema_id", "")
        credentials = params["user_credentials"]
        return self.external_auth_manager.authorize(
            options, secret_data, schema_id, credentials
        )

    @staticmethod
    def _check_field_mapper(field_mapper):
        user_id_field = field_mapper.get("user_id")
        name_field = field_mapper.get("name")
        email_field = field_mapper.get("email")

        if user_id_field is None:
            raise ERROR_REQUIRED_PARAMETER(key="options.field_mapper.user_id")

        if user_id_field not in _AVAILABLE_KEYCLOAK_FIELDS:
            raise ERROR_INVALID_PARAMETER(
                key="options.field_mapper.user_id",
                reason=f"Choose one of the following: " f"{_AVAILABLE_KEYCLOAK_FIELDS}",
            )
        if user_id_field == "name":
            raise ERROR_INVALID_PARAMETER(
                key="options.field_mapper.user_id",
                reason="user_id field does not allow name.",
            )

        if name_field and name_field not in _AVAILABLE_KEYCLOAK_FIELDS:
            raise ERROR_INVALID_PARAMETER(
                key="options.field_mapper.name",
                reason=f"Choose one of the following: " f"{_AVAILABLE_KEYCLOAK_FIELDS}",
            )
        if email_field not in _AVAILABLE_KEYCLOAK_FIELDS:
            raise ERROR_INVALID_PARAMETER(
                key="options.field_mapper.email",
                reason=f"Choose one of the following: " f"{_AVAILABLE_KEYCLOAK_FIELDS}",
            )
