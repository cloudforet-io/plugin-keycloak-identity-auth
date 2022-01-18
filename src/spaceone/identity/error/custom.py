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

from spaceone.core.error import *


class ERROR_NOT_SUPPORT_KEYWORD_SEARCH(ERROR_BASE):
    _message = 'Keyword search is not supported, use user_id(email)'


class ERROR_NOT_FOUND_USER_ID(ERROR_BASE):
    _message = 'user_id: {user_id} does not exist.'


class ERROR_NOT_FOUND_USERS(ERROR_BASE):
    _message = 'not found users.'


class ERROR_INVALID_FIND_REQUEST(ERROR_BASE):
    _message = 'user_id or keyword is required'


class ERROR_INVALID_PLUGIN_OPTIONS(ERROR_BASE):
    _message = 'Invalid options={options}'


class ERROR_AUTHORIZATION_SERVER(ERROR_BASE):
    _message = 'Authorization Server response code: {error_code}'


class ERROR_AUTHORIZATION_SERVER_RESPONSE(ERROR_BASE):
    _message = 'Authorization Server response {keys} not in {response}'


class ERROR_INVALID_CLIENT_CREDENTIALS_OF_FIND(ERROR_BASE):
    _message = '{response} Invalid Client Credentials for find request, check permission'


class ERROR_KEYCLOAK_CONFIGURATION(ERROR_BASE):
    _message = 'Contact keycloak administrator, field={field}'

