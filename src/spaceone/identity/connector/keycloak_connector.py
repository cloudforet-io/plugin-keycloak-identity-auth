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
from urllib.parse import urlparse

from spaceone.core.error import *
from spaceone.identity.error import *
from spaceone.core.connector import BaseConnector

_LOGGER = logging.getLogger(__name__)

# Number of Maximum find user result
MAX_FIND = 25


def _parse_realm(issuer):
    """
    issuer: https://sso.stargate.spaceone.dev/auth/realms/SpaceOne
    """
    items = issuer.split('/')
    realm = items[-1]
    return realm


def _parse_user_find_url(issuer):
    """
    issuer: https://sso.stargate.spaceone.dev/auth/realms/SpaceOne
    """
    temp = issuer.split('/')
    realm = temp[-1]

    items = urlparse(issuer)
    url = f'{items.scheme}://{items.netloc}/auth/admin/realms/{realm}/users'
    return url


class KeycloakConnector(BaseConnector):
    def __init__(self, transaction, config):
        super().__init__(transaction, config)
        self.authorization_endpoint = None
        self.token_endpoint = None
        self.userinfo_endpoint = None
        self.user_find_url = None

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

    def login(self, options, secret_data, schema, user_credentials):
        """
        options
        credentials:
          - access_token
        """
        self.get_endpoint(options)
        # Authorization Grant
        access_token = user_credentials.get('access_token', '')
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {}'.format(access_token)
        }
        # Check token info
        r = requests.get(self.userinfo_endpoint, headers=headers)
        if r.status_code != 200:
            _LOGGER.debug("KeycloakConnector return code:%s" % r.status_code)
            _LOGGER.debug("KeycloakConnector return code:%s" % r.json())
            raise ERROR_NOT_FOUND(key='userinfo', value=headers)
        # status_code == 200
        r2 = r.json()
        _LOGGER.debug(f'response: {r2}')
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
        result = {}
        if 'sub' in r2:
            if 'email' in r2:
                 result['email'] = r2['email']
            else:
                result['email'] = 'UPDATE@EMAIL'

            if 'preferred_username' in r2:
                try:
                    user_info = self.find_by_id(options, r2['sub'], access_token)
                    result['user_id'] = r2['preferred_username']
                except Exception as e:
                    _LOGGER.debug(f'[login] user search error: {e}')
                    result['user_id'] = r2['preferred_username']
            else:
                # where is username
                _LOGGER.error(f'no preferred_username: {r2}')
                raise ERROR_KEYCLOAK_CONFIGURATION(field='preferred_username')

            if 'name' in r2:
                result['name'] = r2['name']
            else:
                result['name'] = 'UPDATE NAME'

            result['state'] = 'ENABLED'
            return result
        raise ERROR_NOT_FOUND(key='user', value='<from access_token>')

    def find_by_id(self, options, keycloak_id, access_token):
        try:
            self.get_endpoint(options)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer {}'.format(access_token)
            }

            req_user_find_url = f'{self.user_find_url}/{keycloak_id}'
            _LOGGER.debug(f'[find_by_id] {req_user_find_url}')
            resp = requests.get(req_user_find_url, headers=headers)
            print("====")
            print(resp)
            print(resp.status_code)
            print(resp.json())
            print("====")
            if resp.status_code == 200:
                json_result = resp.json()
                return self._parse_user_infos(json_result)
            else:
                return None
        except Exception as e:
            _LOGGER.debug(f'[find_by_id] {e}')
            return None

    def find(self, options, secret_data, schema, user_id, keyword):
        # UserInfo
        if secret_data == {}:
            # not support find
            return self._unidentified_user(user_id, keyword)

        try:
            self.get_endpoint(options)
            access_token = self._get_token_from_credentials(secret_data, schema)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer {}'.format(access_token)
            }

            req_user_find_url = f'{self.user_find_url}?'
            if user_id:
                req_user_find_url = f'{req_user_find_url}username={user_id}&'
            elif keyword:
                req_user_find_url = f'{req_user_find_url}search={keyword}&'
            req_user_find_url = f'{req_user_find_url}max={MAX_FIND}&'

            _LOGGER.debug(f'[find] {req_user_find_url}')
            resp = requests.get(req_user_find_url, headers=headers)
            if resp.status_code == 200:
                json_result = resp.json()
                if user_id:
                    # Exact match
                    return self._parse_user_infos(json_result, user_id)
                return self._parse_user_infos(json_result)
            else:
                raise ERROR_NOT_FOUND(key='find', value=req_user_find_url)
        except Exception as e:
            _LOGGER.debug(f'[find] {e}')
            raise ERROR_INVALID_FIND_REQUEST()

    def get_endpoint(self, options):
        """ Find endpoints
        authorization_endpoint
        token_endpoint
        userinfo_endpoint
        """
        result = {}
        try:
            self.authorization_endpoint = options['metadata']['authorization_endpoint']
            self.token_endpoint = options['metadata']['token_endpoint']
            self.userinfo_endpoint = options['metadata']['userinfo_endpoint']
            self.user_find_url = options['metadata']['user_find_url']

        except Exception as e:
            if 'openid-configuration' in options:
                config_url = options['openid-configuration']
                result = self._parse_configuration(config_url)
            else:
                raise ERROR_INVALID_PLUGIN_OPTIONS(options=options)
            self.authorization_endpoint = result['authorization_endpoint']
            self.token_endpoint = result['token_endpoint']
            self.userinfo_endpoint = result['userinfo_endpoint']
            self.user_find_url = result['user_find_url']

        return result

    def _parse_configuration(self, config_url):
        """ discover endpoints
        """
        result = {}
        try:
            r = requests.get(config_url)
            if r.status_code == 200:
                json_result = r.json()
                #_LOGGER.debug(f'[_parse_configuration] {json_result}')
                keys = ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'issuer',
                        'end_session_endpoint']
                for key in keys:
                    if key not in json_result:
                        raise ERROR_AUTHORIZATION_SERVER_RESPONSE(keys=key, response=json_result)
                    result[key] = json_result[key]
                # add realm
                result['realm'] = _parse_realm(json_result['issuer'])
                result['user_find_url'] = _parse_user_find_url(json_result['issuer'])
                _LOGGER.debug(f'[_parse_configuration] {result}')
                return result
            else:
                raise ERROR_AUTHORIZATION_SERVER(error_code=r.status_code)

        except Exception as e:
            raise ERROR_INVALID_PLUGIN_OPTIONS(options=config_url)

    def _get_token_from_credentials(self, credentials, schema):
        """ get access_token from keycloak
        """
        if schema == '' or schema == 'oauth2_client_credentials':
            if 'client_id' not in credentials:
                raise ERROR_INVALID_PLUGIN_OPTIONS(options='secret_data.client_id')
            if 'client_secret' not in credentials:
                raise ERROR_INVALID_PLUGIN_OPTIONS(options='secret_data.client_id')
            data = {
                'grant_type': 'client_credentials',
                'client_id': credentials['client_id'],
                'client_secret': credentials['client_secret']
            }
        else:
            raise ERROR_INVALID_PLUGIN_OPTIONS(options='secret_data')

        r = requests.post(self.token_endpoint, data=data, verify=False)
        if r.status_code == 200:
            json_result = r.json()
            return json_result['access_token']
        elif r.status_code == 401:
            raise ERROR_INVALID_CLIENT_CREDENTIALS_OF_FIND(message=r.status_code)

        _LOGGER.error(f'[_get_token_from_credentials] {r.status_code}')
        raise ERROR_AUTHORIZATION_SERVER(error_code=r.status_code)

    def _parse_user_infos(self, users, exact_match=None):
        """
        [{'id': 'ec504ef1-87b9-412f-85d6-e1a20b397798', 'createdTimestamp': 1589458754161, 'username': 'choonhoson@mz.co.kr', 'enabled': True, 'totp': False, 'emailVerified': False, 'firstName': 'Choonho', 'lastName': 'Son', 'email': 'choonhoson@mz.co.kr', 'disableableCredentialTypes': [], 'requiredActions': [], 'notBefore': 0, 'access': {'manageGroupMembership': False, 'view': True, 'mapRoles': False, 'impersonate': False, 'manage': False}}]
        """
        result = []
        for user in users:
            if 'enabled' in user:
                if user['enabled'] == False:
                    continue
            else:
                continue

            if exact_match:
                if exact_match != user['username']:
                    # This is partial match
                    continue

            user_info = {
                'user_id': user['username'],
                'state': 'ENABLED'
            }
            if 'email' in user:
                user_info.update({'email': user['email']})
            result.append(user_info)
        return result

    def _unidentified_user(self, user_id, keyword):
        result = []
        if user_id:
            user_info = {
                'user_id': user_id,
                'state': 'UNIDENTIFIED'
            }
            result.append(user_info)
        else:
            raise ERROR_NOT_SUPPORT_KEYWORD_SEARCH()
        return result
