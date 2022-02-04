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

from spaceone.api.identity.plugin import auth_pb2, auth_pb2_grpc
from spaceone.core.pygrpc import BaseAPI
from spaceone.core.pygrpc.message_type import *


class Auth(BaseAPI, auth_pb2_grpc.AuthServicer):
    pb2 = auth_pb2
    pb2_grpc = auth_pb2_grpc

    def init(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service('AuthService', metadata) as auth_svc:
            data = auth_svc.init(params)
            return self.locator.get_info('PluginInfo', data)

    def verify(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service('AuthService', metadata) as auth_svc:
            auth_svc.verify(params)
            return self.locator.get_info('EmptyInfo')

    def find(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service('AuthService', metadata) as auth_svc:
            users, total_count = auth_svc.find(params)
            return self.locator.get_info('UsersInfo', users, total_count)

    def login(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service('AuthService', metadata) as auth_svc:
            data = auth_svc.login(params)
            return self.locator.get_info('UserInfo', data)
