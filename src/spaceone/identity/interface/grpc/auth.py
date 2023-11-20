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
