from spaceone.api.identity.plugin import external_auth_pb2, external_auth_pb2_grpc
from spaceone.core.pygrpc import BaseAPI
from spaceone.core.pygrpc.message_type import *


class ExternalAuth(BaseAPI, external_auth_pb2_grpc.ExternalAuthServicer):
    pb2 = external_auth_pb2
    pb2_grpc = external_auth_pb2_grpc

    def init(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service(
            "ExternalAuthService", metadata
        ) as external_auth_svc:
            data = external_auth_svc.init(params)
            return self.locator.get_info("PluginInfo", data)

    def authorize(self, request, context):
        params, metadata = self.parse_request(request, context)

        with self.locator.get_service(
            "ExternalAuthService", metadata
        ) as external_auth_svc:
            data = external_auth_svc.authorize(params)
            return self.locator.get_info("UserInfo", data)
