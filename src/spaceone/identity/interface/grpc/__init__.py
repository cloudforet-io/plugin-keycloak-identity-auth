from spaceone.core.pygrpc.server import GRPCServer
from .external_auth import ExternalAuth

_all_ = ["app"]

app = GRPCServer()
app.add_service(ExternalAuth)
