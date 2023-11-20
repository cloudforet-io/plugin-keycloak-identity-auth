from spaceone.core.pygrpc.server import GRPCServer
from .auth import Auth


_all_ = ['app']

app = GRPCServer()
app.add_service(Auth)
