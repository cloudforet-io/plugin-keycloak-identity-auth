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

__all__ = ["UserInfo", "PluginInfo"]

import functools
from spaceone.api.identity.plugin import external_auth_pb2
from spaceone.core.pygrpc.message_type import *


def UserInfo(user_dict):
    return external_auth_pb2.UserInfo(**user_dict)


def PluginInfo(result):
    result["metadata"] = change_struct_type(result["metadata"])
    return external_auth_pb2.PluginInfo(**result)
