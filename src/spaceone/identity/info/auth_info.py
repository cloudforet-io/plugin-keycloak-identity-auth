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

__all__ = ['UserInfo', 'UsersInfo', 'AuthVerifyInfo', 'PluginInfo']

import functools
from spaceone.api.identity.plugin import auth_pb2
from spaceone.core.pygrpc.message_type import *

def UserInfo(user_dict):
    return auth_pb2.UserInfo(**user_dict)

def UsersInfo(users_list, total_count):
    users = list(map(functools.partial(UserInfo), users_list))
    return auth_pb2.UsersInfo(results=users, total_count=total_count)

def PluginInfo(result):
    result['metadata'] = change_struct_type(result['metadata'])
    return auth_pb2.PluginInfo(**result)

def AuthVerifyInfo(result):
    """ result
    {
     'options': {
        'a': 'b',
        ...
        'auth_type': 'google_oauth2'
    }
    """
    result['options'] = change_struct_type(result['options'])
    return auth_pb2.AuthVerifyInfo(**result)
