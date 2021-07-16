import os
import uuid
import unittest
from spaceone.core.unittest.runner import RichTestRunner

from spaceone.tester.unittest import TestCase, to_json, print_json

def random_string():
    return uuid.uuid4().hex

TOKEN = os.environ.get('KEYCLOAK_TOKEN', 'export KEYCLOAK_TOKEN=xxxxxxxx')
OPENID_CONFIGURATION = os.environ.get('OPENID_CONFIGURATION', 'export OPENID_CONFIGURATION=https://yyyyy')
CLIENT_ID = os.environ.get('CLIENT_ID','export CLIENT_ID=zzzzzzz')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET', 'export CLIENT_SECRET=aaaaaaaaa')

OPTIONS = {
    'openid-configuration': OPENID_CONFIGURATION,
    'auth_type': 'keycloak_oidc',
    'client_id': CLIENT_ID
}

SECRET_DATA = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET
}

SCHEMA = 'oauth2_client_credentials'

class TestOAuth(TestCase):

    #@unittest.skip('WRONG ACCESS_TOKEN')
    def test_login(self):
        credentials = SECRET_DATA
        user_credentials = {
            'access_token': TOKEN
        }
        user_info = self.identity.Auth.login({'options':OPTIONS, 'secret_data':credentials, 'schema': SCHEMA, 'user_credentials':user_credentials})
        user_info_json = to_json(user_info)
        print(user_info_json)
        self.assertEqual(user_info_json['state'], 'ENABLED')

    def test_init(self):
        credentials = {}

        auth_v_info = self.identity.Auth.init({'options':OPTIONS})
        j = to_json(auth_v_info)
        print(j)


    def test_verify(self):
        credentials = SECRET_DATA
        auth_v_info = self.identity.Auth.verify({'options':OPTIONS, 'secret_data': credentials, 'schema': SCHEMA})
        j = to_json(auth_v_info)
        print(j)

   def test_find_user_id(self):
       credentials = SECRET_DATA
       user_id = 'choonho.son@gmail.com'
       keyword = 'mz.co.kr'
       users_info = self.identity.Auth.find({'options':OPTIONS, 'secret_data':credentials, 'schema': SCHEMA, 'user_id':user_id})
       j = to_json(users_info)
       print(j)
       self.assertEqual(j['total_count'], 1)

    def test_find_keyword(self):
        credentials = SECRET_DATA
        keyword = 'mz.co.kr'
        users_info = self.identity.Auth.find({'options':OPTIONS, 'secret_data':credentials, 'schema': SCHEMA, 'keyword':keyword})
        j = to_json(users_info)
        print(j)
        self.assertGreaterEqual(j['total_count'], 1)


    def test_find_failure(self):
        """ not found users
        """
        credentials = SECRET_DATA
        user_id = 'not_found_user@example.com'
        try:
            users_info = self.identity.Auth.find({'options':OPTIONS, 'secret_data':credentials, 'schema': SCHEMA, 'user_id':user_id})
        except Exception as e:
            print(e)

if __name__ == "__main__":
    unittest.main(testRunner=RichTestRunner)

