import os
import uuid
import unittest
from spaceone.core.unittest.runner import RichTestRunner

from spaceone.tester.unittest import TestCase, to_json, print_json

def random_string():
    return uuid.uuid4().hex

TOKEN = "eyJhbGc....."
OPTIONS = {
    'openid-configuration': 'https://sso.example.com/auth/realms/test-domain/.well-known/openid-configuration',
    'domain': 'gmail.com',
    'client_id': 'my_client_id'
}

class TestOAuth(TestCase):

    #@unittest.skip('WRONG ACCESS_TOKEN')
    def test_login(self):
        credentials = {
        }
        user_credentials = {
            'access_token': TOKEN
        }
        user_info = self.identity.Auth.login({'options':OPTIONS, 'secret_data':credentials, 'user_credentials':user_credentials})
        user_info_json = to_json(user_info)
        print(user_info_json)
        self.assertEqual(user_info_json['state'], 'ENABLED')

    def test_init(self):
        credentials = {}

        auth_v_info = self.identity.Auth.init({'options':OPTIONS})
        j = to_json(auth_v_info)
        print(j)


    def test_verify(self):
        credentials = {}

        auth_v_info = self.identity.Auth.verify({'options':OPTIONS, 'secret_data': credentials})
        j = to_json(auth_v_info)
        print(j)

    def test_find(self):
        credentials = {
        }
        user_id = 'choonho.son@gmail.com'
        users_info = self.identity.Auth.find({'options':OPTIONS, 'secret_data':credentials, 'user_id':user_id})
        j = to_json(users_info)
        print(j)
        self.assertEqual(j['total_count'], 1)

    def test_find_failure(self):
        """ Wrong domain name
        """
        credentials = {
        }
        user_id = 'choonho.son@example.com'
        try:
            users_info = self.identity.Auth.find({'options':OPTIONS, 'secret_data':credentials, 'user_id':user_id})
        except Exception as e:
            print(e)
            self.assertTrue(True)

    def test_find_failure2(self):
        """ No domain name
        """
        credentials = {
        }
        user_id = 'choonho.son'
        try:
            users_info = self.identity.Auth.find({'options':OPTIONS, 'secret_data':credentials, 'user_id':user_id})
        except Exception as e:
            print(e)
            self.assertTrue(True)

    def test_find_failure3(self):
        """ Not support keyword search
        """
        credentials = {
        }
        user_id = 'choonho.son'
        try:
            users_info = self.identity.Auth.find({'options':OPTIONS, 'secret_data':credentials, 'keyword':user_id})
        except Exception as e:
            print(e)
            self.assertTrue(True)



if __name__ == "__main__":
    unittest.main(testRunner=RichTestRunner)

