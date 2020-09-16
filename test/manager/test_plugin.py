import os
import uuid
import unittest
from cloudone.core.unittest.runner import RichTestRunner

from cloudone.core import config
from cloudone.core import pygrpc
from cloudone.core import utils
from cloudone.core.error import *

from cloudone.core.transaction import Transaction

from cloudone.identity.manager.auth_manager import AuthManager

def random_string():
    return uuid.uuid4().hex

class TestPlugin(unittest.TestCase):
    config = config.load_config('./config.yml')

    @classmethod
    def setUpClass(cls):
        super(TestPlugin, cls).setUpClass()
        # Do your initialize

    @classmethod
    def tearDownClass(cls):
        super(TestPlugin, cls).tearDownClass()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_verify(self):
        """ Test Verify
        """
        options = {
        }
        auth_mgr = AuthManager(Transaction())
        result = auth_mgr.verify(options)
        print(result)
        self.assertEqual(result, 'ACTIVE')

    @unittest.skip('Real access_token')
    def test_login(self):
        """ Test Login user
        """
        options = {
            'domain': 'mz.co.kr'
        }
        credentials = {}
        user_credentials = {
            'access_token': 'AAAA'
        }
        auth_mgr = AuthManager(Transaction())
        result = auth_mgr.login(options, credentials, user_credentials)
        print(result)
        self.assertEqual(result['user_id'], 'choonhoson@mz.co.kr')
        self.assertEqual(result['state'], 'ENABLED')


    def test_find(self):
        """ Test Find user
        """
        options = {
            'domain': 'gmail.com'
        }
        credentials = {}
        user_id = 'my.name'
        auth_mgr = AuthManager(Transaction())
        result = auth_mgr.find(options, credentials, user_id)
        print(result)
        self.assertEqual(result['user_id'], 'my.name@gmail.com')
        self.assertEqual(result['state'], 'UNIDENTIFIED')

if __name__ == "__main__":
    unittest.main(testRunner=RichTestRunner)

