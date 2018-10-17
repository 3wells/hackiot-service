import unittest
import mock
import string
import random
import time
from push import *


class PushTest(unittest.TestCase):

    @mock.patch("boto3.client")
    def testPush(self, boto3_client):

        secret_key = self.random_string(10)
        os.environ['secret_key'] = secret_key
        response = lambda_handler(self.get_test_payload(secret_key), None)

        assert(response["statusCode"] == 200)
        assert(boto3_client.call_count == 1)

    @mock.patch("boto3.client")
    def testBadKey(self, boto3_client):

        secret_key = self.random_string(10)
        os.environ['secret_key'] = "not_my_secret_key"
        response = lambda_handler(self.get_test_payload(secret_key), None)

        assert(response["statusCode"] == 401)

    @staticmethod
    def get_test_payload(secret_key):

        with open('test_payload', 'r') as testfile:
            body = testfile.read()
        body = body.replace(' ', '').replace('\n', '')
        timestamp = int(time.time())

        signature = calc_hash(secret_key, timestamp, body)
        return {
            "headers": {
                "X-UA-SIGNATURE": signature,
                "X-UA-TIMESTAMP": timestamp
            },
            "body": body
        }

    @staticmethod
    def random_string(length):
        return ''.join(random.choice(string.ascii_letters) for m in xrange(length))

    @staticmethod
    def calc_hash(secret_key, timestamp, body):
        message = bytes("{}:{}".format(timestamp, body)).encode('utf-8')
        return hmac.new(secret_key, message, digestmod=hashlib.sha256).hexdigest()
