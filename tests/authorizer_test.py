import unittest
import string
import random
from authorizer import *


class AuthorizerTest(unittest.TestCase):

    def testAuthHandlerWithGoodToken(self):

        authorization_token = self.random_string(20)
        os.environ['authorizationToken'] = authorization_token
        resource = self.random_string(20)

        event = dict([
            ("authorizationToken", authorization_token),
            ("methodArn", resource)
        ])

        response = lambda_handler(event, None)

        statement = response['policyDocument']['Statement'][0]

        assert(statement['Resource'] == resource)
        assert(statement['Action'] == 'execute-api:Invoke')
        assert(statement['Effect'] == 'Allow')

    def testAuthHandlerWithBadToken(self):

        authorization_token = self.random_string(20)
        os.environ['authorizationToken'] = authorization_token
        resource = self.random_string(20)

        event = dict([
            ("authorizationToken", "not a valid token"),
            ("methodArn", resource)
        ])

        response = lambda_handler(event, None)

        statement = response['policyDocument']['Statement'][0]

        assert(statement['Resource'] == resource)
        assert(statement['Action'] == 'execute-api:Invoke')
        assert(statement['Effect'] == 'Deny')

    @staticmethod
    def random_string(length):
        return ''.join(random.choice(string.ascii_letters) for m in xrange(length))
