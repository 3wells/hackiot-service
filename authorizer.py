import logging
import os


def lambda_handler(event, context):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if event['authorizationToken'] == os.getenv('authorizationToken'):
        return generate_policy('iot', 'Allow', event['methodArn'])
    else:
        return generate_policy(None, 'Deny', event['methodArn'])


def generate_policy(principal_id, effect, method_arn):

    auth_response = {'principalId': principal_id}

    if effect and method_arn:
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'FirstStatement',
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': method_arn
                }
            ]
        }

        auth_response['policyDocument'] = policy_document

    return auth_response
