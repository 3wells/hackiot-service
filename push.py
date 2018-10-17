import boto3
import json
import logging
import hmac
import hashlib
import os


def lambda_handler(event, context):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    secret_key = os.getenv('secret_key')
    signature = calc_hash(secret_key, int(event['headers']['X-UA-TIMESTAMP']), event['body'].encode('utf-8'))
    if signature != event['headers']['X-UA-SIGNATURE']:
        logger.error('Invalid signature detected.')
        return {
            "statusCode": 401
        }

    client = boto3.client('iot-data', region_name='us-west-2')

    body = json.loads(event['body'])
    push_list = body['values']

    for push in push_list:
        target = push['target']
        payload = push['payload']
        client.publish(topic='iot/{}'.format(target['address']), qos=1, payload=payload['alert'])

    return {
        "statusCode": 200,
    }


def calc_hash(secret_key, timestamp, body):
    message = bytes("{}:{}".format(timestamp, body)).encode('utf-8')
    return hmac.new(secret_key, message, digestmod=hashlib.sha256).hexdigest()
