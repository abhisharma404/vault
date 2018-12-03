#! /usr/bin/python

import requests
import json
import time


API_URL = "https://api.ssllabs.com/api/v3/analyze/"

analyze_payload = {

    'host': '',
    'startNew': 'on',
    'publish': 'off',
    'all': 'done',
    'ignoreMismatch': 'on'

}


def request_api(url, payload):
    resp = requests.get(url, params=payload)
    return resp.json()


def analyze(url):
    global analyze_payload

    print('[+] Scanning...')
    analyze_payload['host'] = url
    resp = request_api(API_URL, analyze_payload)
    analyze_payload.pop('startNew')

    while resp['status'] != 'READY' and resp['status'] != 'ERROR':
        time.sleep(30)
        resp = request_api(API_URL, analyze_payload)

    return resp


def vulnerability_parser(data):

    base_data = data['endpoints'][0]['details']

    vuln_dict = {

        'beastAttack': base_data['vulnBeast'],
        'poodle': base_data['poodle'],
        'poodleTls': base_data['poodleTls'],
        'rc4': base_data['rc4Only'],
        'heartbeat': base_data['heartbeat'],
        'heartbleed': base_data['heartbleed'],
        'ticketbleed': base_data['ticketbleed'],
        'openSSL_CCS': base_data['openSslCcs'],
        'openSSL_padding': base_data['openSSLLuckyMinus20'],
        'robot': base_data['bleichenbacher'],
        'freak': base_data['freak'],
        'logjam': base_data['logjam'],
        'drown_attack': base_data['drownVulnerable'],

    }
    print_data(vuln_dict)


def get_value(key, value):

    main_dict = {
        'poodleTls': {

            '-3': 'timeout',
            '-2': 'TLS not supported',
            '-1': 'test failed',
            '0': 'unknown',
            '1': 'not vulnerable',
            '2': 'vulnerable'

        },
        'ticketbleed': {

            '-1': 'test failed',
            '0':  'unknown',
            '1': 'not vulnerable',
            '2': 'vulnerable and insecure'

        },
        'openSSL_CCS': {

            '-1': 'test failed',
            '0': 'unknown',
            '1': 'not vulnerable',
            '2': 'possibly vulnerable, but not exploitable',
            '3': 'vulnerable and exploitable'

        },
        'openSSL_padding': {

            '-1': 'test failed',
            '0': 'unknown',
            '1': 'not vulnerable',
            '2': 'vulnerable and insecure'

        },
        'robot': {

            '-1': 'test failed',
            '0': 'unknown',
            '1': 'not vulnerable',
            '2': 'vulnerable (weak oracle)',
            '3': 'vulnerable (strong oracle)',
            '4': 'inconsistent results'

        }
    }

    value = str(value)
    return main_dict[key][value]


def print_data(dict_value):
    print('[+] Vulnerability Scan Result : \n')
    for key, item in dict_value.items():
        if not isinstance(item, bool):
            new_item = get_value(key, item)
            print('[+] ', key, ' : ', new_item)
        else:
            print('[+] ', key, ' : ', item)
