#! /usr/bin/python

import requests
import time
import ipaddress
from urllib.parse import urlparse
import colors


API_URL = "https://api.ssllabs.com/api/v3/analyze/"

analyze_payload = {

    'host': '',
    'startNew': 'on',
    'publish': 'off',
    'all': 'done',
    'ignoreMismatch': 'on'

}


def request_api(url, payload):
    resp = requests.get(url, params=payload, timeout=30)
    return resp.json()


def _format_errors(resp):
    errors = resp.get('errors') or []
    if errors:
        messages = [e.get('message', str(e)) for e in errors
                    if isinstance(e, dict)]
        return '; '.join(messages)
    return resp.get('statusMessage') or str(resp)


def analyze(url):
    global analyze_payload

    host = urlparse(url).hostname
    if not host:
        host = url

    # SSL Labs rejects IP addresses; fail fast with a clear message.
    try:
        ipaddress.ip_address(host)
        raise RuntimeError('SSL Labs cannot scan IP address "{}"; '
                           'provide a hostname.'.format(host))
    except ValueError:
        pass

    colors.success('Scanning')
    analyze_payload['host'] = host
    resp = request_api(API_URL, analyze_payload)
    analyze_payload.pop('startNew')

    if 'status' not in resp:
        raise RuntimeError('SSL Labs API error: ' + _format_errors(resp))

    while resp['status'] != 'READY' and resp['status'] != 'ERROR':
        time.sleep(30)
        resp = request_api(API_URL, analyze_payload)
        if 'status' not in resp:
            raise RuntimeError('SSL Labs API error: ' + _format_errors(resp))

    if resp['status'] == 'ERROR':
        raise RuntimeError('SSL Labs API error: ' + _format_errors(resp))

    return resp


def vulnerability_parser(data):

    endpoints = data.get('endpoints') or []
    if not endpoints:
        raise RuntimeError('SSL Labs returned no endpoints to analyze.')

    base_data = endpoints[0].get('details')
    if base_data is None:
        raise RuntimeError('SSL Labs returned no details for the endpoint.')

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

    return vuln_dict


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
    colors.success('Vulnerability Scan Result : ')
    for key, item in dict_value.items():
        if not isinstance(item, bool):
            new_item = get_value(key, item)
            print('[+] ', key, ' : ', new_item)
        else:
            print('[+] ', key, ' : ', item)
