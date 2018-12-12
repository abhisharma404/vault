#! /usr/bin/python

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class HeaderVuln(object):

    def __init__(self, url):
        self.url = url

    def get_response(self):
        try:
            resp = requests.get(self.url)
            return resp
        except:
            print('[-] Error in network connection!')

    def gather_header(self):
        try:
            r = self.get_response()
            headers_dict = r.headers
            print('---[!] Header Details---\n')
            for key, value in headers_dict.items():
                print('[+] {} : {}'.format(key, value))
            return headers_dict
        except Exception as e:
            print(e)

    def find_insecure_headers(self):
        headers_dict = self.gather_header()

        if headers_dict:
            print('\n---[!] Finding vulnerabilities---\n')

            try:
                xssprotect = headers_dict['X-XSS-Protection']
                if xssprotect != '1; mode=block':
                    print('[-] X-XSS-Protection not set properly.')
                else:
                    print('[+] X-XSS-Protection set propely.')
            except:
                print('[!] Escaping!...')

            try:
                contenttype = headers_dict['X-Content-Type-Options']
                if contenttype != 'nosniff':
                    print('[-] X-Content-Type-Options not set properly.')
            except:
                print('[!] Escaping')

            try:
                hsts = headers_dict['Strict-Transport-Security']
            except:
                print('[-] HSTS not set properly.')

            try:
                csp = headers_dict['Content-Security-Policy']
                print('[+] CSP set properly.')
            except:
                print('[-] CSP mising')

            try:
                xframe = headers_dict['x-frame-options']
                print('[+] Likely to be safe from X-Frame.')
            except:
                print('[-] X-Frame Missing.')

    def insecure_cookies(self):
        response = self.get_response()
        cookies = response.cookies

        print('\n---[!] Testing Insecure Cookies---\n')

        for cookie in cookies:
            print('[+] Name : ', cookie.name)
            print('[+] Value : ', cookie.value)

            if not cookie.secure:
                cookie.secure = 'True'
            else:
                cookie.secure = 'False'

            if 'httponly' in cookie._rest.keys():
                cookie.httponly = 'True'
            else:
                cookie.httponly = 'False'

            if cookie.domain_initial_dot:
                cookie.domain_initial_dot = 'True'
            else:
                cookie.domain_initial_dot = 'False'

            print('[+] Cookie Secure :', cookie.secure)
            print('[+] Cookie httponly :', cookie.httponly)
            print('[+] Cookies domain initial dot', cookie.domain_initial_dot)
            print('\n')

    def test_http_methods(self):
        modes_list = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']

        print('\n---[!] Testing HTTP methods---\n')

        for mode in modes_list:
            r = requests.request(mode, self.url)
            print('[+]', mode, r.status_code, r.reason)
            if mode == 'TRACE' and 'TRACE / HTTP/1.1' in r.text:
                print('[!] Possible Cross Site Tracing vulnerability found')
