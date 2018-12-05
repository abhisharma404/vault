#! /usr/bin/python

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import *

class HeaderVuln(object):

    def __init__(self, url):
        self.url = url

    def get_response(self):
        try:
            resp = requests.get(self.url)
            return resp
        except:
            print(Fore.RED+'[-] Error in network connection!'+Fore.RESET)

    def gather_header(self):
        try:
            r = self.get_response()
            headers_dict = r.headers
            print(Fore.GREEN+'---[!] Header Details---\n'+Fore.RESET)
            for key, value in headers_dict.items():
                print('[+] {} : {}'.format(key, value))
            return headers_dict
        except Exception as e:
            print(e)

    def find_insecure_headers(self):
        headers_dict = self.gather_header()

        if headers_dict:
            print(Fore.GREEN+'\n---[!] Finding vulnerabilities---\n'+Fore.RESET)

            try:
                xssprotect = headers_dict['X-XSS-Protection']
                if xssprotect != '1; mode=block':
                    print(Fore.BLUE+'[-] X-XSS-Protection not set properly.'+Fore.RESET)
                else: 
                    print(Fore.BLUE+'[+] X-XSS-Protection set propely.'+Fore.RESET)
            except:
                print(Fore.GREEN+'[!] Escaping!...'+Fore.RESET)

            try:
                contenttype = headers_dict['X-Content-Type-Options']
                if contenttype != 'nosniff':
                    print(Fore.RED+'[-] X-Content-Type-Options not set properly.'+Fore.RESET)
            except:
                print(Fore.BLUE+'[!] Escaping'+Fore.RESET)

            try:
                hsts = headers_dict['Strict-Transport-Security']
            except:
                print(Fore.BLUE+'[-] HSTS not set properly.'+Fore.RESET)

            try:
                csp = headers_dict['Content-Security-Policy']
                print(Fore.GREEN+'[+] CSP set properly.'+Fore.RESET)
            except:
                print(Fore.RED+'[-] CSP mising'+Fore.RESET)

            try:
                xframe = headers_dict['x-frame-options']
                print(Fore.GREEN+'[+] Likely to be safe from X-Frame.'+Fore.RESET)
            except:
                print(Fore.RED+'[-] X-Frame Missing.'+Fore.RESET)

    def insecure_cookies(self):
        response = self.get_response()
        cookies = response.cookies

        print(Fore.GREEN +'\n---[!] Testing Insecure Cookies---\n'+ Fore.RESET)

        for cookie in cookies:
            print(Fore.BLUE+'[+] Name : '+Fore.RESET, cookie.name )
            print(Fore.BLUE+'[+] Value : '+Fore.RESET, cookie.value)

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

            print(Fore.BLUE+'[+] Cookie Secure :'+Fore.RESET, cookie.secure)
            print(Fore.BLUE+'[+] Cookie httponly :'+Fore.RESET, cookie.httponly)
            print(Fore.BLUE+'[+] Cookies domain iniitial dot'+Fore.RESET, cookie.domain_initial_dot)
            print('\n')

    def test_http_methods(self):
        modes_list = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']

        print(Fore.GREEN+'\n---[!] Testing HTTP methods---\n'+Fore.RESET)

        for mode in modes_list:
            r = requests.request(mode, self.url)
            print('[+]', mode, r.status_code, r.reason)
            if mode == 'TRACE' and 'TRACE / HTTP/1.1' in r.text:
                print(Fore.BLUE+'[!] Possible Cross Site Tracing vulnerability found'+Fore.RESET)
