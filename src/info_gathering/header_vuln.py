#Various types of information gathering
import requests
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

url = 'http://10.0.2.6/mutillidae/index.php'

def gather_header():
    try:
        r = requests.get(url)
        headers_dict = r.headers
        for key, value in headers_dict.items():
            print('[+] {} : {}'.format(key, value))
        return r
    except:
        print('[-] Error in network connection.')

def find_insecure_headers():
    headers_dict = gather_header()

    if headers_dict:
        headers_dict = headers_dict.headers
    else:
        return

    print('\n[!] Finding vulnerablilties\n')

    try:
        xssprotect = headers_dict['X-XSS-Protection']
        if xssprotect != '1; mode=block':
            print('[-] X-XSS-Protection not set properly.')
        else:
            print('[+] X-XSS-Protection set propely.')
    except:
        print('[+] Escaping')

    try:
        contenttype = headers_dict['X-Content-Type-Options']
        if contenttype != 'nosniff':
            print('[+] X-Content-Type-Options not set properly.')
    except:
        print('[+] Escaping')

    try:
        hsts = headers_dict['Strict-Transport-Security']
    except:
        print('[+] HSTS not set properly.')

    try:
        csp = headers_dict['Content-Security-Policy']
        print('[+] great with csp')
    except:
        print('[-] csp mising')

    try:
        xframe = headers_dict['x-frame-options']
        print('[+] Likely to be safe from xframe')
    except:
        print('[-] xframe Missing.')

def insecure_cookies():
    response = gather_header()
    cookies =  response.cookies

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
        print('[+] Cookies domain iniitial dot', cookie.domain_initial_dot)

def test_http_methods():
    modes_list = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']

    for mode in modes_list:
        r = requests.request(mode, url)
        print('[+]', mode, r.status_code, r.reason)
        if mode == 'TRACE' and 'TRACE / HTTP/1.1' in r.text:
            print('[+] Possible cross site tracing vulnerability found.')

def jquery_check():
    #to find jquery:"1.3.2"
    resp = requests.get(url)
    script_tags = []

    soup_obj = BeautifulSoup(resp.text, 'lxml')
    for line in soup_obj.find_all('script'):
        script_tag = line.get('src')
        script_tags.append(script_tag)

    for script in script_tags:
        if 'jquery.min' in str(script).lower():
            js_url = urljoin(url, script)
            resp = requests.get(js_url)
            #print(resp.text)

jquery_check()
