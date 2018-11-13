import requests
import re
from bs4 import BeautifulSoup
import sys

def get_soure_code(url):
    resp_text = requests.get(url).text
    return resp_text

def find_comment(source_code):
    comments = re.findall('<!--(.*)-->', source_code)
    return comments

URL = 'http://10.0.2.6/mutillidae'

source_code = get_soure_code(URL)
comment = find_comment(source_code)

if len(comment) > 0:
    print('[+] Found', comment)
