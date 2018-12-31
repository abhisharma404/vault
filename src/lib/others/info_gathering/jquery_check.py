#! /usr/bin/python

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import *
import sys
import colors


class JqueryCheck(object):

    def __init__(self, url):
        self.url = url

    def get_jquery_version(self):
        response = requests.get(self.url)
        soup_obj = BeautifulSoup(response.text, "html.parser")
        scripts = []

        for line in soup_obj.find_all('script'):
            if "jquery" in str(line.get('src')).lower():
                response = requests.get(urljoin(self.url, line.get('src')))
                versions = re.findall(r'(?<=\s)v[0-9]+(?:\.[0-9]+)*'
                                      '(?:[a-z](?:\d)?)?(?:-alpha\d)?'
                                      '(?:-beta\d)?(?:-rc\d)?(?:-rc.\d)?',
                                      response.text)
                scripts.append((urljoin(self.url, line.get('src'))
                               .rsplit('/', 1)[-1], versions))

        if scripts != []:
            colors.success("Found Jquery version")
            for i in scripts:
                print("{}, {}".format(i[0], i[1]))

    @staticmethod
    def search_vulnerabilities():
        response = requests.get("https://www.cvedetails.com/json-feed.php"
                                "?vendor_id=6538&orderby=3")
        response = response.json()

        colors.success("Possible vulnerabilities:")
        for i in response:
            print(i["summary"], end="\n\n")

    def start_engine(self):
        colors.info("Starting Jquery Version Checker...")
        self.get_jquery_version()
        self.search_vulnerabilities()
