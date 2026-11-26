#! /usr/bin/python

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import *
import sys
import colors
from vault_cli import errors


class JqueryCheck(object):

    def __init__(self, url):
        self.url = url

    def get_jquery_version(self):
        try:
            response = requests.get(self.url)
        except requests.exceptions.RequestException as e:
            errors.report_error('Failed to fetch page for jQuery version '
                                'check', exc=e, code='E2001')
            return
        soup_obj = BeautifulSoup(response.text, "html.parser")
        scripts = []

        for line in soup_obj.find_all('script'):
            if "jquery" in str(line.get('src')).lower():
                try:
                    response = requests.get(urljoin(self.url, line.get('src')))
                except requests.exceptions.RequestException as e:
                    errors.report_error('Failed to fetch jQuery script',
                                        exc=e, code='E2001')
                    continue
                versions = re.findall(r'(?<=\s)v[0-9]+(?:\.[0-9]+)*'
                                      r'(?:[a-z](?:\d)?)?(?:-alpha\d)?'
                                      r'(?:-beta\d)?(?:-rc\d)?(?:-rc.\d)?',
                                      response.text)
                scripts.append((urljoin(self.url, line.get('src'))
                               .rsplit('/', 1)[-1], versions))

        if scripts != []:
            colors.success("Found Jquery version")
            for i in scripts:
                print("{}, {}".format(i[0], i[1]))

    @staticmethod
    def search_vulnerabilities():
        try:
            response = requests.get("https://www.cvedetails.com/json-feed.php"
                                    "?vendor_id=6538&orderby=3", timeout=10)
            response = response.json()
        except (requests.exceptions.RequestException, ValueError):
            # Benign: the version check already succeeded; only the optional
            # CVE lookup failed, so warn on the console without logging.
            colors.warning('Could not fetch the jQuery vulnerability feed; '
                           'CVE details are unavailable.')
            return

        colors.success("Possible vulnerabilities:")
        for i in response:
            print(i["summary"], end="\n\n")

    def start_engine(self):
        colors.info("Starting Jquery Version Checker...")
        self.get_jquery_version()
        self.search_vulnerabilities()
