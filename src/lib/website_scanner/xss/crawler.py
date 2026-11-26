#! /usr/bin/python

import re
from urllib.parse import *
import requests
import colors
from vault_cli import errors

# Recursion guards: stop crawling once the tree is too deep or the link set
# is large enough, so pathological sites cannot trigger a RecursionError.
MAX_DEPTH = 20
MAX_LINKS = 500


class Crawl(object):

    def __init__(self, url):
        self.url = url
        self.target_links = []
        self.session = requests.Session()

    def extract_links_from(self, url):
        try:
            response = self.session.get(url, timeout=15)
            return re.findall('(?:href=")(.*?)"', response.text)
        except requests.exceptions.Timeout as e:
            errors.report_error('Request timed out while crawling: ' + url,
                                exc=e, code='E2002')
            return []
        except requests.exceptions.RequestException as e:
            errors.report_error('Request failed while crawling: ' + url,
                                exc=e, code='E2001')
            return []

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.url

        if depth > MAX_DEPTH or len(self.target_links) >= MAX_LINKS:
            return

        href_links = self.extract_links_from(url)

        if url not in self.target_links:
            self.target_links.append(url)

        for link in href_links:
            link = urljoin(url, link)

            if '#' in link:
                link = link.split('#')[0]

            if self.url in link and link not in self.target_links:
                if '.css' not in link and '.ico' not in link:
                    self.target_links.append(link)
                    self.crawl(link, depth + 1)

    def getList(self):
        colors.success('Crawling, collecting links...')
        self.crawl()
        return self.target_links
