#! /usr/bin/python

import re
from urllib.parse import *
import requests
import colors


class Crawl(object):

    def __init__(self, url):
        self.url = url
        self.target_links = []
        self.session = requests.Session()

    def extract_links_from(self):
        response = self.session.get(self.url)
        return re.findall('(?:href=")(.*?)"', response.text)

    def crawl(self, url=None):
        if url is None:
            url = self.url

        href_links = self.extract_links_from()
        self.target_links.append(url)

        for link in href_links:
            link = urljoin(url, link)

            if '#' in link:
                link = link.split('#')[0]

            if self.url in link and link not in self.target_links:
                if '.css' not in link and '.ico' not in link:
                    self.target_links.append(link)
                    self.crawl(link)

    def getList(self):
        colors.success('Crawling, collecting links...')
        self.extract_links_from()
        self.crawl()
        return self.target_links
