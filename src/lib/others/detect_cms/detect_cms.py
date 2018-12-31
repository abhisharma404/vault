#! /usr/bin/python

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import *
from collections import defaultdict
import sys
import colors
import operator


class DetectCMS(object):

    def __init__(self, url):
        self.url = url
        self.scores = defaultdict(int)
        self.success_codes = [200, 201, 202, 203, 204, 205, 206]
        self.redirection_codes = [300, 301, 302, 303, 304, 305, 306, 307]

    def extract_headers(self):
        for header in self.response.headers:
            if "/wp-json/" in header.lower():
                self.scores["Wordpress"] += 1
            if "expires: wed, 17 aug 2005 00:00:00 gmt" in header.lower():
                self.scores["Joomla"] += 1

    def extract_code(self):
        soup_obj = BeautifulSoup(self.response.text, "html.parser")
        # Extract meta generator tag
        for line in soup_obj.find_all('meta'):
            if str(line.get("name")).lower() == "generator":
                if "wordpress" in str(line.get("content")).lower():
                    self.scores["Wordpress"] += 1
                if "joomla" in str(line.get("content")).lower():
                    self.scores["Joomla"] += 1
                if "drupal" in str(line.get("content")).lower():
                    self.scores["Drupal"] += 1

        if re.search("\/wp-content\/", self.response.text):
            self.scores["Wordpress"] += 1
        if re.search("\/wp-includes\/", self.response.text):
            self.scores["Wordpress"] += 1
        if re.search("\/\/(?:api|s).w.org", self.response.text):
            self.scores["Wordpress"] += 1
        if re.search("\/\/(?:pixel|s0-s9|stats).wp.com", self.response.text):
            self.scores["Wordpress"] += 1
        if re.search("\/\/wp.me\/", self.response.text):
            self.scores["Wordpress"] += 1

        if re.search("\/media\/jui\/(?:css|js)\/", self.response.text):
            self.scores["Joomla"] += 1
        if re.search("\/media\/media\/(?:css|images|js)\/",
           self.response.text):
            self.scores["Joomla"] += 1
        if re.search("\/media\/system\/(?:css|images|js)\/",
           self.response.text):
            self.scores["Joomla"] += 1
        if re.search("\/templates\/*(?:(?:[a-zA-Z]+).+)\/(?:css|images|js)",
           self.response.text):
            self.scores["Joomla"] += 1

    def extract_files(self):
        response = requests.get(urljoin(self.url, "wp-admin"))
        if response.status_code in self.success_codes or\
           response.status_code in self.redirection_codes or\
           response.status_code == 403:
            self.scores["Wordpress"] += 1

        response = requests.get(urljoin(self.url, "wp-json"))
        if response.status_code in self.success_codes or\
           response.status_code in self.redirection_codes or\
           response.status_code == 403:
            self.scores["Wordpress"] += 1

        response = requests.get(urljoin(self.url, "administrator"))
        if response.status_code in self.success_codes or\
           response.status_code in self.redirection_codes or\
           response.status_code == 403:
            self.scores["Joomla"] += 1

        response = requests.get(urljoin(self.url, "user"))
        if response.status_code in self.success_codes or\
           response.status_code in self.redirection_codes or\
           response.status_code == 403:
            self.scores["Drupal"] += 1

    def start_engine(self):
        self.response = requests.get(self.url)
        colors.info("Starting CMS Detect engine...")
        colors.info("Extracting headers...")
        self.extract_headers()
        colors.info("Extracting code...")
        self.extract_code()
        colors.info("Extracting files...")
        self.extract_files()

        colors.success("Detected framework: {}"
                       .format(max(self.scores.items(),
                                   key=operator.itemgetter(1))[0]))
